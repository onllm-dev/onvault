/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * encrypt.c — Per-file encryption/decryption with key derivation
 */

#include "encrypt.h"
#include "../common/crypto.h"
#include "../common/memwipe.h"

#include <stdio.h>
#include <string.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <errno.h>

#define XATTR_NAME "com.onvault.nonce"

int onvault_file_nonce_generate(onvault_nonce_t *nonce)
{
    if (!nonce)
        return ONVAULT_ERR_INVALID;
    return onvault_random_bytes(nonce->data, ONVAULT_NONCE_SIZE);
}

int onvault_file_nonce_store(const char *ciphertext_path,
                              const onvault_nonce_t *nonce)
{
    if (!ciphertext_path || !nonce)
        return ONVAULT_ERR_INVALID;

    int rc = setxattr(ciphertext_path, XATTR_NAME,
                      nonce->data, ONVAULT_NONCE_SIZE,
                      0, 0);
    return (rc == 0) ? ONVAULT_OK : ONVAULT_ERR_IO;
}

int onvault_file_nonce_load(const char *ciphertext_path,
                             onvault_nonce_t *nonce)
{
    if (!ciphertext_path || !nonce)
        return ONVAULT_ERR_INVALID;

    ssize_t len = getxattr(ciphertext_path, XATTR_NAME,
                           nonce->data, ONVAULT_NONCE_SIZE,
                           0, 0);
    if (len != ONVAULT_NONCE_SIZE)
        return ONVAULT_ERR_NOT_FOUND;

    return ONVAULT_OK;
}

int onvault_file_encrypt_block(const onvault_key_t *vault_key,
                                const onvault_nonce_t *nonce,
                                const uint8_t *plaintext, size_t plaintext_len,
                                uint8_t *ciphertext,
                                uint64_t block_offset)
{
    if (!vault_key || !nonce || !plaintext || !ciphertext)
        return ONVAULT_ERR_INVALID;

    /* Derive per-file XTS key from vault key + nonce */
    onvault_xts_key_t file_key;
    onvault_mlock(&file_key, sizeof(file_key));

    int rc = onvault_derive_file_key(vault_key, nonce, &file_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&file_key, sizeof(file_key));
        return rc;
    }

    /* Use block offset as XTS tweak (little-endian 16 bytes) */
    uint8_t tweak[16] = {0};
    memcpy(tweak, &block_offset, sizeof(block_offset));

    rc = onvault_aes_xts_encrypt(&file_key, tweak,
                                  plaintext, ciphertext, plaintext_len);

    onvault_key_wipe(&file_key, sizeof(file_key));
    return rc;
}

int onvault_file_decrypt_block(const onvault_key_t *vault_key,
                                const onvault_nonce_t *nonce,
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                uint8_t *plaintext,
                                uint64_t block_offset)
{
    if (!vault_key || !nonce || !ciphertext || !plaintext)
        return ONVAULT_ERR_INVALID;

    onvault_xts_key_t file_key;
    onvault_mlock(&file_key, sizeof(file_key));

    int rc = onvault_derive_file_key(vault_key, nonce, &file_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&file_key, sizeof(file_key));
        return rc;
    }

    uint8_t tweak[16] = {0};
    memcpy(tweak, &block_offset, sizeof(block_offset));

    rc = onvault_aes_xts_decrypt(&file_key, tweak,
                                  ciphertext, plaintext, ciphertext_len);

    onvault_key_wipe(&file_key, sizeof(file_key));
    return rc;
}

int onvault_file_encrypt(const onvault_key_t *vault_key,
                          const char *plaintext_path,
                          const char *ciphertext_path)
{
    if (!vault_key || !plaintext_path || !ciphertext_path)
        return ONVAULT_ERR_INVALID;

    FILE *fin = fopen(plaintext_path, "rb");
    if (!fin)
        return ONVAULT_ERR_IO;

    FILE *fout = fopen(ciphertext_path, "wb");
    if (!fout) {
        fclose(fin);
        return ONVAULT_ERR_IO;
    }

    /* Generate and store nonce */
    onvault_nonce_t nonce;
    if (onvault_file_nonce_generate(&nonce) != ONVAULT_OK) {
        fclose(fin);
        fclose(fout);
        return ONVAULT_ERR_CRYPTO;
    }

    /* Derive per-file key once for the whole file */
    onvault_xts_key_t file_key;
    onvault_mlock(&file_key, sizeof(file_key));
    int rc = onvault_derive_file_key(vault_key, &nonce, &file_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&file_key, sizeof(file_key));
        fclose(fin);
        fclose(fout);
        return rc;
    }

    /* Get file size for handling the last block */
    struct stat st;
    if (fstat(fileno(fin), &st) != 0) {
        onvault_key_wipe(&file_key, sizeof(file_key));
        fclose(fin);
        fclose(fout);
        return ONVAULT_ERR_IO;
    }

    /* Write file size as first 8 bytes (needed for decryption of partial last block) */
    uint64_t file_size = (uint64_t)st.st_size;
    fwrite(&file_size, sizeof(file_size), 1, fout);

    uint8_t plainbuf[ONVAULT_BLOCK_SIZE];
    uint8_t cipherbuf[ONVAULT_BLOCK_SIZE];
    uint64_t block_num = 0;
    size_t nread;

    while ((nread = fread(plainbuf, 1, ONVAULT_BLOCK_SIZE, fin)) > 0) {
        /* XTS requires minimum 16 bytes. Pad last block if needed. */
        size_t encrypt_len = nread;
        if (encrypt_len < 16) {
            memset(plainbuf + nread, 0, 16 - nread);
            encrypt_len = 16;
        }

        uint8_t tweak[16] = {0};
        memcpy(tweak, &block_num, sizeof(block_num));

        rc = onvault_aes_xts_encrypt(&file_key, tweak,
                                      plainbuf, cipherbuf, encrypt_len);
        if (rc != ONVAULT_OK)
            break;

        if (fwrite(cipherbuf, 1, encrypt_len, fout) != encrypt_len) {
            rc = ONVAULT_ERR_IO;
            break;
        }

        block_num++;
    }

    onvault_key_wipe(&file_key, sizeof(file_key));
    onvault_memzero(plainbuf, sizeof(plainbuf));
    fclose(fin);
    fclose(fout);

    if (rc != ONVAULT_OK)
        return rc;

    /* Store nonce in xattr after file is written */
    rc = onvault_file_nonce_store(ciphertext_path, &nonce);
    onvault_memzero(&nonce, sizeof(nonce));

    /* Preserve original file permissions */
    chmod(ciphertext_path, st.st_mode & 0777);

    return rc;
}

int onvault_file_decrypt(const onvault_key_t *vault_key,
                          const char *ciphertext_path,
                          const char *plaintext_path)
{
    if (!vault_key || !ciphertext_path || !plaintext_path)
        return ONVAULT_ERR_INVALID;

    /* Load nonce from xattr */
    onvault_nonce_t nonce;
    if (onvault_file_nonce_load(ciphertext_path, &nonce) != ONVAULT_OK)
        return ONVAULT_ERR_NOT_FOUND;

    FILE *fin = fopen(ciphertext_path, "rb");
    if (!fin)
        return ONVAULT_ERR_IO;

    FILE *fout = fopen(plaintext_path, "wb");
    if (!fout) {
        fclose(fin);
        return ONVAULT_ERR_IO;
    }

    /* Derive per-file key */
    onvault_xts_key_t file_key;
    onvault_mlock(&file_key, sizeof(file_key));
    int rc = onvault_derive_file_key(vault_key, &nonce, &file_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&file_key, sizeof(file_key));
        fclose(fin);
        fclose(fout);
        return rc;
    }

    /* Read original file size */
    uint64_t file_size;
    if (fread(&file_size, sizeof(file_size), 1, fin) != 1) {
        onvault_key_wipe(&file_key, sizeof(file_key));
        fclose(fin);
        fclose(fout);
        return ONVAULT_ERR_IO;
    }

    uint8_t cipherbuf[ONVAULT_BLOCK_SIZE];
    uint8_t plainbuf[ONVAULT_BLOCK_SIZE];
    uint64_t block_num = 0;
    uint64_t written = 0;
    size_t nread;

    while ((nread = fread(cipherbuf, 1, ONVAULT_BLOCK_SIZE, fin)) > 0) {
        if (nread < 16) {
            /* Shouldn't happen for properly encrypted files */
            rc = ONVAULT_ERR_CRYPTO;
            break;
        }

        uint8_t tweak[16] = {0};
        memcpy(tweak, &block_num, sizeof(block_num));

        rc = onvault_aes_xts_decrypt(&file_key, tweak,
                                      cipherbuf, plainbuf, nread);
        if (rc != ONVAULT_OK)
            break;

        /* Write only up to original file size (handle padding) */
        size_t to_write = nread;
        if (written + to_write > file_size)
            to_write = (size_t)(file_size - written);

        if (fwrite(plainbuf, 1, to_write, fout) != to_write) {
            rc = ONVAULT_ERR_IO;
            break;
        }

        written += to_write;
        block_num++;
    }

    onvault_key_wipe(&file_key, sizeof(file_key));
    onvault_memzero(plainbuf, sizeof(plainbuf));
    onvault_memzero(&nonce, sizeof(nonce));
    fclose(fin);
    fclose(fout);

    return rc;
}

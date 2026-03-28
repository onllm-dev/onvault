/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * crypto.c — Cryptographic operations (OpenSSL wrappers)
 */

#include "crypto.h"
#include "memwipe.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

int onvault_crypto_init(void)
{
    /* OpenSSL 3.x auto-initializes, but ensure error strings are loaded */
    return 0;
}

int onvault_random_bytes(uint8_t *buf, size_t len)
{
    if (RAND_bytes(buf, (int)len) != 1)
        return ONVAULT_ERR_CRYPTO;
    return ONVAULT_OK;
}

/* --- AES-256-XTS --- */

int onvault_aes_xts_encrypt(const onvault_xts_key_t *key,
                            const uint8_t tweak[16],
                            const uint8_t *in, uint8_t *out, size_t len)
{
    if (!key || !tweak || !in || !out || len < 16)
        return ONVAULT_ERR_INVALID;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return ONVAULT_ERR_CRYPTO;

    int ret = ONVAULT_ERR_CRYPTO;
    int outl = 0, final_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key->data, tweak) != 1)
        goto cleanup;

    if (EVP_EncryptUpdate(ctx, out, &outl, in, (int)len) != 1)
        goto cleanup;

    if (EVP_EncryptFinal_ex(ctx, out + outl, &final_len) != 1)
        goto cleanup;

    ret = ONVAULT_OK;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int onvault_aes_xts_decrypt(const onvault_xts_key_t *key,
                            const uint8_t tweak[16],
                            const uint8_t *in, uint8_t *out, size_t len)
{
    if (!key || !tweak || !in || !out || len < 16)
        return ONVAULT_ERR_INVALID;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return ONVAULT_ERR_CRYPTO;

    int ret = ONVAULT_ERR_CRYPTO;
    int outl = 0, final_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key->data, tweak) != 1)
        goto cleanup;

    if (EVP_DecryptUpdate(ctx, out, &outl, in, (int)len) != 1)
        goto cleanup;

    if (EVP_DecryptFinal_ex(ctx, out + outl, &final_len) != 1)
        goto cleanup;

    ret = ONVAULT_OK;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* --- AES-256-GCM --- */

int onvault_aes_gcm_encrypt(const onvault_key_t *key,
                            const uint8_t *iv,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *in, size_t in_len,
                            uint8_t *out,
                            uint8_t tag[ONVAULT_GCM_TAG_SIZE],
                            uint8_t iv_out[ONVAULT_GCM_IV_SIZE])
{
    if (!key || !in || !out || !tag || !iv_out)
        return ONVAULT_ERR_INVALID;

    /* Generate random IV if not provided */
    uint8_t iv_buf[ONVAULT_GCM_IV_SIZE];
    if (iv) {
        memcpy(iv_buf, iv, ONVAULT_GCM_IV_SIZE);
    } else {
        if (onvault_random_bytes(iv_buf, ONVAULT_GCM_IV_SIZE) != ONVAULT_OK)
            return ONVAULT_ERR_CRYPTO;
    }
    memcpy(iv_out, iv_buf, ONVAULT_GCM_IV_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return ONVAULT_ERR_CRYPTO;

    int ret = ONVAULT_ERR_CRYPTO;
    int outl = 0, final_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ONVAULT_GCM_IV_SIZE, NULL) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key->data, iv_buf) != 1)
        goto cleanup;

    /* AAD */
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1)
            goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, out, &outl, in, (int)in_len) != 1)
        goto cleanup;

    if (EVP_EncryptFinal_ex(ctx, out + outl, &final_len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ONVAULT_GCM_TAG_SIZE, tag) != 1)
        goto cleanup;

    ret = ONVAULT_OK;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int onvault_aes_gcm_decrypt(const onvault_key_t *key,
                            const uint8_t iv[ONVAULT_GCM_IV_SIZE],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *in, size_t in_len,
                            uint8_t *out,
                            const uint8_t tag[ONVAULT_GCM_TAG_SIZE])
{
    if (!key || !iv || !in || !out || !tag)
        return ONVAULT_ERR_INVALID;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return ONVAULT_ERR_CRYPTO;

    int ret = ONVAULT_ERR_CRYPTO;
    int outl = 0, final_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ONVAULT_GCM_IV_SIZE, NULL) != 1)
        goto cleanup;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key->data, iv) != 1)
        goto cleanup;

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1)
            goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, out, &outl, in, (int)in_len) != 1)
        goto cleanup;

    /* Set expected tag before final */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ONVAULT_GCM_TAG_SIZE,
                            (void *)tag) != 1)
        goto cleanup;

    /* Final verifies the tag */
    if (EVP_DecryptFinal_ex(ctx, out + outl, &final_len) != 1)
        goto cleanup;  /* Auth tag mismatch → failure */

    ret = ONVAULT_OK;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* --- HKDF-SHA512 --- */

int onvault_hkdf(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len)
{
    if (!ikm || !okm || okm_len == 0)
        return ONVAULT_ERR_INVALID;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx)
        return ONVAULT_ERR_CRYPTO;

    int ret = ONVAULT_ERR_CRYPTO;

    if (EVP_PKEY_derive_init(ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha512()) <= 0)
        goto cleanup;

    if (salt && salt_len > 0) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) <= 0)
            goto cleanup;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikm_len) <= 0)
        goto cleanup;

    if (info && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) <= 0)
            goto cleanup;
    }

    size_t outlen = okm_len;
    if (EVP_PKEY_derive(ctx, okm, &outlen) <= 0)
        goto cleanup;

    ret = ONVAULT_OK;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* --- Key derivation helpers --- */

int onvault_derive_vault_key(const onvault_key_t *master_key,
                             const char *vault_id,
                             onvault_key_t *vault_key)
{
    if (!master_key || !vault_id || !vault_key)
        return ONVAULT_ERR_INVALID;

    /* info = "onvault\0vault\0" + vault_id */
    char info[256];
    size_t info_len = (size_t)snprintf(info, sizeof(info),
                                        "onvault%cvault%c%s",
                                        '\0', '\0', vault_id);
    /* snprintf stops at first \0, so build manually */
    memcpy(info, "onvault\0vault\0", 14);
    size_t id_len = strlen(vault_id);
    memcpy(info + 14, vault_id, id_len);
    info_len = 14 + id_len;

    return onvault_hkdf(NULL, 0,
                        master_key->data, ONVAULT_KEY_SIZE,
                        (const uint8_t *)info, info_len,
                        vault_key->data, ONVAULT_KEY_SIZE);
}

int onvault_derive_file_key(const onvault_key_t *vault_key,
                            const onvault_nonce_t *nonce,
                            onvault_xts_key_t *file_key)
{
    if (!vault_key || !nonce || !file_key)
        return ONVAULT_ERR_INVALID;

    /* info = "onvault\0file\0" + nonce */
    uint8_t info[13 + ONVAULT_NONCE_SIZE];
    memcpy(info, "onvault\0file\0", 13);
    memcpy(info + 13, nonce->data, ONVAULT_NONCE_SIZE);

    return onvault_hkdf(NULL, 0,
                        vault_key->data, ONVAULT_KEY_SIZE,
                        info, sizeof(info),
                        file_key->data, ONVAULT_XTS_KEY_SIZE);
}

int onvault_derive_config_key(const onvault_key_t *master_key,
                              onvault_key_t *config_key)
{
    if (!master_key || !config_key)
        return ONVAULT_ERR_INVALID;

    const char *info = "onvault\0config\0";
    size_t info_len = 15; /* includes the \0 bytes */

    return onvault_hkdf(NULL, 0,
                        master_key->data, ONVAULT_KEY_SIZE,
                        (const uint8_t *)info, info_len,
                        config_key->data, ONVAULT_KEY_SIZE);
}

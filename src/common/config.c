/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * config.c — Encrypted configuration read/write
 */

#include "config.h"
#include "crypto.h"
#include "memwipe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int onvault_config_write(const char *path,
                          const onvault_key_t *config_key,
                          const uint8_t *data, size_t data_len)
{
    if (!path || !config_key || !data)
        return ONVAULT_ERR_INVALID;

    uint8_t *ciphertext = malloc(data_len);
    if (!ciphertext)
        return ONVAULT_ERR_MEMORY;

    uint8_t iv[ONVAULT_GCM_IV_SIZE];
    uint8_t tag[ONVAULT_GCM_TAG_SIZE];

    int rc = onvault_aes_gcm_encrypt(config_key, NULL, NULL, 0,
                                      data, data_len,
                                      ciphertext, tag, iv);
    if (rc != ONVAULT_OK) {
        free(ciphertext);
        return rc;
    }

    /* File format: [iv(12)] [tag(16)] [ciphertext(N)] */
    FILE *f = fopen(path, "wb");
    if (!f) {
        free(ciphertext);
        return ONVAULT_ERR_IO;
    }

    fwrite(iv, 1, ONVAULT_GCM_IV_SIZE, f);
    fwrite(tag, 1, ONVAULT_GCM_TAG_SIZE, f);
    fwrite(ciphertext, 1, data_len, f);
    fclose(f);

    chmod(path, 0600);

    onvault_memzero(ciphertext, data_len);
    free(ciphertext);
    return ONVAULT_OK;
}

int onvault_config_read(const char *path,
                         const onvault_key_t *config_key,
                         uint8_t *data, size_t *data_len)
{
    if (!path || !config_key || !data || !data_len)
        return ONVAULT_ERR_INVALID;

    FILE *f = fopen(path, "rb");
    if (!f)
        return ONVAULT_ERR_NOT_FOUND;

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < (long)(ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE + 1)) {
        fclose(f);
        return ONVAULT_ERR_INVALID;
    }

    size_t cipher_len = (size_t)(file_size - ONVAULT_GCM_IV_SIZE - ONVAULT_GCM_TAG_SIZE);
    if (cipher_len > *data_len) {
        fclose(f);
        return ONVAULT_ERR_MEMORY;
    }

    uint8_t iv[ONVAULT_GCM_IV_SIZE];
    uint8_t tag[ONVAULT_GCM_TAG_SIZE];

    if (fread(iv, 1, ONVAULT_GCM_IV_SIZE, f) != ONVAULT_GCM_IV_SIZE ||
        fread(tag, 1, ONVAULT_GCM_TAG_SIZE, f) != ONVAULT_GCM_TAG_SIZE) {
        fclose(f);
        return ONVAULT_ERR_IO;
    }

    uint8_t *ciphertext = malloc(cipher_len);
    if (!ciphertext) {
        fclose(f);
        return ONVAULT_ERR_MEMORY;
    }

    if (fread(ciphertext, 1, cipher_len, f) != cipher_len) {
        free(ciphertext);
        fclose(f);
        return ONVAULT_ERR_IO;
    }
    fclose(f);

    int rc = onvault_aes_gcm_decrypt(config_key, iv, NULL, 0,
                                      ciphertext, cipher_len,
                                      data, tag);

    onvault_memzero(ciphertext, cipher_len);
    free(ciphertext);

    if (rc == ONVAULT_OK)
        *data_len = cipher_len;

    return rc;
}

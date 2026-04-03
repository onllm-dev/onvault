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
#include <limits.h>

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

int onvault_defaults_parse(const char *filepath, onvault_defaults_t *out)
{
    if (!filepath || !out)
        return ONVAULT_ERR_INVALID;

    out->count = 0;

    FILE *f = fopen(filepath, "r");
    if (!f)
        return ONVAULT_ERR_NOT_FOUND;

    char line[ONVAULT_DEFAULTS_LINE_MAX + 2]; /* +2 for \n and \0 */
    while (fgets(line, (int)sizeof(line), f)) {
        size_t len = strlen(line);

        /* Detect lines that exceed the maximum */
        if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
            fclose(f);
            return ONVAULT_ERR_INVALID;
        }

        /* Trim trailing whitespace / newline */
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                            line[len - 1] == ' '  || line[len - 1] == '\t')) {
            line[--len] = '\0';
        }

        /* Skip empty lines and comments */
        if (len == 0 || line[0] == '#')
            continue;

        /* Only extract list items: lines starting with "- " */
        if (len >= 2 && line[0] == '-' && line[1] == ' ') {
            const char *item = line + 2;
            /* Skip leading whitespace after "- " */
            while (*item == ' ' || *item == '\t')
                item++;

            if (*item == '\0')
                continue; /* empty item */

            if (out->count >= ONVAULT_DEFAULTS_MAX_PATHS) {
                fclose(f);
                return ONVAULT_ERR_INVALID;
            }

            /* Store path — truncate safely */
            strncpy(out->paths[out->count], item, PATH_MAX - 1);
            out->paths[out->count][PATH_MAX - 1] = '\0';
            out->count++;
        }
        /* key: value lines are silently skipped */
    }

    fclose(f);
    return ONVAULT_OK;
}

int onvault_defaults_load(const char *vault_type, onvault_defaults_t *out)
{
    if (!vault_type || !out)
        return ONVAULT_ERR_INVALID;

    char filepath[PATH_MAX];

    /* Try relative to current working directory first */
    snprintf(filepath, sizeof(filepath), "defaults/%s.yaml", vault_type);
    if (onvault_defaults_parse(filepath, out) == ONVAULT_OK)
        return ONVAULT_OK;

    /* Fall back to system-wide install path */
    snprintf(filepath, sizeof(filepath),
             "/usr/local/share/onvault/defaults/%s.yaml", vault_type);
    return onvault_defaults_parse(filepath, out);
}

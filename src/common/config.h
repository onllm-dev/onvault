/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * config.h — Encrypted configuration read/write
 */

#ifndef ONVAULT_CONFIG_H
#define ONVAULT_CONFIG_H

#include "types.h"

/*
 * Write data encrypted with the config key.
 * path: output file path
 * config_key: AES-256-GCM key
 * data: plaintext data to encrypt
 * data_len: data length
 */
int onvault_config_write(const char *path,
                          const onvault_key_t *config_key,
                          const uint8_t *data, size_t data_len);

/*
 * Read and decrypt a config file.
 * path: encrypted file path
 * config_key: AES-256-GCM key
 * data: output buffer (caller allocates)
 * data_len: in: buffer size, out: actual data length
 */
int onvault_config_read(const char *path,
                         const onvault_key_t *config_key,
                         uint8_t *data, size_t *data_len);

/* Simple line-oriented config parser for defaults YAML files.
 * Not a general YAML parser -- handles only key: value and - item format. */

#define ONVAULT_DEFAULTS_MAX_PATHS 32
#define ONVAULT_DEFAULTS_LINE_MAX  4096

typedef struct {
    char paths[ONVAULT_DEFAULTS_MAX_PATHS][PATH_MAX];
    int  count;
} onvault_defaults_t;

/* Parse a defaults file. Returns ONVAULT_OK on success.
 * Extracts list items (lines starting with "- ") under any key. */
int onvault_defaults_parse(const char *filepath, onvault_defaults_t *out);

/* Load smart defaults for a vault type (e.g., "ssh", "aws", "kube").
 * Looks for defaults/<type>.yaml relative to the current working directory
 * or /usr/local/share/onvault/defaults/.
 * Returns ONVAULT_OK on success, ONVAULT_ERR_NOT_FOUND if no defaults file exists. */
int onvault_defaults_load(const char *vault_type, onvault_defaults_t *out);

#endif /* ONVAULT_CONFIG_H */

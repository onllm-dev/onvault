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

#endif /* ONVAULT_CONFIG_H */

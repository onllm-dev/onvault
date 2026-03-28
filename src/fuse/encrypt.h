/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * encrypt.h — Per-file encryption/decryption with key derivation
 */

#ifndef ONVAULT_ENCRYPT_H
#define ONVAULT_ENCRYPT_H

#include "../common/types.h"

/*
 * Generate a new random nonce for a file.
 */
int onvault_file_nonce_generate(onvault_nonce_t *nonce);

/*
 * Store a file's nonce as an extended attribute.
 * ciphertext_path: path to the encrypted file in the vault
 */
int onvault_file_nonce_store(const char *ciphertext_path,
                              const onvault_nonce_t *nonce);

/*
 * Load a file's nonce from its extended attribute.
 */
int onvault_file_nonce_load(const char *ciphertext_path,
                             onvault_nonce_t *nonce);

/*
 * Encrypt a plaintext buffer for a specific file.
 * vault_key: per-vault key
 * nonce: per-file nonce (already stored in xattr)
 * plaintext/plaintext_len: input data
 * ciphertext: output buffer (same size as plaintext)
 * block_offset: offset in file (used as XTS tweak)
 */
int onvault_file_encrypt_block(const onvault_key_t *vault_key,
                                const onvault_nonce_t *nonce,
                                const uint8_t *plaintext, size_t plaintext_len,
                                uint8_t *ciphertext,
                                uint64_t block_offset);

/*
 * Decrypt a ciphertext buffer for a specific file.
 */
int onvault_file_decrypt_block(const onvault_key_t *vault_key,
                                const onvault_nonce_t *nonce,
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                uint8_t *plaintext,
                                uint64_t block_offset);

/*
 * Encrypt an entire file from source to destination.
 * Creates the ciphertext file and stores the nonce in xattr.
 */
int onvault_file_encrypt(const onvault_key_t *vault_key,
                          const char *plaintext_path,
                          const char *ciphertext_path);

/*
 * Decrypt an entire file from ciphertext to plaintext.
 */
int onvault_file_decrypt(const onvault_key_t *vault_key,
                          const char *ciphertext_path,
                          const char *plaintext_path);

#endif /* ONVAULT_ENCRYPT_H */

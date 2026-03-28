/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * crypto.h — Cryptographic operations (OpenSSL wrappers)
 */

#ifndef ONVAULT_CRYPTO_H
#define ONVAULT_CRYPTO_H

#include "types.h"

/*
 * Initialize OpenSSL. Call once at startup.
 */
int onvault_crypto_init(void);

/*
 * AES-256-XTS encryption.
 * key: 64-byte XTS key (two 32-byte keys concatenated)
 * tweak: 16-byte sector/block number (little-endian)
 * in: plaintext
 * out: ciphertext (same size as in)
 * len: data length (must be >= 16 bytes for XTS)
 * Returns 0 on success.
 */
int onvault_aes_xts_encrypt(const onvault_xts_key_t *key,
                            const uint8_t tweak[16],
                            const uint8_t *in, uint8_t *out, size_t len);

int onvault_aes_xts_decrypt(const onvault_xts_key_t *key,
                            const uint8_t tweak[16],
                            const uint8_t *in, uint8_t *out, size_t len);

/*
 * AES-256-GCM authenticated encryption.
 * key: 32-byte key
 * iv: 12-byte IV (randomly generated if NULL, written to iv_out)
 * aad: additional authenticated data (can be NULL)
 * aad_len: length of AAD
 * in: plaintext
 * in_len: plaintext length
 * out: ciphertext (same size as in)
 * tag: 16-byte authentication tag (output)
 * iv_out: 12-byte IV used (output, can be same as iv if iv != NULL)
 * Returns 0 on success.
 */
int onvault_aes_gcm_encrypt(const onvault_key_t *key,
                            const uint8_t *iv,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *in, size_t in_len,
                            uint8_t *out,
                            uint8_t tag[ONVAULT_GCM_TAG_SIZE],
                            uint8_t iv_out[ONVAULT_GCM_IV_SIZE]);

int onvault_aes_gcm_decrypt(const onvault_key_t *key,
                            const uint8_t iv[ONVAULT_GCM_IV_SIZE],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *in, size_t in_len,
                            uint8_t *out,
                            const uint8_t tag[ONVAULT_GCM_TAG_SIZE]);

/*
 * HKDF-SHA512: Extract-then-Expand.
 * salt: optional salt (can be NULL for zero-length salt)
 * salt_len: salt length
 * ikm: input keying material
 * ikm_len: IKM length
 * info: context/application-specific info
 * info_len: info length
 * okm: output keying material
 * okm_len: desired output length
 * Returns 0 on success.
 */
int onvault_hkdf(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len);

/*
 * Generate cryptographically secure random bytes.
 * Returns 0 on success.
 */
int onvault_random_bytes(uint8_t *buf, size_t len);

/*
 * Derive a per-vault key from the master key.
 * master_key: 32-byte master key
 * vault_id: vault identifier string (e.g., "ssh")
 * vault_key: output 32-byte per-vault key
 */
int onvault_derive_vault_key(const onvault_key_t *master_key,
                             const char *vault_id,
                             onvault_key_t *vault_key);

/*
 * Derive a per-file XTS key from the vault key and file nonce.
 * vault_key: 32-byte per-vault key
 * nonce: 16-byte per-file nonce
 * file_key: output 64-byte XTS key
 */
int onvault_derive_file_key(const onvault_key_t *vault_key,
                            const onvault_nonce_t *nonce,
                            onvault_xts_key_t *file_key);

/*
 * Derive the config encryption key from the master key.
 * master_key: 32-byte master key
 * config_key: output 32-byte config key
 */
int onvault_derive_config_key(const onvault_key_t *master_key,
                              onvault_key_t *config_key);

#endif /* ONVAULT_CRYPTO_H */

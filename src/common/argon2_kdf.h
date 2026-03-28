/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * argon2_kdf.h — Argon2id passphrase key derivation
 */

#ifndef ONVAULT_ARGON2_KDF_H
#define ONVAULT_ARGON2_KDF_H

#include "types.h"

/* OWASP 2025 recommended Argon2id parameters */
#define ONVAULT_ARGON2_MEMORY_KB  (46 * 1024)  /* 46 MiB */
#define ONVAULT_ARGON2_ITERATIONS 1
#define ONVAULT_ARGON2_PARALLELISM 1

/*
 * Derive a key from a passphrase using Argon2id.
 * passphrase: user passphrase (null-terminated)
 * salt: 16-byte salt
 * key: output 32-byte derived key
 * Returns 0 on success.
 */
int onvault_argon2_derive(const char *passphrase,
                          const uint8_t salt[ONVAULT_SALT_SIZE],
                          onvault_key_t *key);

/*
 * Hash a passphrase for storage (verification purposes).
 * passphrase: user passphrase
 * salt: 16-byte salt
 * hash: output buffer (at least 128 bytes)
 * hash_len: size of hash buffer
 * Returns 0 on success.
 */
int onvault_argon2_hash(const char *passphrase,
                        const uint8_t salt[ONVAULT_SALT_SIZE],
                        uint8_t *hash, size_t hash_len);

/*
 * Verify a passphrase against a stored hash.
 * Returns 0 if the passphrase matches.
 */
int onvault_argon2_verify(const char *passphrase,
                          const uint8_t salt[ONVAULT_SALT_SIZE],
                          const uint8_t *expected_hash, size_t hash_len);

#endif /* ONVAULT_ARGON2_KDF_H */

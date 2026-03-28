/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * hash.h — SHA-256 hashing (CommonCrypto)
 */

#ifndef ONVAULT_HASH_H
#define ONVAULT_HASH_H

#include "types.h"

/*
 * Compute SHA-256 hash of a buffer.
 */
void onvault_sha256(const uint8_t *data, size_t len, onvault_hash_t *hash);

/*
 * Compute SHA-256 hash of a file.
 * Returns 0 on success, -1 on error.
 */
int onvault_sha256_file(const char *path, onvault_hash_t *hash);

/*
 * Compare two hashes in constant time.
 * Returns 0 if equal.
 */
int onvault_hash_compare(const onvault_hash_t *a, const onvault_hash_t *b);

/*
 * Format hash as hex string. buf must be at least 65 bytes.
 */
void onvault_hash_to_hex(const onvault_hash_t *hash, char *buf);

#endif /* ONVAULT_HASH_H */

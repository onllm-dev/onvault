/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * argon2_kdf.c — Argon2id passphrase key derivation
 */

#include "argon2_kdf.h"
#include "memwipe.h"
#include <argon2.h>
#include <string.h>

int onvault_argon2_derive(const char *passphrase,
                          const uint8_t salt[ONVAULT_SALT_SIZE],
                          onvault_key_t *key)
{
    if (!passphrase || !salt || !key)
        return ONVAULT_ERR_INVALID;

    int rc = argon2id_hash_raw(
        ONVAULT_ARGON2_ITERATIONS,
        ONVAULT_ARGON2_MEMORY_KB,
        ONVAULT_ARGON2_PARALLELISM,
        passphrase, strlen(passphrase),
        salt, ONVAULT_SALT_SIZE,
        key->data, ONVAULT_KEY_SIZE
    );

    return (rc == ARGON2_OK) ? ONVAULT_OK : ONVAULT_ERR_CRYPTO;
}

int onvault_argon2_hash(const char *passphrase,
                        const uint8_t salt[ONVAULT_SALT_SIZE],
                        uint8_t *hash, size_t hash_len)
{
    if (!passphrase || !salt || !hash || hash_len < ONVAULT_KEY_SIZE)
        return ONVAULT_ERR_INVALID;

    int rc = argon2id_hash_raw(
        ONVAULT_ARGON2_ITERATIONS,
        ONVAULT_ARGON2_MEMORY_KB,
        ONVAULT_ARGON2_PARALLELISM,
        passphrase, strlen(passphrase),
        salt, ONVAULT_SALT_SIZE,
        hash, hash_len
    );

    return (rc == ARGON2_OK) ? ONVAULT_OK : ONVAULT_ERR_CRYPTO;
}

int onvault_argon2_verify(const char *passphrase,
                          const uint8_t salt[ONVAULT_SALT_SIZE],
                          const uint8_t *expected_hash, size_t hash_len)
{
    if (!passphrase || !salt || !expected_hash || hash_len == 0)
        return ONVAULT_ERR_INVALID;

    uint8_t computed[128];
    if (hash_len > sizeof(computed))
        return ONVAULT_ERR_INVALID;

    int rc = argon2id_hash_raw(
        ONVAULT_ARGON2_ITERATIONS,
        ONVAULT_ARGON2_MEMORY_KB,
        ONVAULT_ARGON2_PARALLELISM,
        passphrase, strlen(passphrase),
        salt, ONVAULT_SALT_SIZE,
        computed, hash_len
    );

    if (rc != ARGON2_OK) {
        onvault_memzero(computed, sizeof(computed));
        return ONVAULT_ERR_CRYPTO;
    }

    /* Constant-time comparison */
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < hash_len; i++) {
        diff |= computed[i] ^ expected_hash[i];
    }

    onvault_memzero(computed, sizeof(computed));
    return diff ? ONVAULT_ERR_AUTH : ONVAULT_OK;
}

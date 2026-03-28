/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * test_crypto.c — Unit tests for crypto, hash, memwipe, argon2
 */

#include "types.h"
#include "crypto.h"
#include "hash.h"
#include "memwipe.h"
#include "argon2_kdf.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%s] ", #name); \
    if (test_##name()) { \
        tests_passed++; \
        printf("PASS\n"); \
    } else { \
        printf("FAIL\n"); \
    } \
} while(0)

/* --- memwipe tests --- */

static int test_memzero(void)
{
    uint8_t buf[32];
    memset(buf, 0xAA, sizeof(buf));
    onvault_memzero(buf, sizeof(buf));
    for (int i = 0; i < 32; i++) {
        if (buf[i] != 0) return 0;
    }
    return 1;
}

static int test_mlock_munlock(void)
{
    uint8_t buf[4096];
    if (onvault_mlock(buf, sizeof(buf)) != 0)
        return 0; /* May fail without privilege, but try */
    onvault_munlock(buf, sizeof(buf));
    return 1;
}

/* --- AES-256-XTS tests --- */

static int test_aes_xts_roundtrip(void)
{
    onvault_xts_key_t key;
    onvault_random_bytes(key.data, ONVAULT_XTS_KEY_SIZE);

    uint8_t tweak[16] = {0};
    tweak[0] = 1; /* sector number 1 */

    /* XTS requires at least 16 bytes */
    const char *plaintext = "Hello onvault! This is a test of AES-256-XTS encryption.";
    size_t len = strlen(plaintext) + 1; /* include null for exact comparison */
    /* Round up to 16 bytes minimum (already > 16) */

    uint8_t *ciphertext = malloc(len);
    uint8_t *decrypted = malloc(len);
    if (!ciphertext || !decrypted) return 0;

    if (onvault_aes_xts_encrypt(&key, tweak,
                                 (const uint8_t *)plaintext, ciphertext, len) != ONVAULT_OK) {
        free(ciphertext); free(decrypted);
        return 0;
    }

    /* Ciphertext should differ from plaintext */
    if (memcmp(plaintext, ciphertext, len) == 0) {
        free(ciphertext); free(decrypted);
        return 0;
    }

    if (onvault_aes_xts_decrypt(&key, tweak,
                                 ciphertext, decrypted, len) != ONVAULT_OK) {
        free(ciphertext); free(decrypted);
        return 0;
    }

    int ok = (memcmp(plaintext, decrypted, len) == 0);

    onvault_memzero(key.data, ONVAULT_XTS_KEY_SIZE);
    free(ciphertext);
    free(decrypted);
    return ok;
}

/* --- AES-256-GCM tests --- */

static int test_aes_gcm_roundtrip(void)
{
    onvault_key_t key;
    onvault_random_bytes(key.data, ONVAULT_KEY_SIZE);

    const char *plaintext = "Sensitive credential data";
    size_t len = strlen(plaintext);
    const char *aad = "vault:ssh";

    uint8_t *ciphertext = malloc(len);
    uint8_t *decrypted = malloc(len);
    uint8_t tag[ONVAULT_GCM_TAG_SIZE];
    uint8_t iv[ONVAULT_GCM_IV_SIZE];

    if (!ciphertext || !decrypted) return 0;

    if (onvault_aes_gcm_encrypt(&key, NULL,
                                 (const uint8_t *)aad, strlen(aad),
                                 (const uint8_t *)plaintext, len,
                                 ciphertext, tag, iv) != ONVAULT_OK) {
        free(ciphertext); free(decrypted);
        return 0;
    }

    /* Ciphertext should differ */
    if (memcmp(plaintext, ciphertext, len) == 0) {
        free(ciphertext); free(decrypted);
        return 0;
    }

    if (onvault_aes_gcm_decrypt(&key, iv,
                                 (const uint8_t *)aad, strlen(aad),
                                 ciphertext, len,
                                 decrypted, tag) != ONVAULT_OK) {
        free(ciphertext); free(decrypted);
        return 0;
    }

    int ok = (memcmp(plaintext, decrypted, len) == 0);

    onvault_memzero(key.data, ONVAULT_KEY_SIZE);
    free(ciphertext);
    free(decrypted);
    return ok;
}

static int test_aes_gcm_tamper_detection(void)
{
    onvault_key_t key;
    onvault_random_bytes(key.data, ONVAULT_KEY_SIZE);

    const char *plaintext = "Do not tamper";
    size_t len = strlen(plaintext);

    uint8_t *ciphertext = malloc(len);
    uint8_t *decrypted = malloc(len);
    uint8_t tag[ONVAULT_GCM_TAG_SIZE];
    uint8_t iv[ONVAULT_GCM_IV_SIZE];

    if (!ciphertext || !decrypted) return 0;

    onvault_aes_gcm_encrypt(&key, NULL, NULL, 0,
                            (const uint8_t *)plaintext, len,
                            ciphertext, tag, iv);

    /* Tamper with ciphertext */
    ciphertext[0] ^= 0xFF;

    /* Decryption should fail (auth tag mismatch) */
    int rc = onvault_aes_gcm_decrypt(&key, iv, NULL, 0,
                                      ciphertext, len, decrypted, tag);

    onvault_memzero(key.data, ONVAULT_KEY_SIZE);
    free(ciphertext);
    free(decrypted);
    return (rc != ONVAULT_OK); /* Should fail */
}

/* --- HKDF tests --- */

static int test_hkdf_derive(void)
{
    onvault_key_t master;
    onvault_random_bytes(master.data, ONVAULT_KEY_SIZE);

    uint8_t okm1[32], okm2[32], okm3[32];

    /* Same input → same output */
    onvault_hkdf(NULL, 0, master.data, ONVAULT_KEY_SIZE,
                 (const uint8_t *)"info1", 5, okm1, 32);
    onvault_hkdf(NULL, 0, master.data, ONVAULT_KEY_SIZE,
                 (const uint8_t *)"info1", 5, okm2, 32);

    if (memcmp(okm1, okm2, 32) != 0) return 0;

    /* Different info → different output */
    onvault_hkdf(NULL, 0, master.data, ONVAULT_KEY_SIZE,
                 (const uint8_t *)"info2", 5, okm3, 32);

    if (memcmp(okm1, okm3, 32) == 0) return 0;

    onvault_memzero(master.data, ONVAULT_KEY_SIZE);
    return 1;
}

/* --- Key derivation hierarchy tests --- */

static int test_vault_key_derivation(void)
{
    onvault_key_t master, vault_ssh, vault_aws;

    onvault_random_bytes(master.data, ONVAULT_KEY_SIZE);

    if (onvault_derive_vault_key(&master, "ssh", &vault_ssh) != ONVAULT_OK)
        return 0;
    if (onvault_derive_vault_key(&master, "aws", &vault_aws) != ONVAULT_OK)
        return 0;

    /* Different vaults → different keys */
    if (memcmp(vault_ssh.data, vault_aws.data, ONVAULT_KEY_SIZE) == 0)
        return 0;

    /* Same vault → same key (deterministic) */
    onvault_key_t vault_ssh2;
    if (onvault_derive_vault_key(&master, "ssh", &vault_ssh2) != ONVAULT_OK)
        return 0;
    if (memcmp(vault_ssh.data, vault_ssh2.data, ONVAULT_KEY_SIZE) != 0)
        return 0;

    onvault_memzero(master.data, ONVAULT_KEY_SIZE);
    onvault_memzero(vault_ssh.data, ONVAULT_KEY_SIZE);
    onvault_memzero(vault_aws.data, ONVAULT_KEY_SIZE);
    onvault_memzero(vault_ssh2.data, ONVAULT_KEY_SIZE);
    return 1;
}

static int test_file_key_derivation(void)
{
    onvault_key_t vault_key;
    onvault_random_bytes(vault_key.data, ONVAULT_KEY_SIZE);

    onvault_nonce_t nonce1, nonce2;
    onvault_random_bytes(nonce1.data, ONVAULT_NONCE_SIZE);
    onvault_random_bytes(nonce2.data, ONVAULT_NONCE_SIZE);

    onvault_xts_key_t fk1, fk2;

    if (onvault_derive_file_key(&vault_key, &nonce1, &fk1) != ONVAULT_OK)
        return 0;
    if (onvault_derive_file_key(&vault_key, &nonce2, &fk2) != ONVAULT_OK)
        return 0;

    /* Different nonces → different file keys */
    if (memcmp(fk1.data, fk2.data, ONVAULT_XTS_KEY_SIZE) == 0)
        return 0;

    onvault_memzero(vault_key.data, ONVAULT_KEY_SIZE);
    onvault_memzero(fk1.data, ONVAULT_XTS_KEY_SIZE);
    onvault_memzero(fk2.data, ONVAULT_XTS_KEY_SIZE);
    return 1;
}

static int test_config_key_derivation(void)
{
    onvault_key_t master, config_key, vault_key;
    onvault_random_bytes(master.data, ONVAULT_KEY_SIZE);

    if (onvault_derive_config_key(&master, &config_key) != ONVAULT_OK)
        return 0;
    if (onvault_derive_vault_key(&master, "ssh", &vault_key) != ONVAULT_OK)
        return 0;

    /* Config key differs from vault keys */
    if (memcmp(config_key.data, vault_key.data, ONVAULT_KEY_SIZE) == 0)
        return 0;

    onvault_memzero(master.data, ONVAULT_KEY_SIZE);
    onvault_memzero(config_key.data, ONVAULT_KEY_SIZE);
    onvault_memzero(vault_key.data, ONVAULT_KEY_SIZE);
    return 1;
}

/* --- SHA-256 tests --- */

static int test_sha256_basic(void)
{
    /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    const uint8_t expected[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    onvault_hash_t hash;
    onvault_sha256((const uint8_t *)"abc", 3, &hash);

    return (memcmp(hash.data, expected, 32) == 0);
}

static int test_sha256_hex(void)
{
    onvault_hash_t hash;
    onvault_sha256((const uint8_t *)"abc", 3, &hash);

    char hex[65];
    onvault_hash_to_hex(&hash, hex);

    return (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
}

static int test_hash_compare(void)
{
    onvault_hash_t a, b;
    onvault_sha256((const uint8_t *)"abc", 3, &a);
    onvault_sha256((const uint8_t *)"abc", 3, &b);

    if (onvault_hash_compare(&a, &b) != 0)
        return 0;

    onvault_sha256((const uint8_t *)"xyz", 3, &b);
    if (onvault_hash_compare(&a, &b) == 0)
        return 0;

    return 1;
}

/* --- Argon2id tests --- */

static int test_argon2_derive(void)
{
    uint8_t salt[ONVAULT_SALT_SIZE];
    onvault_random_bytes(salt, ONVAULT_SALT_SIZE);

    onvault_key_t key1, key2;

    /* Same passphrase + salt → same key */
    if (onvault_argon2_derive("mypassphrase", salt, &key1) != ONVAULT_OK)
        return 0;
    if (onvault_argon2_derive("mypassphrase", salt, &key2) != ONVAULT_OK)
        return 0;

    if (memcmp(key1.data, key2.data, ONVAULT_KEY_SIZE) != 0)
        return 0;

    /* Different passphrase → different key */
    if (onvault_argon2_derive("otherpassphrase", salt, &key2) != ONVAULT_OK)
        return 0;

    if (memcmp(key1.data, key2.data, ONVAULT_KEY_SIZE) == 0)
        return 0;

    onvault_memzero(key1.data, ONVAULT_KEY_SIZE);
    onvault_memzero(key2.data, ONVAULT_KEY_SIZE);
    return 1;
}

static int test_argon2_verify(void)
{
    uint8_t salt[ONVAULT_SALT_SIZE];
    onvault_random_bytes(salt, ONVAULT_SALT_SIZE);

    uint8_t hash[ONVAULT_KEY_SIZE];
    if (onvault_argon2_hash("testpass", salt, hash, ONVAULT_KEY_SIZE) != ONVAULT_OK)
        return 0;

    /* Correct passphrase should verify */
    if (onvault_argon2_verify("testpass", salt, hash, ONVAULT_KEY_SIZE) != ONVAULT_OK)
        return 0;

    /* Wrong passphrase should fail */
    if (onvault_argon2_verify("wrongpass", salt, hash, ONVAULT_KEY_SIZE) == ONVAULT_OK)
        return 0;

    return 1;
}

/* --- Main --- */

int main(void)
{
    printf("onvault crypto test suite\n");
    printf("=========================\n\n");

    onvault_crypto_init();

    printf("Memory safety:\n");
    TEST(memzero);
    TEST(mlock_munlock);

    printf("\nAES-256-XTS:\n");
    TEST(aes_xts_roundtrip);

    printf("\nAES-256-GCM:\n");
    TEST(aes_gcm_roundtrip);
    TEST(aes_gcm_tamper_detection);

    printf("\nHKDF-SHA512:\n");
    TEST(hkdf_derive);

    printf("\nKey hierarchy:\n");
    TEST(vault_key_derivation);
    TEST(file_key_derivation);
    TEST(config_key_derivation);

    printf("\nSHA-256:\n");
    TEST(sha256_basic);
    TEST(sha256_hex);
    TEST(hash_compare);

    printf("\nArgon2id:\n");
    TEST(argon2_derive);
    TEST(argon2_verify);

    printf("\n=========================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}

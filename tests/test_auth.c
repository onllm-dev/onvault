/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * test_auth.c — Unit tests for auth lifecycle, sessions, challenge-response
 */

#include "types.h"
#include "crypto.h"
#include "hash.h"
#include "memwipe.h"
#include "argon2_kdf.h"
#include "../src/auth/auth.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

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

/* Set HOME to a temp directory for test isolation */
static char g_test_home[PATH_MAX];

static void setup_test_home(void)
{
    snprintf(g_test_home, sizeof(g_test_home), "/tmp/onvault_test_%d", getpid());
    mkdir(g_test_home, 0700);
    setenv("HOME", g_test_home, 1);
}

static void cleanup_dir(const char *path)
{
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void)system(cmd);
}

static void cleanup_test_home(void)
{
    cleanup_dir(g_test_home);
}

/* --- Auth init tests --- */

static int test_auth_init_creates_files(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    int rc = onvault_auth_init("testpass123", recovery_key);
    if (rc != ONVAULT_OK) return 0;

    /* Verify files created */
    char path[PATH_MAX];
    struct stat st;

    snprintf(path, sizeof(path), "%s/.onvault/salt", g_test_home);
    if (stat(path, &st) != 0) return 0;

    snprintf(path, sizeof(path), "%s/.onvault/auth.enc", g_test_home);
    if (stat(path, &st) != 0) return 0;

    snprintf(path, sizeof(path), "%s/.onvault/vaults", g_test_home);
    if (stat(path, &st) != 0) return 0;

    snprintf(path, sizeof(path), "%s/.onvault/mnt", g_test_home);
    if (stat(path, &st) != 0) return 0;

    /* Recovery key should be 24 chars */
    if (strlen(recovery_key) != 24) return 0;

    cleanup_test_home();
    return 1;
}

/* --- Auth unlock tests --- */

static int test_auth_unlock_correct_passphrase(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("correctpass", recovery_key) != ONVAULT_OK)
        return 0;

    onvault_key_t master_key;
    int rc = onvault_auth_unlock("correctpass", &master_key);
    onvault_key_wipe(&master_key, sizeof(master_key));

    cleanup_test_home();
    return rc == ONVAULT_OK;
}

static int test_auth_unlock_wrong_passphrase(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("correctpass", recovery_key) != ONVAULT_OK)
        return 0;

    onvault_key_t master_key;
    int rc = onvault_auth_unlock("wrongpass", &master_key);

    cleanup_test_home();
    return rc == ONVAULT_ERR_AUTH;
}

/* --- Auth lock tests --- */

static int test_auth_lock_deletes_session(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("testpass", recovery_key) != ONVAULT_OK)
        return 0;

    onvault_key_t master_key;
    if (onvault_auth_unlock("testpass", &master_key) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }
    onvault_key_wipe(&master_key, sizeof(master_key));

    /* Session file should exist after unlock */
    char session_path[PATH_MAX];
    struct stat st;
    snprintf(session_path, sizeof(session_path), "%s/.onvault/session", g_test_home);
    if (stat(session_path, &st) != 0) {
        cleanup_test_home();
        return 0;
    }

    /* Lock should delete session */
    onvault_auth_lock();
    int result = (stat(session_path, &st) != 0); /* should not exist */

    cleanup_test_home();
    return result;
}

/* --- Auth unlock after lock (round-trip) --- */

static int test_auth_unlock_after_lock(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("mypass", recovery_key) != ONVAULT_OK)
        return 0;

    onvault_key_t mk1, mk2;

    /* First unlock */
    if (onvault_auth_unlock("mypass", &mk1) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }

    /* Lock */
    onvault_auth_lock();

    /* Second unlock should succeed */
    int rc = onvault_auth_unlock("mypass", &mk2);

    /* Keys should match */
    int keys_match = (rc == ONVAULT_OK) &&
                     onvault_constant_time_eq(mk1.data, mk2.data, ONVAULT_KEY_SIZE);

    onvault_key_wipe(&mk1, sizeof(mk1));
    onvault_key_wipe(&mk2, sizeof(mk2));
    cleanup_test_home();
    return keys_match;
}

/* --- Challenge-response tests --- */

static int test_auth_challenge_response_valid(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("crpass", recovery_key) != ONVAULT_OK)
        return 0;

    /* Generate a nonce */
    uint8_t nonce[ONVAULT_HASH_SIZE];
    onvault_random_bytes(nonce, sizeof(nonce));

    /* Compute proof from passphrase */
    uint8_t proof[ONVAULT_HASH_SIZE];
    if (onvault_auth_compute_proof("crpass", nonce, sizeof(nonce), proof) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }

    /* Verify proof using stored key */
    int rc = onvault_auth_verify_proof(proof, nonce, sizeof(nonce));
    cleanup_test_home();
    return rc == ONVAULT_OK;
}

static int test_auth_challenge_response_wrong(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("rightpass", recovery_key) != ONVAULT_OK)
        return 0;

    uint8_t nonce[ONVAULT_HASH_SIZE];
    onvault_random_bytes(nonce, sizeof(nonce));

    /* Compute proof with WRONG passphrase */
    uint8_t proof[ONVAULT_HASH_SIZE];
    if (onvault_auth_compute_proof("wrongpass", nonce, sizeof(nonce), proof) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }

    int rc = onvault_auth_verify_proof(proof, nonce, sizeof(nonce));
    cleanup_test_home();
    return rc == ONVAULT_ERR_AUTH;
}

/* --- Session token expiry test --- */

static int test_auth_session_token_expiry(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("sesspass", recovery_key) != ONVAULT_OK)
        return 0;

    onvault_key_t master_key;
    if (onvault_auth_unlock("sesspass", &master_key) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }
    onvault_key_wipe(&master_key, sizeof(master_key));

    /* Tamper with session file to make it expired:
     * Session format: [token(32)][expiry(8)][hmac(32)]
     * Set expiry to a past time — HMAC will be invalid, so
     * check_session should fail with ERR_AUTH */
    char session_path[PATH_MAX];
    snprintf(session_path, sizeof(session_path), "%s/.onvault/session", g_test_home);

    uint8_t session_blob[72]; /* 32 + 8 + 32 */
    FILE *f = fopen(session_path, "rb");
    if (!f) { cleanup_test_home(); return 0; }
    size_t n = fread(session_blob, 1, sizeof(session_blob), f);
    fclose(f);
    if (n != 72) { cleanup_test_home(); return 0; }

    /* Corrupt the expiry field to force mismatch — HMAC check will fail */
    uint64_t past_time = 1000; /* Unix epoch + 1000 seconds */
    memcpy(session_blob + 32, &past_time, sizeof(past_time));

    f = fopen(session_path, "wb");
    if (!f) { cleanup_test_home(); return 0; }
    fwrite(session_blob, 1, sizeof(session_blob), f);
    fclose(f);

    /* Session check should fail (HMAC mismatch due to tampered expiry) */
    onvault_key_t check_key;
    int rc = onvault_auth_check_session(&check_key);
    if (rc == ONVAULT_OK)
        onvault_key_wipe(&check_key, sizeof(check_key));

    cleanup_test_home();
    return rc == ONVAULT_ERR_AUTH;
}

/* --- Session refresh tests --- */

static int test_auth_session_refresh_extends_ttl(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("refreshpass", recovery_key) != ONVAULT_OK)
        return 0;

    onvault_key_t master_key;
    if (onvault_auth_unlock("refreshpass", &master_key) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }

    /* Refresh should succeed */
    int rc = onvault_auth_refresh_session(&master_key);

    /* Check session is still valid after refresh */
    onvault_key_t check_key;
    int check_rc = onvault_auth_check_session(&check_key);
    if (check_rc == ONVAULT_OK)
        onvault_key_wipe(&check_key, sizeof(check_key));

    onvault_key_wipe(&master_key, sizeof(master_key));
    cleanup_test_home();
    return rc == ONVAULT_OK && check_rc == ONVAULT_OK;
}

/* --- Touch ID tests --- */

static int test_auth_touchid_unlock_success(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("tidpass", recovery_key) != ONVAULT_OK)
        return 0;

    /* First do a normal unlock to store key in keystore stub */
    onvault_key_t mk1;
    if (onvault_auth_unlock("tidpass", &mk1) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }
    onvault_auth_lock();

    /* Now Touch ID unlock should work (stub always succeeds) */
    onvault_key_t mk2;
    int rc = onvault_auth_unlock_touchid(&mk2);

    int keys_match = (rc == ONVAULT_OK) &&
                     onvault_constant_time_eq(mk1.data, mk2.data, ONVAULT_KEY_SIZE);

    onvault_key_wipe(&mk1, sizeof(mk1));
    if (rc == ONVAULT_OK)
        onvault_key_wipe(&mk2, sizeof(mk2));

    cleanup_test_home();
    return keys_match;
}

/* --- Recovery key tests --- */

static int test_auth_recovery_hash_stored(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("recpass", recovery_key) != ONVAULT_OK)
        return 0;

    /* recovery.enc should exist after init */
    char path[PATH_MAX];
    struct stat st;
    snprintf(path, sizeof(path), "%s/.onvault/recovery.enc", g_test_home);
    int exists = (stat(path, &st) == 0);

    cleanup_test_home();
    return exists;
}

static int test_auth_recovery_unlock_correct(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("oldpass", recovery_key) != ONVAULT_OK)
        return 0;

    /* First unlock to store key */
    onvault_key_t mk;
    if (onvault_auth_unlock("oldpass", &mk) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }
    onvault_key_wipe(&mk, sizeof(mk));
    onvault_auth_lock();

    /* Recovery unlock with correct key + new passphrase */
    onvault_key_t recovered_mk;
    int rc = onvault_auth_unlock_recovery(recovery_key, "newpass", &recovered_mk);
    if (rc == ONVAULT_OK)
        onvault_key_wipe(&recovered_mk, sizeof(recovered_mk));

    /* Should be able to unlock with new passphrase */
    onvault_auth_lock();
    int new_rc = onvault_auth_unlock("newpass", &mk);
    if (new_rc == ONVAULT_OK)
        onvault_key_wipe(&mk, sizeof(mk));

    cleanup_test_home();
    return rc == ONVAULT_OK && new_rc == ONVAULT_OK;
}

static int test_auth_recovery_unlock_wrong(void)
{
    cleanup_test_home();
    setup_test_home();

    char recovery_key[32];
    if (onvault_auth_init("recwrongpass", recovery_key) != ONVAULT_OK)
        return 0;

    /* First unlock to store key */
    onvault_key_t mk;
    if (onvault_auth_unlock("recwrongpass", &mk) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }
    onvault_key_wipe(&mk, sizeof(mk));
    onvault_auth_lock();

    /* Recovery with WRONG key should fail */
    onvault_key_t recovered_mk;
    int rc = onvault_auth_unlock_recovery("WRONGKEYWRONGKEYWRONGKEY", "newpass", &recovered_mk);
    if (rc == ONVAULT_OK)
        onvault_key_wipe(&recovered_mk, sizeof(recovered_mk));

    cleanup_test_home();
    return rc != ONVAULT_OK;
}

int main(void)
{
    printf("onvault auth test suite\n");
    printf("=======================\n\n");

    printf("Auth init:\n");
    TEST(auth_init_creates_files);

    printf("\nAuth unlock:\n");
    TEST(auth_unlock_correct_passphrase);
    TEST(auth_unlock_wrong_passphrase);

    printf("\nAuth lock:\n");
    TEST(auth_lock_deletes_session);
    TEST(auth_unlock_after_lock);

    printf("\nChallenge-response:\n");
    TEST(auth_challenge_response_valid);
    TEST(auth_challenge_response_wrong);

    printf("\nSession tokens:\n");
    TEST(auth_session_token_expiry);

    printf("\nSession refresh:\n");
    TEST(auth_session_refresh_extends_ttl);

    printf("\nTouch ID:\n");
    TEST(auth_touchid_unlock_success);

    printf("\nRecovery key:\n");
    TEST(auth_recovery_hash_stored);
    TEST(auth_recovery_unlock_correct);
    TEST(auth_recovery_unlock_wrong);

    printf("\n=======================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}

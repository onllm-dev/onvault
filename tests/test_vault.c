/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * test_vault.c — End-to-end vault encryption/decryption tests
 *
 * Tests the full pipeline WITHOUT needing macFUSE or ESF:
 *   1. Generate master key
 *   2. Derive vault key
 *   3. Encrypt files to vault directory
 *   4. Verify ciphertext differs from plaintext
 *   5. Decrypt files back
 *   6. Verify roundtrip integrity
 *   7. Test policy engine (allowlist matching)
 *   8. Test config encryption
 *
 * Run: make test-vault && ./tests/test_vault
 */

#include "types.h"
#include "crypto.h"
#include "hash.h"
#include "memwipe.h"
#include "config.h"
#include "log.h"
#include "../auth/auth.h"
#include "../fuse/encrypt.h"
#include "../esf/policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

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

static char g_test_dir[PATH_MAX];

static void setup_test_dir(void)
{
    snprintf(g_test_dir, PATH_MAX, "/tmp/onvault-test-%d", getpid());
    mkdir(g_test_dir, 0700);
}

static void cleanup_path(const char *path)
{
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    system(cmd);
}

/* --- File encryption roundtrip --- */

static int test_file_encrypt_decrypt(void)
{
    /* Create a test file with known content */
    char plain_path[PATH_MAX], cipher_path[PATH_MAX], decrypted_path[PATH_MAX];
    snprintf(plain_path, PATH_MAX, "%s/secret.txt", g_test_dir);
    snprintf(cipher_path, PATH_MAX, "%s/secret.txt.enc", g_test_dir);
    snprintf(decrypted_path, PATH_MAX, "%s/secret.txt.dec", g_test_dir);

    const char *secret = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                         "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAG\n"
                         "This is a fake SSH key for testing onvault encryption.\n"
                         "It should be encrypted at rest and only accessible to\n"
                         "authorized processes like /usr/bin/ssh.\n"
                         "-----END OPENSSH PRIVATE KEY-----\n";

    FILE *f = fopen(plain_path, "w");
    if (!f) return 0;
    fwrite(secret, 1, strlen(secret), f);
    fclose(f);

    /* Generate vault key */
    onvault_key_t master_key, vault_key;
    onvault_random_bytes(master_key.data, ONVAULT_KEY_SIZE);
    onvault_derive_vault_key(&master_key, "ssh", &vault_key);

    /* Encrypt */
    int rc = onvault_file_encrypt(&vault_key, plain_path, cipher_path);
    if (rc != ONVAULT_OK) return 0;

    /* Verify ciphertext exists and differs from plaintext */
    struct stat st;
    if (stat(cipher_path, &st) != 0) return 0;

    /* Read ciphertext and verify it's not plaintext */
    FILE *fc = fopen(cipher_path, "rb");
    if (!fc) return 0;
    char cipherbuf[1024];
    size_t cn = fread(cipherbuf, 1, sizeof(cipherbuf), fc);
    fclose(fc);

    if (cn > 0 && strstr(cipherbuf, "OPENSSH PRIVATE KEY") != NULL) {
        /* Plaintext found in ciphertext file! Encryption failed. */
        return 0;
    }

    /* Decrypt */
    rc = onvault_file_decrypt(&vault_key, cipher_path, decrypted_path);
    if (rc != ONVAULT_OK) return 0;

    /* Read decrypted and compare to original */
    FILE *fd = fopen(decrypted_path, "r");
    if (!fd) return 0;
    char decbuf[1024];
    size_t dn = fread(decbuf, 1, sizeof(decbuf), fd);
    fclose(fd);

    int ok = (dn == strlen(secret) && memcmp(decbuf, secret, dn) == 0);

    onvault_memzero(master_key.data, ONVAULT_KEY_SIZE);
    onvault_memzero(vault_key.data, ONVAULT_KEY_SIZE);

    return ok;
}

/* --- Wrong key fails decryption --- */

static int test_wrong_key_fails(void)
{
    char plain_path[PATH_MAX], cipher_path[PATH_MAX], dec_path[PATH_MAX];
    snprintf(plain_path, PATH_MAX, "%s/wrongkey.txt", g_test_dir);
    snprintf(cipher_path, PATH_MAX, "%s/wrongkey.enc", g_test_dir);
    snprintf(dec_path, PATH_MAX, "%s/wrongkey.dec", g_test_dir);

    FILE *f = fopen(plain_path, "w");
    fprintf(f, "sensitive data that should not decrypt with wrong key");
    fclose(f);

    onvault_key_t key1, key2;
    onvault_random_bytes(key1.data, ONVAULT_KEY_SIZE);
    onvault_random_bytes(key2.data, ONVAULT_KEY_SIZE);

    /* Encrypt with key1 */
    onvault_file_encrypt(&key1, plain_path, cipher_path);

    /* Decrypt with key2 — should produce garbage, not the original */
    onvault_file_decrypt(&key2, cipher_path, dec_path);

    FILE *fd = fopen(dec_path, "r");
    if (!fd) return 1; /* No output = acceptable failure */

    char buf[256];
    size_t n = fread(buf, 1, sizeof(buf), fd);
    fclose(fd);

    /* Should NOT match original */
    int ok = (n == 0 || memcmp(buf, "sensitive data", 14) != 0);

    onvault_memzero(key1.data, ONVAULT_KEY_SIZE);
    onvault_memzero(key2.data, ONVAULT_KEY_SIZE);
    return ok;
}

/* --- Per-file nonce uniqueness --- */

static int test_nonce_uniqueness(void)
{
    char path1[PATH_MAX], path2[PATH_MAX];
    snprintf(path1, PATH_MAX, "%s/nonce1.enc", g_test_dir);
    snprintf(path2, PATH_MAX, "%s/nonce2.enc", g_test_dir);

    /* Create two dummy files */
    FILE *f1 = fopen(path1, "w"); fprintf(f1, "data"); fclose(f1);
    FILE *f2 = fopen(path2, "w"); fprintf(f2, "data"); fclose(f2);

    onvault_nonce_t n1, n2;
    onvault_file_nonce_generate(&n1);
    onvault_file_nonce_generate(&n2);

    /* Nonces should differ */
    return (memcmp(n1.data, n2.data, ONVAULT_NONCE_SIZE) != 0);
}

/* --- Nonce xattr roundtrip --- */

static int test_nonce_xattr(void)
{
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "%s/xattr_test.dat", g_test_dir);

    FILE *f = fopen(path, "w"); fprintf(f, "test"); fclose(f);

    onvault_nonce_t original, loaded;
    onvault_file_nonce_generate(&original);

    if (onvault_file_nonce_store(path, &original) != ONVAULT_OK)
        return 0;

    if (onvault_file_nonce_load(path, &loaded) != ONVAULT_OK)
        return 0;

    return (memcmp(original.data, loaded.data, ONVAULT_NONCE_SIZE) == 0);
}

/* --- Policy engine tests --- */

static int test_policy_allow(void)
{
    onvault_policy_clear();

    /* Create a vault policy */
    onvault_vault_policy_t policy;
    memset(&policy, 0, sizeof(policy));
    strlcpy(policy.vault_id, "ssh", sizeof(policy.vault_id));
    strlcpy(policy.mount_path, "/tmp/onvault-mnt/ssh", sizeof(policy.mount_path));
    policy.verify_mode = VERIFY_CODESIGN_PREFERRED;

    /* Add rule: allow /usr/bin/ssh */
    strlcpy(policy.rules[0].process_path, "/usr/bin/ssh", PATH_MAX);
    policy.rules[0].action = RULE_ALLOW;
    policy.rules[0].allow_escalated = 0;
    policy.rule_count = 1;

    onvault_policy_add_vault(&policy);

    /* Test: /usr/bin/ssh should be allowed */
    onvault_process_t proc_ssh;
    memset(&proc_ssh, 0, sizeof(proc_ssh));
    proc_ssh.pid = 1000;
    proc_ssh.ruid = 501;
    proc_ssh.euid = 501;
    strlcpy(proc_ssh.path, "/usr/bin/ssh", PATH_MAX);

    int allowed = onvault_policy_evaluate(&proc_ssh,
                                           "/tmp/onvault-mnt/ssh/id_rsa",
                                           "/tmp/onvault-mnt/ssh");
    if (!allowed) return 0;

    /* Test: /usr/bin/python3 should be denied */
    onvault_process_t proc_py;
    memset(&proc_py, 0, sizeof(proc_py));
    proc_py.pid = 2000;
    proc_py.ruid = 501;
    proc_py.euid = 501;
    strlcpy(proc_py.path, "/usr/bin/python3", PATH_MAX);

    int denied = !onvault_policy_evaluate(&proc_py,
                                           "/tmp/onvault-mnt/ssh/id_rsa",
                                           "/tmp/onvault-mnt/ssh");

    onvault_policy_clear();
    return denied;
}

/* --- su/sudo escalation detection --- */

static int test_policy_su_detection(void)
{
    onvault_policy_clear();

    onvault_vault_policy_t policy;
    memset(&policy, 0, sizeof(policy));
    strlcpy(policy.vault_id, "ssh", sizeof(policy.vault_id));
    strlcpy(policy.mount_path, "/tmp/mnt/ssh", sizeof(policy.mount_path));
    policy.verify_mode = VERIFY_CODESIGN_PREFERRED;

    strlcpy(policy.rules[0].process_path, "/usr/bin/ssh", PATH_MAX);
    policy.rules[0].action = RULE_ALLOW;
    policy.rules[0].allow_escalated = 0; /* Deny su/sudo */
    policy.rule_count = 1;

    onvault_policy_add_vault(&policy);

    /* Normal user (ruid == euid) — should be allowed */
    onvault_process_t normal;
    memset(&normal, 0, sizeof(normal));
    normal.ruid = 501;
    normal.euid = 501;
    strlcpy(normal.path, "/usr/bin/ssh", PATH_MAX);

    int normal_ok = onvault_policy_evaluate(&normal, "/tmp/mnt/ssh/key", "/tmp/mnt/ssh");

    /* Root via su (ruid=0, euid=501) — should be denied */
    onvault_process_t escalated;
    memset(&escalated, 0, sizeof(escalated));
    escalated.ruid = 0;  /* Root's real UID */
    escalated.euid = 501; /* Pretending to be user */
    strlcpy(escalated.path, "/usr/bin/ssh", PATH_MAX);

    int escalated_denied = !onvault_policy_evaluate(&escalated, "/tmp/mnt/ssh/key", "/tmp/mnt/ssh");

    onvault_policy_clear();
    return normal_ok && escalated_denied;
}

/* --- Encrypted config roundtrip --- */

static int test_config_encrypt_decrypt(void)
{
    char config_path[PATH_MAX];
    snprintf(config_path, PATH_MAX, "%s/test.enc", g_test_dir);

    onvault_key_t config_key;
    onvault_random_bytes(config_key.data, ONVAULT_KEY_SIZE);

    const char *policy_data = "vault_id: ssh\nrules:\n  - /usr/bin/ssh: allow\n  - default: deny\n";
    size_t data_len = strlen(policy_data);

    /* Write encrypted */
    int rc = onvault_config_write(config_path, &config_key,
                                   (const uint8_t *)policy_data, data_len);
    if (rc != ONVAULT_OK) return 0;

    /* Read and decrypt */
    uint8_t buf[1024];
    size_t buf_len = sizeof(buf);
    rc = onvault_config_read(config_path, &config_key, buf, &buf_len);
    if (rc != ONVAULT_OK) return 0;

    /* Verify */
    int ok = (buf_len == data_len && memcmp(buf, policy_data, data_len) == 0);

    /* Verify wrong key fails */
    onvault_key_t wrong_key;
    onvault_random_bytes(wrong_key.data, ONVAULT_KEY_SIZE);
    buf_len = sizeof(buf);
    rc = onvault_config_read(config_path, &wrong_key, buf, &buf_len);
    ok = ok && (rc != ONVAULT_OK); /* Should fail with wrong key */

    onvault_memzero(config_key.data, ONVAULT_KEY_SIZE);
    return ok;
}

/* --- Encrypted audit log --- */

static int test_encrypted_log(void)
{
    /* Clean up stale log files from previous test runs */
    char data_dir_pre[PATH_MAX];
    if (onvault_get_data_dir(data_dir_pre) == ONVAULT_OK) {
        char log_dir_pre[PATH_MAX];
        snprintf(log_dir_pre, PATH_MAX, "%s/logs", data_dir_pre);
        cleanup_path(log_dir_pre);
    }

    onvault_key_t log_key;
    onvault_random_bytes(log_key.data, ONVAULT_KEY_SIZE);

    if (onvault_log_init(&log_key) != ONVAULT_OK)
        return 0;

    /* Write some log entries */
    onvault_log_write(LOG_ACCESS_ALLOWED, "ssh", "/usr/bin/ssh", 1234,
                       "/home/user/.ssh/id_rsa", "test allowed");
    onvault_log_write(LOG_ACCESS_DENIED, "ssh", "/usr/bin/python3", 5678,
                       "/home/user/.ssh/id_rsa", "test denied");
    onvault_log_write(LOG_VAULT_MOUNTED, "aws", NULL, 0, NULL, "mounted");

    /* Read all entries back */
    char buf[8192];
    size_t buf_len = sizeof(buf);
    if (onvault_log_read(buf, &buf_len, 0, 0) != ONVAULT_OK)
        return 0;

    /* Should have all 3 entries */
    if (buf_len == 0)
        return 0;

    /* Check that entries contain expected content */
    buf[buf_len] = '\0';
    if (strstr(buf, "\"ALLOWED\"") == NULL)
        return 0;
    if (strstr(buf, "\"DENIED\"") == NULL)
        return 0;
    if (strstr(buf, "\"MOUNTED\"") == NULL)
        return 0;

    /* Read denied-only entries */
    buf_len = sizeof(buf);
    if (onvault_log_read(buf, &buf_len, 0, 1) != ONVAULT_OK)
        return 0;

    buf[buf_len] = '\0';
    if (strstr(buf, "\"DENIED\"") == NULL)
        return 0;
    /* Should NOT contain ALLOWED entries */
    if (strstr(buf, "\"ALLOWED\"") != NULL)
        return 0;

    onvault_log_close();
    onvault_memzero(log_key.data, ONVAULT_KEY_SIZE);

    /* Clean up log files created during test */
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) == ONVAULT_OK) {
        char log_dir[PATH_MAX];
        snprintf(log_dir, PATH_MAX, "%s/logs", data_dir);
        cleanup_path(log_dir);
    }

    return 1;
}

/* --- Full pipeline: key hierarchy → encrypt → decrypt --- */

static int test_full_pipeline(void)
{
    /* Simulate: passphrase → master key → vault key → file key → encrypt → decrypt */

    /* 1. Master key from "passphrase" */
    uint8_t salt[ONVAULT_SALT_SIZE];
    onvault_random_bytes(salt, ONVAULT_SALT_SIZE);

    onvault_key_t master_key;
    onvault_mlock(&master_key, sizeof(master_key));

    /* Use a quick derivation for testing (not full Argon2 which is slow) */
    onvault_hkdf(salt, ONVAULT_SALT_SIZE,
                 (const uint8_t *)"testpassphrase", 14,
                 (const uint8_t *)"master", 6,
                 master_key.data, ONVAULT_KEY_SIZE);

    /* 2. Derive vault key */
    onvault_key_t vault_key;
    onvault_derive_vault_key(&master_key, "ssh", &vault_key);

    /* 3. Derive config key */
    onvault_key_t config_key;
    onvault_derive_config_key(&master_key, &config_key);

    /* 4. Create test file */
    char src_dir[PATH_MAX], vault_dir[PATH_MAX];
    snprintf(src_dir, PATH_MAX, "%s/pipeline_src", g_test_dir);
    snprintf(vault_dir, PATH_MAX, "%s/pipeline_vault", g_test_dir);
    mkdir(src_dir, 0700);

    char key_path[PATH_MAX];
    snprintf(key_path, PATH_MAX, "%s/id_rsa", src_dir);
    FILE *f = fopen(key_path, "w");
    fprintf(f, "PRIVATE KEY CONTENT - TOP SECRET");
    fclose(f);

    /* 5. Encrypt file */
    mkdir(vault_dir, 0700);
    char enc_path[PATH_MAX];
    snprintf(enc_path, PATH_MAX, "%s/id_rsa", vault_dir);
    int rc = onvault_file_encrypt(&vault_key, key_path, enc_path);
    if (rc != ONVAULT_OK) return 0;

    /* 6. Verify disk has ciphertext */
    FILE *fc = fopen(enc_path, "rb");
    char buf[256];
    size_t n = fread(buf, 1, sizeof(buf), fc);
    fclose(fc);
    if (n > 0 && strstr(buf, "PRIVATE KEY") != NULL) return 0;

    /* 7. Decrypt with same vault key */
    char dec_path[PATH_MAX];
    snprintf(dec_path, PATH_MAX, "%s/id_rsa.dec", g_test_dir);
    rc = onvault_file_decrypt(&vault_key, enc_path, dec_path);
    if (rc != ONVAULT_OK) return 0;

    /* 8. Verify roundtrip */
    FILE *fd = fopen(dec_path, "r");
    char decbuf[256];
    size_t dn = fread(decbuf, 1, sizeof(decbuf), fd);
    fclose(fd);

    int ok = (dn == 32 && memcmp(decbuf, "PRIVATE KEY CONTENT - TOP SECRET", 32) == 0);

    onvault_key_wipe(&master_key, sizeof(master_key));
    onvault_key_wipe(&vault_key, sizeof(vault_key));
    onvault_key_wipe(&config_key, sizeof(config_key));

    return ok;
}

int main(void)
{
    printf("onvault end-to-end test suite\n");
    printf("==============================\n\n");

    onvault_crypto_init();
    setup_test_dir();

    printf("File encryption:\n");
    TEST(file_encrypt_decrypt);
    TEST(wrong_key_fails);

    printf("\nPer-file nonces:\n");
    TEST(nonce_uniqueness);
    TEST(nonce_xattr);

    printf("\nPolicy engine:\n");
    TEST(policy_allow);
    TEST(policy_su_detection);

    printf("\nEncrypted config:\n");
    TEST(config_encrypt_decrypt);

    printf("\nEncrypted logging:\n");
    TEST(encrypted_log);

    printf("\nFull pipeline:\n");
    TEST(full_pipeline);

    printf("\n==============================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    /* Cleanup */
    cleanup_path(g_test_dir);

    return (tests_passed == tests_run) ? 0 : 1;
}

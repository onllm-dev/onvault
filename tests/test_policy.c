/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * test_policy.c — Unit tests for per-process access policy engine
 */

#include "types.h"
#include "crypto.h"
#include "memwipe.h"
#include "../src/auth/auth.h"
#include "../src/esf/policy.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
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

static char g_test_home[PATH_MAX];

static void setup_test_home(void)
{
    snprintf(g_test_home, sizeof(g_test_home), "/tmp/onvault_policy_test_%d", getpid());
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

/* Helper: build a minimal vault policy for testing */
static void make_test_vault_policy(onvault_vault_policy_t *p,
                                    const char *vault_id,
                                    const char *mount_path)
{
    memset(p, 0, sizeof(*p));
    strlcpy(p->vault_id, vault_id, sizeof(p->vault_id));
    strlcpy(p->mount_path, mount_path, sizeof(p->mount_path));
    p->verify_mode = VERIFY_HASH_ONLY;
    p->allow_escalated = 0;
    p->rule_count = 0;
}

/* Helper: build a minimal process identity for evaluation */
static void make_test_process(onvault_process_t *proc, const char *path)
{
    memset(proc, 0, sizeof(*proc));
    proc->pid = getpid();
    proc->ruid = getuid();
    proc->euid = getuid();
    strlcpy(proc->path, path, sizeof(proc->path));
    proc->is_signed = 0;
}

/* Helper: derive a throwaway config key for policy save/load tests */
static int make_test_config_key(onvault_key_t *config_key)
{
    /* Use a fixed test master key to derive config key */
    onvault_key_t master_key;
    onvault_mlock(&master_key, sizeof(master_key));
    memset(master_key.data, 0xAB, ONVAULT_KEY_SIZE);

    onvault_mlock(config_key, sizeof(*config_key));
    int rc = onvault_derive_config_key(&master_key, config_key);
    onvault_key_wipe(&master_key, sizeof(master_key));
    return rc;
}

/* --- Tests --- */

static int test_policy_add_allow_rule(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_policy_clear();

    /* Add a vault policy first */
    onvault_vault_policy_t vp;
    make_test_vault_policy(&vp, "testvault", "/tmp/mnt/testvault");
    if (onvault_policy_add_vault(&vp) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }

    /* Add an allow rule for /bin/ls */
    int rc = onvault_policy_add_rule("testvault", "/bin/ls", RULE_ALLOW);

    char buf[4096];
    onvault_policy_get_rules("testvault", buf, sizeof(buf));
    int found_allow = (strstr(buf, "ALLOW") != NULL &&
                       strstr(buf, "/bin/ls") != NULL);

    onvault_policy_clear();
    cleanup_test_home();
    return rc == ONVAULT_OK && found_allow;
}

static int test_policy_add_deny_rule(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_policy_clear();

    onvault_vault_policy_t vp;
    make_test_vault_policy(&vp, "testvault2", "/tmp/mnt/testvault2");
    if (onvault_policy_add_vault(&vp) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }

    int rc = onvault_policy_add_rule("testvault2", "/bin/sh", RULE_DENY);

    char buf[4096];
    onvault_policy_get_rules("testvault2", buf, sizeof(buf));
    int found_deny = (strstr(buf, "DENY") != NULL &&
                      strstr(buf, "/bin/sh") != NULL);

    onvault_policy_clear();
    cleanup_test_home();
    return rc == ONVAULT_OK && found_deny;
}

static int test_policy_default_deny(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_policy_clear();

    /* No rules added — evaluation should deny */
    onvault_process_t proc;
    make_test_process(&proc, "/bin/ls");

    int allowed = onvault_policy_evaluate(&proc, "/tmp/mnt/novault/file.txt",
                                           "/tmp/mnt/novault");

    onvault_policy_clear();
    cleanup_test_home();
    return allowed == 0;
}

static int test_policy_clear_wipes_all(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_policy_clear();

    onvault_vault_policy_t vp;
    make_test_vault_policy(&vp, "wipevault", "/tmp/mnt/wipevault");
    onvault_policy_add_vault(&vp);
    onvault_policy_add_rule("wipevault", "/bin/ls", RULE_ALLOW);

    /* Clear all policies */
    onvault_policy_clear();

    /* show should report 0 vaults */
    char buf[4096];
    onvault_policy_show(buf, sizeof(buf));
    int empty = (strstr(buf, "No vaults configured") != NULL ||
                 strstr(buf, "0 vault(s)") != NULL);

    cleanup_test_home();
    return empty;
}

static int test_policy_persistence_roundtrip(void)
{
    cleanup_test_home();
    setup_test_home();

    /* Need data dir for policies.enc */
    char data_dir[PATH_MAX];
    onvault_get_data_dir(data_dir);

    onvault_policy_clear();

    onvault_vault_policy_t vp;
    make_test_vault_policy(&vp, "persistvault", "/tmp/mnt/persistvault");
    onvault_policy_add_vault(&vp);

    onvault_key_t config_key;
    if (make_test_config_key(&config_key) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }

    /* Load (sets config key) then add rule then save */
    onvault_policy_load(&config_key);

    make_test_vault_policy(&vp, "persistvault", "/tmp/mnt/persistvault");
    onvault_policy_add_vault(&vp);
    onvault_policy_add_rule("persistvault", "/bin/ls", RULE_ALLOW);
    onvault_policy_save();

    /* Clear and reload */
    onvault_policy_clear();
    int rc = onvault_policy_load(&config_key);

    char buf[4096];
    int found = 0;
    if (rc == ONVAULT_OK) {
        onvault_policy_get_rules("persistvault", buf, sizeof(buf));
        found = (strstr(buf, "ALLOW") != NULL &&
                 strstr(buf, "/bin/ls") != NULL);
    }

    onvault_key_wipe(&config_key, sizeof(config_key));
    onvault_policy_clear();
    cleanup_test_home();
    return rc == ONVAULT_OK && found;
}

static int test_policy_auto_create_for_vault(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_get_data_dir((char[PATH_MAX]){0}); /* ensure data dir exists */
    onvault_policy_clear();

    /* Add rule for a vault that doesn't have an explicit policy yet */
    int rc = onvault_policy_add_rule("autovault", "/bin/ls", RULE_ALLOW);

    char buf[4096];
    onvault_policy_show(buf, sizeof(buf));
    int found = (strstr(buf, "autovault") != NULL);

    onvault_policy_clear();
    cleanup_test_home();
    return rc == ONVAULT_OK && found;
}

static int test_policy_multiple_vaults(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_policy_clear();

    onvault_vault_policy_t vp1, vp2;
    make_test_vault_policy(&vp1, "vault_a", "/tmp/mnt/vault_a");
    make_test_vault_policy(&vp2, "vault_b", "/tmp/mnt/vault_b");
    onvault_policy_add_vault(&vp1);
    onvault_policy_add_vault(&vp2);

    onvault_policy_add_rule("vault_a", "/bin/ls", RULE_ALLOW);
    onvault_policy_add_rule("vault_b", "/bin/sh", RULE_DENY);

    char buf_a[4096], buf_b[4096];
    onvault_policy_get_rules("vault_a", buf_a, sizeof(buf_a));
    onvault_policy_get_rules("vault_b", buf_b, sizeof(buf_b));

    int a_ok = (strstr(buf_a, "ALLOW") != NULL && strstr(buf_a, "/bin/ls") != NULL);
    int b_ok = (strstr(buf_b, "DENY") != NULL && strstr(buf_b, "/bin/sh") != NULL);

    /* Rules should be independent — vault_a should not see vault_b's rules */
    int independent = (strstr(buf_a, "/bin/sh") == NULL &&
                       strstr(buf_b, "/bin/ls") == NULL);

    onvault_policy_clear();
    cleanup_test_home();
    return a_ok && b_ok && independent;
}

static int test_policy_encrypted_storage(void)
{
    cleanup_test_home();
    setup_test_home();

    char data_dir[PATH_MAX];
    onvault_get_data_dir(data_dir);
    onvault_policy_clear();

    onvault_key_t config_key;
    if (make_test_config_key(&config_key) != ONVAULT_OK) {
        cleanup_test_home();
        return 0;
    }

    /* Load to set config key, add a vault and rule, then save */
    onvault_policy_load(&config_key);

    onvault_vault_policy_t vp;
    make_test_vault_policy(&vp, "encvault", "/tmp/mnt/encvault");
    onvault_policy_add_vault(&vp);
    onvault_policy_add_rule("encvault", "/bin/ls", RULE_ALLOW);
    onvault_policy_save();

    /* Read raw bytes from policies.enc and verify vault_id is not plaintext */
    char policy_path[PATH_MAX];
    snprintf(policy_path, sizeof(policy_path), "%s/policies.enc", data_dir);

    FILE *f = fopen(policy_path, "rb");
    if (!f) {
        onvault_key_wipe(&config_key, sizeof(config_key));
        onvault_policy_clear();
        cleanup_test_home();
        return 0;
    }

    uint8_t raw[4096];
    size_t n = fread(raw, 1, sizeof(raw), f);
    fclose(f);

    /* "encvault" should NOT appear in plaintext in the file */
    int not_plaintext = 1;
    for (size_t i = 0; i + 8 <= n; i++) {
        if (memcmp(raw + i, "encvault", 8) == 0) {
            not_plaintext = 0;
            break;
        }
    }

    onvault_key_wipe(&config_key, sizeof(config_key));
    onvault_policy_clear();
    cleanup_test_home();
    return not_plaintext;
}

int main(void)
{
    printf("onvault policy test suite\n");
    printf("=========================\n\n");

    printf("Policy rules:\n");
    TEST(policy_add_allow_rule);
    TEST(policy_add_deny_rule);

    printf("\nDefault deny:\n");
    TEST(policy_default_deny);

    printf("\nPolicy lifecycle:\n");
    TEST(policy_clear_wipes_all);
    TEST(policy_persistence_roundtrip);
    TEST(policy_auto_create_for_vault);
    TEST(policy_multiple_vaults);

    printf("\nEncrypted storage:\n");
    TEST(policy_encrypted_storage);

    printf("\n=========================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}

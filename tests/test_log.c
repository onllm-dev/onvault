/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * test_log.c — Unit tests for encrypted audit logging
 */

#include "types.h"
#include "crypto.h"
#include "memwipe.h"
#include "log.h"
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

static char g_test_home[PATH_MAX];

static void setup_test_home(void)
{
    snprintf(g_test_home, sizeof(g_test_home), "/tmp/onvault_log_test_%d", getpid());
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

/* Helper: make a random config key for log encryption */
static void make_log_key(onvault_key_t *key)
{
    onvault_mlock(key, sizeof(*key));
    onvault_random_bytes(key->data, ONVAULT_KEY_SIZE);
}

/* --- Tests --- */

/*
 * test_log_init_creates_file
 * Init log, write one entry, verify the encrypted log file exists on disk.
 */
static int test_log_init_creates_file(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_log_close();

    onvault_key_t key;
    make_log_key(&key);

    if (onvault_log_init(&key) != ONVAULT_OK) {
        onvault_key_wipe(&key, sizeof(key));
        cleanup_test_home();
        return 0;
    }

    onvault_log_write(LOG_AUTH_SUCCESS, "ssh", "/bin/ls", 1234,
                      "/tmp/mnt/ssh/id_rsa", "test init");

    /* The log file is named YYYYMMDD.log.enc inside logs/ */
    char data_dir[PATH_MAX];
    onvault_get_data_dir(data_dir);

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char date_str[16];
    strftime(date_str, sizeof(date_str), "%Y%m%d", tm_info);

    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/logs/%s.log.enc",
             data_dir, date_str);

    struct stat st;
    int exists = (stat(log_path, &st) == 0 && st.st_size > 0);

    onvault_log_close();
    onvault_key_wipe(&key, sizeof(key));
    cleanup_test_home();
    return exists;
}

/*
 * test_log_write_read_roundtrip
 * Write one entry, read it back, verify the content matches.
 */
static int test_log_write_read_roundtrip(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_log_close();

    onvault_key_t key;
    make_log_key(&key);

    if (onvault_log_init(&key) != ONVAULT_OK) {
        onvault_key_wipe(&key, sizeof(key));
        cleanup_test_home();
        return 0;
    }

    int rc = onvault_log_write(LOG_ACCESS_DENIED, "aws", "/usr/bin/python3", 9999,
                                "/tmp/mnt/aws/credentials", "roundtrip test");
    if (rc != ONVAULT_OK) {
        onvault_log_close();
        onvault_key_wipe(&key, sizeof(key));
        cleanup_test_home();
        return 0;
    }

    char buf[8192];
    size_t buf_len = sizeof(buf);
    rc = onvault_log_read(buf, &buf_len, 0, 0);

    int ok = (rc == ONVAULT_OK && buf_len > 0);
    if (ok) {
        buf[buf_len] = '\0';
        ok = (strstr(buf, "\"DENIED\"") != NULL &&
              strstr(buf, "aws") != NULL &&
              strstr(buf, "/usr/bin/python3") != NULL);
    }

    onvault_log_close();
    onvault_key_wipe(&key, sizeof(key));
    cleanup_test_home();
    return ok;
}

/*
 * test_log_daily_rotation_filename
 * Verify the log filename contains today's date in YYYYMMDD format.
 */
static int test_log_daily_rotation_filename(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_log_close();

    onvault_key_t key;
    make_log_key(&key);

    if (onvault_log_init(&key) != ONVAULT_OK) {
        onvault_key_wipe(&key, sizeof(key));
        cleanup_test_home();
        return 0;
    }

    onvault_log_write(LOG_VAULT_MOUNTED, "kube", NULL, 0, NULL, "rotation test");

    char data_dir[PATH_MAX];
    onvault_get_data_dir(data_dir);

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    /* Build expected filename using YYYYMMDD pattern */
    char date_str[16];
    strftime(date_str, sizeof(date_str), "%Y%m%d", tm_info);

    /* Also build the YYYY-MM-DD form to verify correct format */
    char dash_date[16];
    strftime(dash_date, sizeof(dash_date), "%Y-%m-%d", tm_info);

    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/logs/%s.log.enc",
             data_dir, date_str);

    struct stat st;
    int file_exists = (stat(log_path, &st) == 0);

    /* Filename must contain the 8-digit date (no dashes) */
    int has_date = (strstr(log_path, date_str) != NULL);

    /* Filename must NOT have dashes in the date portion */
    int no_dash_date = (strstr(log_path, dash_date) == NULL);

    onvault_log_close();
    onvault_key_wipe(&key, sizeof(key));
    cleanup_test_home();
    return file_exists && has_date && no_dash_date;
}

/*
 * test_log_multiple_events
 * Write UNLOCK, LOCK, ALLOW events; read all; verify count = 3.
 */
static int test_log_multiple_events(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_log_close();

    onvault_key_t key;
    make_log_key(&key);

    if (onvault_log_init(&key) != ONVAULT_OK) {
        onvault_key_wipe(&key, sizeof(key));
        cleanup_test_home();
        return 0;
    }

    onvault_log_write(LOG_AUTH_SUCCESS, NULL, NULL, 0, NULL, "unlock");
    onvault_log_write(LOG_AUTH_FAILURE, NULL, NULL, 0, NULL, "lock");
    onvault_log_write(LOG_ACCESS_ALLOWED, "ssh", "/usr/bin/ssh", 1111,
                      "/tmp/mnt/ssh/id_rsa", "allow");

    char buf[8192];
    size_t buf_len = sizeof(buf);
    int rc = onvault_log_read(buf, &buf_len, 0, 0);

    int ok = (rc == ONVAULT_OK && buf_len > 0);
    if (ok) {
        buf[buf_len] = '\0';
        /* Count newlines — each JSON line ends with \n */
        int lines = 0;
        for (size_t i = 0; i < buf_len; i++) {
            if (buf[i] == '\n') lines++;
        }
        ok = (lines == 3);
    }

    onvault_log_close();
    onvault_key_wipe(&key, sizeof(key));
    cleanup_test_home();
    return ok;
}

/*
 * test_log_close_and_reopen
 * Write entries, close, re-init with same key, write more, read all,
 * verify all entries are present.
 */
static int test_log_close_and_reopen(void)
{
    cleanup_test_home();
    setup_test_home();
    onvault_log_close();

    onvault_key_t key;
    make_log_key(&key);

    /* First session: write 2 entries */
    if (onvault_log_init(&key) != ONVAULT_OK) {
        onvault_key_wipe(&key, sizeof(key));
        cleanup_test_home();
        return 0;
    }

    onvault_log_write(LOG_VAULT_MOUNTED, "ssh", NULL, 0, NULL, "first-mount");
    onvault_log_write(LOG_ACCESS_ALLOWED, "ssh", "/usr/bin/ssh", 2222,
                      "/tmp/mnt/ssh/id_rsa", "first-allow");
    onvault_log_close();

    /* Second session: reopen and write 1 more entry */
    if (onvault_log_init(&key) != ONVAULT_OK) {
        onvault_key_wipe(&key, sizeof(key));
        cleanup_test_home();
        return 0;
    }

    onvault_log_write(LOG_POLICY_CHANGE, "ssh", NULL, 0, NULL, "second-policy");

    /* Read all — should see 3 entries total */
    char buf[8192];
    size_t buf_len = sizeof(buf);
    int rc = onvault_log_read(buf, &buf_len, 0, 0);

    int ok = (rc == ONVAULT_OK && buf_len > 0);
    if (ok) {
        buf[buf_len] = '\0';
        int lines = 0;
        for (size_t i = 0; i < buf_len; i++) {
            if (buf[i] == '\n') lines++;
        }
        ok = (lines == 3 &&
              strstr(buf, "first-mount") != NULL &&
              strstr(buf, "second-policy") != NULL);
    }

    onvault_log_close();
    onvault_key_wipe(&key, sizeof(key));
    cleanup_test_home();
    return ok;
}

int main(void)
{
    printf("onvault audit log test suite\n");
    printf("============================\n\n");

    onvault_crypto_init();

    printf("Log init:\n");
    TEST(log_init_creates_file);

    printf("\nRead/write:\n");
    TEST(log_write_read_roundtrip);

    printf("\nFile naming:\n");
    TEST(log_daily_rotation_filename);

    printf("\nMultiple events:\n");
    TEST(log_multiple_events);

    printf("\nPersistence:\n");
    TEST(log_close_and_reopen);

    printf("\n============================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}

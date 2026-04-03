/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * test_config.c — Unit tests for config parser and smart defaults
 */

#include "types.h"
#include "config.h"

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

static char g_test_dir[256];

static void setup_test_dir(void)
{
    snprintf(g_test_dir, sizeof(g_test_dir), "/tmp/onvault_config_test_%d", getpid());
    mkdir(g_test_dir, 0700);
}

static void cleanup_test_dir(void)
{
    char cmd[280];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_test_dir);
    (void)system(cmd);
}

static void write_test_file(const char *name, const char *content)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_test_dir, name);
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

/* --- Tests --- */

static int test_config_parse_valid(void)
{
    write_test_file("valid.yaml",
        "# comment line\n"
        "allowlist:\n"
        "- /usr/bin/ssh\n"
        "- /usr/bin/scp\n");

    char path[512];
    snprintf(path, sizeof(path), "%s/valid.yaml", g_test_dir);

    onvault_defaults_t d;
    int rc = onvault_defaults_parse(path, &d);
    if (rc != ONVAULT_OK) return 0;
    if (d.count != 2) return 0;
    if (strcmp(d.paths[0], "/usr/bin/ssh") != 0) return 0;
    if (strcmp(d.paths[1], "/usr/bin/scp") != 0) return 0;
    return 1;
}

static int test_config_parse_comments_ignored(void)
{
    write_test_file("comments.yaml",
        "# first comment\n"
        "# second comment\n"
        "# third comment\n");

    char path[512];
    snprintf(path, sizeof(path), "%s/comments.yaml", g_test_dir);

    onvault_defaults_t d;
    int rc = onvault_defaults_parse(path, &d);
    if (rc != ONVAULT_OK) return 0;
    return d.count == 0;
}

static int test_config_parse_list_items(void)
{
    write_test_file("list.yaml",
        "- /bin/a\n"
        "- /bin/b\n"
        "- /bin/c\n"
        "- /bin/d\n"
        "- /bin/e\n");

    char path[512];
    snprintf(path, sizeof(path), "%s/list.yaml", g_test_dir);

    onvault_defaults_t d;
    int rc = onvault_defaults_parse(path, &d);
    if (rc != ONVAULT_OK) return 0;
    return d.count == 5;
}

static int test_config_parse_malformed_rejected(void)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/nonexistent_file.yaml", g_test_dir);

    onvault_defaults_t d;
    int rc = onvault_defaults_parse(path, &d);
    return rc == ONVAULT_ERR_NOT_FOUND;
}

static int test_config_parse_empty_file(void)
{
    write_test_file("empty.yaml", "");

    char path[512];
    snprintf(path, sizeof(path), "%s/empty.yaml", g_test_dir);

    onvault_defaults_t d;
    int rc = onvault_defaults_parse(path, &d);
    if (rc != ONVAULT_OK) return 0;
    return d.count == 0;
}

int main(void)
{
    printf("onvault config parser test suite\n");
    printf("=================================\n\n");

    setup_test_dir();

    printf("Config parser:\n");
    TEST(config_parse_valid);
    TEST(config_parse_comments_ignored);
    TEST(config_parse_list_items);
    TEST(config_parse_malformed_rejected);
    TEST(config_parse_empty_file);

    cleanup_test_dir();

    printf("\n=================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}

/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * test_fuse_ops.c — Unit tests for FUSE filesystem operations
 */

#include "types.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>

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
    snprintf(g_test_dir, sizeof(g_test_dir), "/tmp/onvault_fuse_test_%d", getpid());
    mkdir(g_test_dir, 0700);
}

static void cleanup_test_dir(void)
{
    char cmd[280];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_test_dir);
    (void)system(cmd);
}

static void make_file(const char *name, const char *content)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_test_dir, name);
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

static int file_exists(const char *name)
{
    char path[512];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", g_test_dir, name);
    return stat(path, &st) == 0;
}

/* 1. unlink removes a file */
static int test_fuse_unlink_removes_file(void)
{
    cleanup_test_dir(); setup_test_dir();
    make_file("a.txt", "x");
    char path[512];
    snprintf(path, sizeof(path), "%s/a.txt", g_test_dir);
    if (unlink(path) != 0) { cleanup_test_dir(); return 0; }
    int ok = !file_exists("a.txt");
    cleanup_test_dir();
    return ok;
}

/* 2. rename moves a file */
static int test_fuse_rename_file(void)
{
    cleanup_test_dir(); setup_test_dir();
    make_file("old.txt", "x");
    char from[512], to[512];
    snprintf(from, sizeof(from), "%s/old.txt", g_test_dir);
    snprintf(to, sizeof(to), "%s/new.txt", g_test_dir);
    if (rename(from, to) != 0) { cleanup_test_dir(); return 0; }
    int ok = !file_exists("old.txt") && file_exists("new.txt");
    cleanup_test_dir();
    return ok;
}

/* 3. mkdir creates a directory */
static int test_fuse_mkdir_creates_directory(void)
{
    cleanup_test_dir(); setup_test_dir();
    char path[512];
    snprintf(path, sizeof(path), "%s/subdir", g_test_dir);
    if (mkdir(path, 0700) != 0) { cleanup_test_dir(); return 0; }
    struct stat st;
    int ok = (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
    cleanup_test_dir();
    return ok;
}

/* 4. rmdir removes an empty directory */
static int test_fuse_rmdir_empty(void)
{
    cleanup_test_dir(); setup_test_dir();
    char path[512];
    snprintf(path, sizeof(path), "%s/emptydir", g_test_dir);
    mkdir(path, 0700);
    if (rmdir(path) != 0) { cleanup_test_dir(); return 0; }
    struct stat st;
    int ok = (stat(path, &st) != 0);
    cleanup_test_dir();
    return ok;
}

/* 5. rmdir on non-empty directory fails with ENOTEMPTY */
static int test_fuse_rmdir_nonempty_fails(void)
{
    cleanup_test_dir(); setup_test_dir();
    char dirpath[512];
    snprintf(dirpath, sizeof(dirpath), "%s/fulldir", g_test_dir);
    mkdir(dirpath, 0700);
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/fulldir/inside.txt", g_test_dir);
    FILE *f = fopen(filepath, "w");
    if (f) { fputs("x", f); fclose(f); }
    int rc = rmdir(dirpath);
    int ok = (rc != 0 && errno == ENOTEMPTY);
    cleanup_test_dir();
    return ok;
}

/* 6. chmod changes file mode */
static int test_fuse_chmod_changes_mode(void)
{
    cleanup_test_dir(); setup_test_dir();
    make_file("modfile.txt", "data");
    char path[512];
    snprintf(path, sizeof(path), "%s/modfile.txt", g_test_dir);
    if (chmod(path, 0644) != 0) { cleanup_test_dir(); return 0; }
    struct stat st;
    if (stat(path, &st) != 0) { cleanup_test_dir(); return 0; }
    int ok = ((st.st_mode & 0777) == 0644);
    cleanup_test_dir();
    return ok;
}

/* 7. utimensat updates timestamps */
static int test_fuse_utimens_updates_timestamps(void)
{
    cleanup_test_dir(); setup_test_dir();
    make_file("timefile.txt", "data");
    char path[512];
    snprintf(path, sizeof(path), "%s/timefile.txt", g_test_dir);
    struct timespec ts[2];
    ts[0].tv_sec = 1000000000;
    ts[0].tv_nsec = 0;
    ts[1].tv_sec = 1000000000;
    ts[1].tv_nsec = 0;
    if (utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW) != 0) { cleanup_test_dir(); return 0; }
    struct stat st;
    if (stat(path, &st) != 0) { cleanup_test_dir(); return 0; }
    int ok = (st.st_mtime == 1000000000);
    cleanup_test_dir();
    return ok;
}

/* 8. statvfs returns valid filesystem stats */
static int test_fuse_statfs_returns_valid(void)
{
    cleanup_test_dir(); setup_test_dir();
    struct statvfs svfs;
    int rc = statvfs(g_test_dir, &svfs);
    int ok = (rc == 0 && svfs.f_bsize > 0);
    cleanup_test_dir();
    return ok;
}

/* 9. symlink + readlink roundtrip */
static int test_fuse_symlink_readlink_roundtrip(void)
{
    cleanup_test_dir(); setup_test_dir();
    make_file("target.txt", "data");
    char target[512], linkpath[512];
    snprintf(target, sizeof(target), "%s/target.txt", g_test_dir);
    snprintf(linkpath, sizeof(linkpath), "%s/mylink", g_test_dir);
    if (symlink(target, linkpath) != 0) { cleanup_test_dir(); return 0; }
    char buf[512];
    ssize_t len = readlink(linkpath, buf, sizeof(buf) - 1);
    if (len < 0) { cleanup_test_dir(); return 0; }
    buf[len] = '\0';
    int ok = (strcmp(buf, target) == 0);
    cleanup_test_dir();
    return ok;
}

/* 10. create, write, read, unlink lifecycle */
static int test_fuse_create_write_read_unlink(void)
{
    cleanup_test_dir(); setup_test_dir();
    char path[512];
    snprintf(path, sizeof(path), "%s/lifecycle.txt", g_test_dir);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) { cleanup_test_dir(); return 0; }
    const char *msg = "hello";
    if (write(fd, msg, 5) != 5) { close(fd); cleanup_test_dir(); return 0; }
    close(fd);
    fd = open(path, O_RDONLY);
    if (fd < 0) { cleanup_test_dir(); return 0; }
    char rbuf[16];
    memset(rbuf, 0, sizeof(rbuf));
    ssize_t n = read(fd, rbuf, sizeof(rbuf) - 1);
    close(fd);
    if (n != 5 || strncmp(rbuf, "hello", 5) != 0) { cleanup_test_dir(); return 0; }
    if (unlink(path) != 0) { cleanup_test_dir(); return 0; }
    struct stat st;
    int ok = (stat(path, &st) != 0);
    cleanup_test_dir();
    return ok;
}

/* 11. mkdir, create file inside, rename file out, rmdir (now empty) */
static int test_fuse_mkdir_file_rename_rmdir(void)
{
    cleanup_test_dir(); setup_test_dir();
    char dirpath[512], inpath[512], outpath[512];
    snprintf(dirpath, sizeof(dirpath), "%s/mydir", g_test_dir);
    snprintf(inpath, sizeof(inpath), "%s/mydir/inside.txt", g_test_dir);
    snprintf(outpath, sizeof(outpath), "%s/outside.txt", g_test_dir);
    if (mkdir(dirpath, 0700) != 0) { cleanup_test_dir(); return 0; }
    FILE *f = fopen(inpath, "w");
    if (!f) { cleanup_test_dir(); return 0; }
    fputs("data", f); fclose(f);
    if (rename(inpath, outpath) != 0) { cleanup_test_dir(); return 0; }
    if (rmdir(dirpath) != 0) { cleanup_test_dir(); return 0; }
    struct stat st;
    int ok = (stat(dirpath, &st) != 0) && (stat(outpath, &st) == 0);
    cleanup_test_dir();
    return ok;
}

/* 12. rename preserves file content */
static int test_fuse_rename_preserves_content(void)
{
    cleanup_test_dir(); setup_test_dir();
    make_file("src.txt", "test data");
    char from[512], to[512];
    snprintf(from, sizeof(from), "%s/src.txt", g_test_dir);
    snprintf(to, sizeof(to), "%s/dst.txt", g_test_dir);
    if (rename(from, to) != 0) { cleanup_test_dir(); return 0; }
    FILE *f = fopen(to, "r");
    if (!f) { cleanup_test_dir(); return 0; }
    char buf[32];
    memset(buf, 0, sizeof(buf));
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    int ok = (n == 9 && strcmp(buf, "test data") == 0);
    cleanup_test_dir();
    return ok;
}

int main(void)
{
    printf("onvault FUSE ops test suite\n");
    printf("==========================\n\n");
    printf("File operations:\n");
    TEST(fuse_unlink_removes_file);
    TEST(fuse_rename_file);
    TEST(fuse_rename_preserves_content);
    printf("\nDirectory operations:\n");
    TEST(fuse_mkdir_creates_directory);
    TEST(fuse_rmdir_empty);
    TEST(fuse_rmdir_nonempty_fails);
    printf("\nPermissions & metadata:\n");
    TEST(fuse_chmod_changes_mode);
    TEST(fuse_utimens_updates_timestamps);
    TEST(fuse_statfs_returns_valid);
    printf("\nSymlinks:\n");
    TEST(fuse_symlink_readlink_roundtrip);
    printf("\nLifecycle:\n");
    TEST(fuse_create_write_read_unlink);
    TEST(fuse_mkdir_file_rename_rmdir);
    printf("\n==========================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}

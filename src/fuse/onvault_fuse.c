/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * onvault_fuse.c — macFUSE encrypted filesystem layer
 *
 * This implements a FUSE filesystem that presents decrypted views
 * of encrypted vault files. On disk, all files are ciphertext.
 * Through the FUSE mount, authorized processes see plaintext.
 *
 * Requires macFUSE: brew install --cask macfuse
 * Compile with: -I/usr/local/include/osxfuse -losxfuse
 *
 * When macFUSE is not installed, this module provides stub
 * implementations that return errors.
 */

#include "onvault_fuse.h"
#include "encrypt.h"
#include "../common/crypto.h"
#include "../common/memwipe.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <dirent.h>
#include <stdlib.h>

/* Policy check callback (Layer 2 integration) */
static onvault_policy_check_fn g_policy_check = NULL;

void onvault_fuse_set_policy_check(onvault_policy_check_fn fn)
{
    g_policy_check = fn;
}

#ifdef HAVE_MACFUSE

/* ============================================================
 * macFUSE implementation
 * ============================================================ */

#define FUSE_USE_VERSION 26
#include <fuse.h>

/* Per-mount context stored in fuse_context private_data */
typedef struct {
    char           vault_dir[PATH_MAX];
    onvault_key_t  vault_key;
} onvault_fuse_ctx_t;

static onvault_fuse_ctx_t *get_ctx(void)
{
    return (onvault_fuse_ctx_t *)fuse_get_context()->private_data;
}

/* Map a FUSE path to the real ciphertext path */
static void real_path(const char *path, char *out)
{
    onvault_fuse_ctx_t *ctx = get_ctx();
    if (strcmp(path, "/") == 0)
        snprintf(out, PATH_MAX, "%s", ctx->vault_dir);
    else
        snprintf(out, PATH_MAX, "%s%s", ctx->vault_dir, path);
}

/* --- FUSE operations --- */

static int ov_getattr(const char *path, struct stat *stbuf)
{
    char rpath[PATH_MAX];
    real_path(path, rpath);

    if (lstat(rpath, stbuf) != 0)
        return -errno;

    /* For regular files, report the original (plaintext) size
     * by reading the stored size from the ciphertext header */
    if (S_ISREG(stbuf->st_mode)) {
        FILE *f = fopen(rpath, "rb");
        if (f) {
            uint64_t orig_size;
            if (fread(&orig_size, sizeof(orig_size), 1, f) == 1) {
                stbuf->st_size = (off_t)orig_size;
            }
            fclose(f);
        }
    }

    return 0;
}

static int ov_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi)
{
    (void)offset;
    (void)fi;

    char rpath[PATH_MAX];
    real_path(path, rpath);

    DIR *dir = opendir(rpath);
    if (!dir)
        return -errno;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' &&
            (strcmp(entry->d_name, ".") == 0 ||
             strcmp(entry->d_name, "..") == 0 ||
             strcmp(entry->d_name, ".onvault_source") == 0))
            continue;

        filler(buf, entry->d_name, NULL, 0);
    }

    closedir(dir);
    return 0;
}

static int ov_open(const char *path, struct fuse_file_info *fi)
{
    /* Layer 2 policy check */
    if (g_policy_check) {
        pid_t caller = fuse_get_context()->pid;
        if (g_policy_check(caller, path) != 0)
            return -EACCES;
    }

    char rpath[PATH_MAX];
    real_path(path, rpath);

    int fd = open(rpath, fi->flags);
    if (fd < 0)
        return -errno;

    fi->fh = (uint64_t)fd;
    return 0;
}

static int ov_read(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi)
{
    (void)fi;

    char rpath[PATH_MAX];
    real_path(path, rpath);

    onvault_fuse_ctx_t *ctx = get_ctx();

    /* Load nonce */
    onvault_nonce_t nonce;
    if (onvault_file_nonce_load(rpath, &nonce) != ONVAULT_OK)
        return -EIO;

    /* Open ciphertext file */
    FILE *f = fopen(rpath, "rb");
    if (!f)
        return -errno;

    /* Read original file size */
    uint64_t file_size;
    if (fread(&file_size, sizeof(file_size), 1, f) != 1) {
        fclose(f);
        return -EIO;
    }

    if ((uint64_t)offset >= file_size) {
        fclose(f);
        return 0;
    }

    /* Clamp read size */
    if ((uint64_t)offset + size > file_size)
        size = (size_t)(file_size - (uint64_t)offset);

    /* Determine which blocks to read */
    uint64_t start_block = (uint64_t)offset / ONVAULT_BLOCK_SIZE;
    uint64_t block_offset_in = (uint64_t)offset % ONVAULT_BLOCK_SIZE;

    size_t total_read = 0;

    while (total_read < size) {
        /* Seek to the right ciphertext block */
        uint64_t cipher_offset = sizeof(file_size) + start_block * ONVAULT_BLOCK_SIZE;
        fseek(f, (long)cipher_offset, SEEK_SET);

        uint8_t cipherbuf[ONVAULT_BLOCK_SIZE];
        uint8_t plainbuf[ONVAULT_BLOCK_SIZE];

        size_t block_read = fread(cipherbuf, 1, ONVAULT_BLOCK_SIZE, f);
        if (block_read == 0)
            break;
        if (block_read < 16)
            break; /* XTS minimum */

        /* Decrypt block */
        int rc = onvault_file_decrypt_block(&ctx->vault_key, &nonce,
                                             cipherbuf, block_read,
                                             plainbuf, start_block);
        if (rc != ONVAULT_OK) {
            onvault_memzero(plainbuf, sizeof(plainbuf));
            break;
        }

        /* Copy relevant portion to output buffer */
        size_t copy_start = (total_read == 0) ? (size_t)block_offset_in : 0;
        size_t copy_len = block_read - copy_start;
        if (copy_len > size - total_read)
            copy_len = size - total_read;

        memcpy(buf + total_read, plainbuf + copy_start, copy_len);
        onvault_memzero(plainbuf, sizeof(plainbuf));

        total_read += copy_len;
        start_block++;
    }

    onvault_memzero(&nonce, sizeof(nonce));
    fclose(f);
    return (int)total_read;
}

static int ov_write(const char *path, const char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    (void)fi;
    (void)path;
    (void)buf;
    (void)size;
    (void)offset;

    /* TODO: Implement write support for vaults */
    /* For now, credential files are mostly read-only */
    return -EROFS;
}

static int ov_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    if (fi->fh)
        close((int)fi->fh);
    return 0;
}

static struct fuse_operations onvault_fuse_ops = {
    .getattr  = ov_getattr,
    .readdir  = ov_readdir,
    .open     = ov_open,
    .read     = ov_read,
    .write    = ov_write,
    .release  = ov_release,
};

int onvault_fuse_mount(const char *vault_id,
                        const onvault_key_t *vault_key,
                        const char *vault_dir,
                        const char *mount_dir)
{
    (void)vault_id;

    if (!vault_key || !vault_dir || !mount_dir)
        return ONVAULT_ERR_INVALID;

    /* Create context */
    onvault_fuse_ctx_t *ctx = calloc(1, sizeof(onvault_fuse_ctx_t));
    if (!ctx)
        return ONVAULT_ERR_MEMORY;

    snprintf(ctx->vault_dir, PATH_MAX, "%s", vault_dir);
    memcpy(&ctx->vault_key, vault_key, sizeof(onvault_key_t));
    onvault_mlock(&ctx->vault_key, sizeof(ctx->vault_key));

    /* FUSE args */
    char *argv[] = {
        "onvault",
        (char *)mount_dir,
        "-o", "local,allow_other,auto_unmount,fsname=onvault",
        "-f",  /* foreground */
        NULL
    };
    int argc = 5;

    int rc = fuse_main(argc, argv, &onvault_fuse_ops, ctx);

    /* Clean up after unmount */
    onvault_key_wipe(&ctx->vault_key, sizeof(ctx->vault_key));
    free(ctx);

    return (rc == 0) ? ONVAULT_OK : ONVAULT_ERR_IO;
}

#else /* !HAVE_MACFUSE */

/* ============================================================
 * Stub implementation when macFUSE is not installed.
 * Vault add/remove still work (encrypt/decrypt files on disk).
 * FUSE mount/unmount return errors.
 * ============================================================ */

int onvault_fuse_mount(const char *vault_id,
                        const onvault_key_t *vault_key,
                        const char *vault_dir,
                        const char *mount_dir)
{
    (void)vault_id;
    (void)vault_key;
    (void)vault_dir;
    (void)mount_dir;
    fprintf(stderr, "onvault: macFUSE not available. Install with: brew install --cask macfuse\n");
    return ONVAULT_ERR_IO;
}

#endif /* HAVE_MACFUSE */

int onvault_fuse_unmount(const char *mount_dir)
{
    if (!mount_dir)
        return ONVAULT_ERR_INVALID;

    /* Use unmount(2) on macOS */
    if (unmount(mount_dir, MNT_FORCE) == 0)
        return ONVAULT_OK;

    /* Fallback to umount command */
    char cmd[PATH_MAX + 32];
    snprintf(cmd, sizeof(cmd), "umount '%s' 2>/dev/null", mount_dir);
    int rc = system(cmd);
    return (rc == 0) ? ONVAULT_OK : ONVAULT_ERR_IO;
}

int onvault_fuse_is_mounted(const char *mount_dir)
{
    if (!mount_dir)
        return 0;

    struct statfs buf;
    if (statfs(mount_dir, &buf) != 0)
        return 0;

    /* Check if it's a FUSE mount */
    return (strstr(buf.f_fstypename, "fuse") != NULL ||
            strstr(buf.f_fstypename, "osxfuse") != NULL ||
            strstr(buf.f_fstypename, "macfuse") != NULL);
}

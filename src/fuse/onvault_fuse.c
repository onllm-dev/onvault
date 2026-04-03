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
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
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
    char           mount_dir[PATH_MAX];
    onvault_key_t  vault_key;
} onvault_fuse_ctx_t;

static onvault_fuse_ctx_t *get_ctx(void)
{
    return (onvault_fuse_ctx_t *)fuse_get_context()->private_data;
}

/* Map a FUSE path to the real ciphertext path.
 * Returns 0 on success, -1 if path escapes the vault directory. */
static int real_path(const char *path, char *out)
{
    onvault_fuse_ctx_t *ctx = get_ctx();

    if (strcmp(path, "/") == 0) {
        snprintf(out, PATH_MAX, "%s", ctx->vault_dir);
        return 0;
    }

    /* Reject paths containing ".." to prevent directory traversal */
    if (strstr(path, "..") != NULL)
        return -1;

    snprintf(out, PATH_MAX, "%s%s", ctx->vault_dir, path);

    /* Resolve symlinks and verify the result stays within vault_dir */
    char resolved[PATH_MAX];
    if (realpath(out, resolved) != NULL) {
        size_t vlen = strlen(ctx->vault_dir);
        if (strncmp(resolved, ctx->vault_dir, vlen) != 0)
            return -1; /* escaped vault boundary */
        snprintf(out, PATH_MAX, "%s", resolved);
    }
    /* If realpath fails (file doesn't exist yet), verify the parent */
    else {
        char parent[PATH_MAX];
        snprintf(parent, PATH_MAX, "%s", out);
        char *slash = strrchr(parent, '/');
        if (slash && slash != parent) {
            *slash = '\0';
            if (realpath(parent, resolved) != NULL) {
                size_t vlen = strlen(ctx->vault_dir);
                if (strncmp(resolved, ctx->vault_dir, vlen) != 0)
                    return -1;
            }
        }
    }

    return 0;
}

static size_t ciphertext_len_for_plaintext(uint64_t plain_size)
{
    uint64_t full_blocks = plain_size / ONVAULT_BLOCK_SIZE;
    uint64_t tail = plain_size % ONVAULT_BLOCK_SIZE;
    size_t cipher_len = (size_t)(full_blocks * ONVAULT_BLOCK_SIZE);

    if (tail > 0)
        cipher_len += (size_t)(tail < 16 ? 16 : tail);

    return cipher_len;
}

/* --- FUSE operations --- */

static int ov_getattr(const char *path, struct stat *stbuf)
{
    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;

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
    if (real_path(path, rpath) != 0) return -EACCES;

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
        if (g_policy_check(caller, path, get_ctx()->mount_dir) != 0)
            return -EACCES;
    }

    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;

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
    if (real_path(path, rpath) != 0) return -EACCES;

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
        if (fseeko(f, (off_t)cipher_offset, SEEK_SET) != 0)
            break;

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

    /* If decryption failed before reading any bytes, return I/O error */
    if (total_read == 0 && size > 0 && (uint64_t)offset < file_size)
        return -EIO;

    return (int)total_read;
}

static int ov_write(const char *path, const char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    (void)fi;

    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;

    onvault_fuse_ctx_t *ctx = get_ctx();

    /* Load nonce */
    onvault_nonce_t nonce;
    if (onvault_file_nonce_load(rpath, &nonce) != ONVAULT_OK)
        return -EIO;

    /* Open ciphertext file for reading current state and writing */
    FILE *f = fopen(rpath, "r+b");
    if (!f)
        return -errno;
    int fd = fileno(f);
    if (fd >= 0)
        flock(fd, LOCK_EX);

    /* Read current file size from header */
    uint64_t file_size;
    if (fread(&file_size, sizeof(file_size), 1, f) != 1) {
        if (fd >= 0)
            flock(fd, LOCK_UN);
        fclose(f);
        return -EIO;
    }

    /* Calculate new file size if write extends past end */
    uint64_t write_end = (uint64_t)offset + size;
    uint64_t new_file_size = (write_end > file_size) ? write_end : file_size;

    /* Write blocks */
    uint64_t start_block = (uint64_t)offset / ONVAULT_BLOCK_SIZE;
    size_t block_offset_in = (size_t)((uint64_t)offset % ONVAULT_BLOCK_SIZE);
    size_t total_written = 0;

    while (total_written < size) {
        uint64_t cipher_pos = sizeof(file_size) + start_block * ONVAULT_BLOCK_SIZE;
        uint8_t plainbuf[ONVAULT_BLOCK_SIZE];
        memset(plainbuf, 0, sizeof(plainbuf));

        /* Read existing block if we're doing a partial block write */
        size_t copy_start = (total_written == 0) ? block_offset_in : 0;
        if (copy_start > 0 || (size - total_written) < ONVAULT_BLOCK_SIZE) {
            /* Need to read-modify-write: decrypt existing block first */
            if (fseeko(f, (off_t)cipher_pos, SEEK_SET) == 0) {
                uint8_t cipherbuf[ONVAULT_BLOCK_SIZE];
                size_t block_read = fread(cipherbuf, 1, ONVAULT_BLOCK_SIZE, f);
                if (block_read >= 16) {
                    onvault_file_decrypt_block(&ctx->vault_key, &nonce,
                                               cipherbuf, block_read,
                                               plainbuf, start_block);
                }
            }
        }

        /* Overlay new data */
        size_t copy_len = ONVAULT_BLOCK_SIZE - copy_start;
        if (copy_len > size - total_written)
            copy_len = size - total_written;
        memcpy(plainbuf + copy_start, buf + total_written, copy_len);

        /* Determine block size to encrypt (at least 16 for XTS) */
        size_t block_end = copy_start + copy_len;
        /* Calculate how much of this block actually has data */
        uint64_t block_data_end = (start_block + 1) * ONVAULT_BLOCK_SIZE;
        if (block_data_end > new_file_size)
            block_data_end = new_file_size;
        size_t encrypt_len = (size_t)(block_data_end - start_block * ONVAULT_BLOCK_SIZE);
        if (encrypt_len < block_end)
            encrypt_len = block_end;
        if (encrypt_len < 16)
            encrypt_len = 16;
        if (encrypt_len > ONVAULT_BLOCK_SIZE)
            encrypt_len = ONVAULT_BLOCK_SIZE;

        /* Encrypt the block */
        uint8_t cipherout[ONVAULT_BLOCK_SIZE];
        int rc = onvault_file_encrypt_block(&ctx->vault_key, &nonce,
                                             plainbuf, encrypt_len,
                                             cipherout, start_block);
        onvault_memzero(plainbuf, sizeof(plainbuf));

        if (rc != ONVAULT_OK) {
            if (fd >= 0)
                flock(fd, LOCK_UN);
            fclose(f);
            onvault_memzero(&nonce, sizeof(nonce));
            return -EIO;
        }

        /* Write encrypted block to ciphertext file */
        if (fseeko(f, (off_t)cipher_pos, SEEK_SET) != 0) {
            if (fd >= 0)
                flock(fd, LOCK_UN);
            fclose(f);
            onvault_memzero(&nonce, sizeof(nonce));
            return -EIO;
        }
        if (fwrite(cipherout, 1, encrypt_len, f) != encrypt_len) {
            if (fd >= 0)
                flock(fd, LOCK_UN);
            fclose(f);
            onvault_memzero(&nonce, sizeof(nonce));
            return -EIO;
        }

        total_written += copy_len;
        start_block++;
    }

    /* Update file size header if it changed */
    if (new_file_size != file_size) {
        if (fseeko(f, 0, SEEK_SET) == 0)
            fwrite(&new_file_size, sizeof(new_file_size), 1, f);
    }

    fflush(f);
    if (fd >= 0)
        flock(fd, LOCK_UN);
    fclose(f);
    onvault_memzero(&nonce, sizeof(nonce));
    return (int)total_written;
}

static int ov_truncate(const char *path, off_t newsize)
{
    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;

    if (newsize < 0)
        return -EINVAL;

    onvault_fuse_ctx_t *ctx = get_ctx();
    onvault_nonce_t nonce;
    if (onvault_file_nonce_load(rpath, &nonce) != ONVAULT_OK)
        return -EIO;

    FILE *f = fopen(rpath, "r+b");
    if (!f)
        return -errno;
    int fd = fileno(f);
    if (fd >= 0)
        flock(fd, LOCK_EX);

    uint64_t old_size = 0;
    if (fread(&old_size, sizeof(old_size), 1, f) != 1) {
        if (fd >= 0)
            flock(fd, LOCK_UN);
        fclose(f);
        onvault_memzero(&nonce, sizeof(nonce));
        return -EIO;
    }

    if ((uint64_t)newsize > old_size) {
        uint8_t zeros[ONVAULT_BLOCK_SIZE];
        off_t offset = (off_t)old_size;

        memset(zeros, 0, sizeof(zeros));
        while (offset < newsize) {
            size_t chunk = (size_t)(newsize - offset);
            if (chunk > sizeof(zeros))
                chunk = sizeof(zeros);
            if (fd >= 0)
                flock(fd, LOCK_UN);
            fclose(f);
            if (ov_write(path, (const char *)zeros, chunk, offset, NULL) < 0) {
                onvault_memzero(&nonce, sizeof(nonce));
                return -EIO;
            }
            offset += (off_t)chunk;
            f = fopen(rpath, "r+b");
            if (!f) {
                onvault_memzero(&nonce, sizeof(nonce));
                return -errno;
            }
            fd = fileno(f);
            if (fd >= 0)
                flock(fd, LOCK_EX);
        }
    } else {
        uint64_t new_file_size = (uint64_t)newsize;
        size_t tail = (size_t)(new_file_size % ONVAULT_BLOCK_SIZE);

        if (tail > 0) {
            uint64_t block_index = new_file_size / ONVAULT_BLOCK_SIZE;
            uint64_t old_block_plain = old_size - (block_index * ONVAULT_BLOCK_SIZE);
            size_t old_block_len = old_block_plain > ONVAULT_BLOCK_SIZE
                ? ONVAULT_BLOCK_SIZE
                : (size_t)old_block_plain;
            size_t old_cipher_len = old_block_len == 0
                ? 0
                : (old_block_len < 16 ? 16 : old_block_len);
            size_t new_cipher_len = tail < 16 ? 16 : tail;
            uint8_t cipherbuf[ONVAULT_BLOCK_SIZE];
            uint8_t plainbuf[ONVAULT_BLOCK_SIZE];

            memset(cipherbuf, 0, sizeof(cipherbuf));
            memset(plainbuf, 0, sizeof(plainbuf));

            if (old_cipher_len > 0) {
                off_t block_pos = (off_t)(sizeof(uint64_t) + block_index * ONVAULT_BLOCK_SIZE);
                if (fseeko(f, block_pos, SEEK_SET) != 0 ||
                    fread(cipherbuf, 1, old_cipher_len, f) != old_cipher_len ||
                    onvault_file_decrypt_block(&ctx->vault_key, &nonce,
                                               cipherbuf, old_cipher_len,
                                               plainbuf, block_index) != ONVAULT_OK) {
                    if (fd >= 0)
                        flock(fd, LOCK_UN);
                    fclose(f);
                    onvault_memzero(cipherbuf, sizeof(cipherbuf));
                    onvault_memzero(plainbuf, sizeof(plainbuf));
                    onvault_memzero(&nonce, sizeof(nonce));
                    return -EIO;
                }
            }

            memset(plainbuf + tail, 0, sizeof(plainbuf) - tail);
            if (onvault_file_encrypt_block(&ctx->vault_key, &nonce,
                                           plainbuf, new_cipher_len,
                                           cipherbuf, block_index) != ONVAULT_OK) {
                if (fd >= 0)
                    flock(fd, LOCK_UN);
                fclose(f);
                onvault_memzero(cipherbuf, sizeof(cipherbuf));
                onvault_memzero(plainbuf, sizeof(plainbuf));
                onvault_memzero(&nonce, sizeof(nonce));
                return -EIO;
            }
            if (fseeko(f, (off_t)(sizeof(uint64_t) + block_index * ONVAULT_BLOCK_SIZE), SEEK_SET) != 0 ||
                fwrite(cipherbuf, 1, new_cipher_len, f) != new_cipher_len) {
                if (fd >= 0)
                    flock(fd, LOCK_UN);
                fclose(f);
                onvault_memzero(cipherbuf, sizeof(cipherbuf));
                onvault_memzero(plainbuf, sizeof(plainbuf));
                onvault_memzero(&nonce, sizeof(nonce));
                return -EIO;
            }

            onvault_memzero(cipherbuf, sizeof(cipherbuf));
            onvault_memzero(plainbuf, sizeof(plainbuf));
        }

        if (fseeko(f, 0, SEEK_SET) != 0 ||
            fwrite(&new_file_size, sizeof(new_file_size), 1, f) != 1 ||
            fflush(f) != 0 ||
            ftruncate(fd, (off_t)(sizeof(uint64_t) + ciphertext_len_for_plaintext(new_file_size))) != 0) {
            if (fd >= 0)
                flock(fd, LOCK_UN);
            fclose(f);
            onvault_memzero(&nonce, sizeof(nonce));
            return -EIO;
        }
    }

    if (fd >= 0)
        flock(fd, LOCK_UN);
    fclose(f);
    onvault_memzero(&nonce, sizeof(nonce));
    return 0;
}

static int ov_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    if (fi->fh)
        close((int)fi->fh);
    return 0;
}

static int ov_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    /* Layer 2 policy check */
    if (g_policy_check) {
        pid_t caller = fuse_get_context()->pid;
        if (g_policy_check(caller, path, get_ctx()->mount_dir) != 0)
            return -EACCES;
    }

    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;

    /* Create the ciphertext file with size header */
    int fd = open(rpath, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd < 0)
        return -errno;

    /* Write initial size header (0 bytes) */
    uint64_t file_size = 0;
    (void)write(fd, &file_size, sizeof(file_size));

    /* Generate and store a nonce for this new file */
    onvault_nonce_t nonce;
    onvault_file_nonce_generate(&nonce);
    onvault_file_nonce_store(rpath, &nonce);
    onvault_memzero(&nonce, sizeof(nonce));

    fi->fh = (uint64_t)fd;
    return 0;
}

static int ov_unlink(const char *path)
{
    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;
    if (unlink(rpath) != 0)
        return -errno;
    return 0;
}

static int ov_rename(const char *from, const char *to)
{
    char rfrom[PATH_MAX], rto[PATH_MAX];
    if (real_path(from, rfrom) != 0) return -EACCES;
    if (real_path(to, rto) != 0) return -EACCES;
    if (rename(rfrom, rto) != 0)
        return -errno;
    return 0;
}

static int ov_mkdir(const char *path, mode_t mode)
{
    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;
    if (mkdir(rpath, mode) != 0)
        return -errno;
    return 0;
}

static int ov_rmdir(const char *path)
{
    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;
    if (rmdir(rpath) != 0)
        return -errno;
    return 0;
}

static int ov_chmod(const char *path, mode_t mode)
{
    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;
    if (chmod(rpath, mode) != 0)
        return -errno;
    return 0;
}

static int ov_chown(const char *path, uid_t uid, gid_t gid)
{
    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;
    if (lchown(rpath, uid, gid) != 0)
        return -errno;
    return 0;
}

static int ov_utimens(const char *path, const struct timespec ts[2])
{
    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;
    if (utimensat(AT_FDCWD, rpath, ts, AT_SYMLINK_NOFOLLOW) != 0)
        return -errno;
    return 0;
}

static int ov_statfs(const char *path, struct statvfs *stbuf)
{
    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;
    if (statvfs(rpath, stbuf) != 0)
        return -errno;
    return 0;
}

static int ov_symlink(const char *target, const char *linkname)
{
    char rlink[PATH_MAX];
    if (real_path(linkname, rlink) != 0) return -EACCES;
    if (symlink(target, rlink) != 0)
        return -errno;
    return 0;
}

static int ov_readlink(const char *path, char *buf, size_t size)
{
    char rpath[PATH_MAX];
    if (real_path(path, rpath) != 0) return -EACCES;
    ssize_t len = readlink(rpath, buf, size - 1);
    if (len < 0)
        return -errno;
    buf[len] = '\0';
    return 0;
}

static struct fuse_operations onvault_fuse_ops = {
    .getattr  = ov_getattr,
    .readdir  = ov_readdir,
    .open     = ov_open,
    .read     = ov_read,
    .write    = ov_write,
    .truncate = ov_truncate,
    .create   = ov_create,
    .release  = ov_release,
    .unlink   = ov_unlink,
    .rename   = ov_rename,
    .mkdir    = ov_mkdir,
    .rmdir    = ov_rmdir,
    .chmod    = ov_chmod,
    .chown    = ov_chown,
    .utimens  = ov_utimens,
    .statfs   = ov_statfs,
    .symlink  = ov_symlink,
    .readlink = ov_readlink,
};

int onvault_fuse_mount(const char *vault_id,
                        onvault_key_t *vault_key,
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
    snprintf(ctx->mount_dir, PATH_MAX, "%s", mount_dir);
    memcpy(&ctx->vault_key, vault_key, sizeof(onvault_key_t));
    onvault_mlock(&ctx->vault_key, sizeof(ctx->vault_key));
    onvault_key_wipe(vault_key, sizeof(*vault_key));

    /* FUSE args */
    char *argv[] = {
        "onvault",
        (char *)mount_dir,
        "-o", "local,auto_unmount,fsname=onvault",
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
                        onvault_key_t *vault_key,
                        const char *vault_dir,
                        const char *mount_dir)
{
    (void)vault_id;
    (void)vault_dir;
    (void)mount_dir;
    if (vault_key)
        onvault_key_wipe(vault_key, sizeof(*vault_key));
    fprintf(stderr, "onvault: macFUSE not available. Install with: brew install --cask macfuse\n");
    return ONVAULT_ERR_IO;
}

#endif /* HAVE_MACFUSE */

int onvault_fuse_unmount(const char *mount_dir)
{
    if (!mount_dir)
        return ONVAULT_ERR_INVALID;

    /* Validate mount_dir contains no shell-dangerous characters */
    for (const char *p = mount_dir; *p; p++) {
        if (*p == '\'' || *p == '`' || *p == '$' || *p == '\\' ||
            *p == ';' || *p == '|' || *p == '&' || *p == '\n')
            return ONVAULT_ERR_INVALID;
    }

    /* Use unmount(2) on macOS */
    if (unmount(mount_dir, MNT_FORCE) == 0)
        return ONVAULT_OK;

    /* Fallback: try without force flag */
    if (unmount(mount_dir, 0) == 0)
        return ONVAULT_OK;

    return ONVAULT_ERR_IO;
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

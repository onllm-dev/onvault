/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * vault.c — Vault lifecycle management
 */

#include "vault.h"
#include "encrypt.h"
#include "../common/crypto.h"
#include "../common/memwipe.h"
#include "../auth/auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <libgen.h>
#include <errno.h>

/* Validate vault_id contains only safe characters (no path traversal) */
static int validate_vault_id(const char *vault_id)
{
    if (!vault_id || vault_id[0] == '\0')
        return 0;
    for (const char *p = vault_id; *p; p++) {
        /* Allow alphanumeric, underscore, hyphen, dot (but not leading/double dots) */
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')
            continue;
        if (*p == '.' && p > vault_id && *(p - 1) != '.')
            continue; /* Allow single dots, not leading or double */
        return 0;
    }
    /* Reject ".." anywhere */
    if (strstr(vault_id, "..") != NULL)
        return 0;
    return 1;
}

void onvault_vault_id_from_path(const char *source_path, char *vault_id, size_t len)
{
    /* Extract last component, strip leading dot */
    const char *base = strrchr(source_path, '/');
    base = base ? base + 1 : source_path;
    if (*base == '.')
        base++;
    snprintf(vault_id, len, "%s", base);
}

int onvault_vault_get_paths(const char *vault_id,
                             char *vault_dir, char *mount_dir,
                             char *source_path)
{
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    if (vault_dir)
        snprintf(vault_dir, PATH_MAX, "%s/vaults/%s", data_dir, vault_id);
    if (mount_dir)
        snprintf(mount_dir, PATH_MAX, "%s/mnt/%s", data_dir, vault_id);

    /* Read source path from metadata file if it exists */
    if (source_path) {
        char meta_path[PATH_MAX];
        snprintf(meta_path, PATH_MAX, "%s/vaults/%s/.onvault_source", data_dir, vault_id);
        FILE *f = fopen(meta_path, "r");
        if (f) {
            if (fgets(source_path, PATH_MAX, f) == NULL)
                source_path[0] = '\0';
            /* Strip trailing newline */
            size_t slen = strlen(source_path);
            if (slen > 0 && source_path[slen - 1] == '\n')
                source_path[slen - 1] = '\0';
            fclose(f);
        } else {
            source_path[0] = '\0';
        }
    }

    return ONVAULT_OK;
}

/* Recursively encrypt directory contents from src to dst */
static int encrypt_directory(const onvault_key_t *vault_key,
                              const char *src_dir, const char *dst_dir)
{
    DIR *dir = opendir(src_dir);
    if (!dir)
        return ONVAULT_ERR_IO;

    mkdir(dst_dir, 0700);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (strcmp(entry->d_name, ".onvault_source") == 0)
            continue;

        char src_path[PATH_MAX], dst_path[PATH_MAX];
        snprintf(src_path, PATH_MAX, "%s/%s", src_dir, entry->d_name);
        snprintf(dst_path, PATH_MAX, "%s/%s", dst_dir, entry->d_name);

        struct stat st;
        if (lstat(src_path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            int rc = encrypt_directory(vault_key, src_path, dst_path);
            if (rc != ONVAULT_OK) {
                closedir(dir);
                return rc;
            }
        } else if (S_ISREG(st.st_mode)) {
            int rc = onvault_file_encrypt(vault_key, src_path, dst_path);
            if (rc != ONVAULT_OK) {
                closedir(dir);
                return rc;
            }
        } else if (S_ISLNK(st.st_mode)) {
            /* Preserve symlinks as-is inside the vault */
            char link_target[PATH_MAX];
            ssize_t link_len = readlink(src_path, link_target, PATH_MAX - 1);
            if (link_len > 0) {
                link_target[link_len] = '\0';
                symlink(link_target, dst_path);
            }
        }
    }

    closedir(dir);
    return ONVAULT_OK;
}

/* Recursively decrypt directory contents from src to dst */
static int decrypt_directory(const onvault_key_t *vault_key,
                              const char *src_dir, const char *dst_dir)
{
    DIR *dir = opendir(src_dir);
    if (!dir)
        return ONVAULT_ERR_IO;

    mkdir(dst_dir, 0700);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (strcmp(entry->d_name, ".onvault_source") == 0)
            continue;

        char src_path[PATH_MAX], dst_path[PATH_MAX];
        snprintf(src_path, PATH_MAX, "%s/%s", src_dir, entry->d_name);
        snprintf(dst_path, PATH_MAX, "%s/%s", dst_dir, entry->d_name);

        struct stat st;
        if (lstat(src_path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            int rc = decrypt_directory(vault_key, src_path, dst_path);
            if (rc != ONVAULT_OK) {
                closedir(dir);
                return rc;
            }
        } else if (S_ISREG(st.st_mode)) {
            int rc = onvault_file_decrypt(vault_key, src_path, dst_path);
            if (rc != ONVAULT_OK) {
                closedir(dir);
                return rc;
            }
        } else if (S_ISLNK(st.st_mode)) {
            char link_target[PATH_MAX];
            ssize_t link_len = readlink(src_path, link_target, PATH_MAX - 1);
            if (link_len > 0) {
                link_target[link_len] = '\0';
                symlink(link_target, dst_path);
            }
        }
    }

    closedir(dir);
    return ONVAULT_OK;
}

/* Recursively remove a directory */
static int remove_directory(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir)
        return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char full[PATH_MAX];
        snprintf(full, PATH_MAX, "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(full, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            if (remove_directory(full) != 0) {
                closedir(dir);
                return -1;
            }
        } else {
            if (unlink(full) != 0) {
                closedir(dir);
                return -1;
            }
        }
    }

    closedir(dir);
    return rmdir(path);
}

int onvault_vault_add(const onvault_key_t *master_key,
                       const char *source_path,
                       const char *vault_id_in)
{
    if (!master_key || !source_path)
        return ONVAULT_ERR_INVALID;

    /* Resolve source path */
    char resolved[PATH_MAX];
    if (!realpath(source_path, resolved))
        return ONVAULT_ERR_NOT_FOUND;

    struct stat st;
    if (stat(resolved, &st) != 0 || !S_ISDIR(st.st_mode))
        return ONVAULT_ERR_INVALID;

    /* Derive vault ID */
    char vault_id[64];
    if (vault_id_in) {
        snprintf(vault_id, sizeof(vault_id), "%s", vault_id_in);
    } else {
        onvault_vault_id_from_path(resolved, vault_id, sizeof(vault_id));
    }

    /* Validate vault_id to prevent path traversal */
    if (!validate_vault_id(vault_id))
        return ONVAULT_ERR_INVALID;

    /* Get paths */
    char vault_dir[PATH_MAX], mount_dir[PATH_MAX];
    onvault_vault_get_paths(vault_id, vault_dir, mount_dir, NULL);

    /* Check vault doesn't already exist */
    if (stat(vault_dir, &st) == 0)
        return ONVAULT_ERR_ALREADY_EXISTS;

    /* Create vault and mount directories */
    mkdir(vault_dir, 0700);
    mkdir(mount_dir, 0700);

    /* Derive vault key */
    onvault_key_t vault_key;
    onvault_mlock(&vault_key, sizeof(vault_key));
    int rc = onvault_derive_vault_key(master_key, vault_id, &vault_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&vault_key, sizeof(vault_key));
        return rc;
    }

    /* Encrypt directory contents */
    rc = encrypt_directory(&vault_key, resolved, vault_dir);
    onvault_key_wipe(&vault_key, sizeof(vault_key));

    if (rc != ONVAULT_OK) {
        remove_directory(vault_dir);
        rmdir(mount_dir);
        return rc;
    }

    /* Store source path metadata */
    char meta_path[PATH_MAX];
    snprintf(meta_path, PATH_MAX, "%s/.onvault_source", vault_dir);
    FILE *f = fopen(meta_path, "w");
    if (f) {
        fprintf(f, "%s\n", resolved);
        fclose(f);
    }

    /* Remove original directory and create symlink */
    char backup[PATH_MAX];
    snprintf(backup, PATH_MAX, "%s.onvault-backup", resolved);
    if (rename(resolved, backup) != 0) {
        /* Can't move original — leave both intact */
        return ONVAULT_ERR_IO;
    }

    if (symlink(mount_dir, resolved) != 0) {
        /* Restore original if symlink fails */
        rename(backup, resolved);
        return ONVAULT_ERR_IO;
    }

    /* Remove backup after successful symlink */
    remove_directory(backup);

    return ONVAULT_OK;
}

int onvault_vault_remove(const onvault_key_t *master_key,
                          const char *vault_id)
{
    if (!master_key || !vault_id)
        return ONVAULT_ERR_INVALID;

    /* Validate vault_id */
    if (!validate_vault_id(vault_id))
        return ONVAULT_ERR_INVALID;

    char vault_dir[PATH_MAX], mount_dir[PATH_MAX], source_path[PATH_MAX];
    onvault_vault_get_paths(vault_id, vault_dir, mount_dir, source_path);

    if (source_path[0] == '\0')
        return ONVAULT_ERR_NOT_FOUND;

    /* Derive vault key */
    onvault_key_t vault_key;
    onvault_mlock(&vault_key, sizeof(vault_key));
    int rc = onvault_derive_vault_key(master_key, vault_id, &vault_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&vault_key, sizeof(vault_key));
        return rc;
    }

    struct stat lst;
    if (lstat(source_path, &lst) != 0 || !S_ISLNK(lst.st_mode)) {
        onvault_key_wipe(&vault_key, sizeof(vault_key));
        return ONVAULT_ERR_INVALID;
    }

    {
        char link_target[PATH_MAX];
        char expected_mount[PATH_MAX];
        ssize_t llen = readlink(source_path, link_target, PATH_MAX - 1);
        if (llen <= 0) {
            onvault_key_wipe(&vault_key, sizeof(vault_key));
            return ONVAULT_ERR_INVALID;
        }
        link_target[llen] = '\0';
        onvault_vault_get_paths(vault_id, NULL, expected_mount, NULL);
        if (strcmp(link_target, expected_mount) != 0) {
            onvault_key_wipe(&vault_key, sizeof(vault_key));
            return ONVAULT_ERR_INVALID;
        }
    }

    /* Decrypt to a temporary restore directory first. */
    char restore_path[PATH_MAX];
    snprintf(restore_path, PATH_MAX, "%s.onvault-restore", source_path);

    if (lstat(restore_path, &lst) == 0) {
        if (S_ISDIR(lst.st_mode))
            remove_directory(restore_path);
        else
            unlink(restore_path);
    }

    rc = decrypt_directory(&vault_key, vault_dir, restore_path);
    onvault_key_wipe(&vault_key, sizeof(vault_key));

    if (rc != ONVAULT_OK) {
        remove_directory(restore_path);
        return rc;
    }

    if (unlink(source_path) != 0) {
        remove_directory(restore_path);
        return ONVAULT_ERR_IO;
    }
    if (rename(restore_path, source_path) != 0) {
        symlink(mount_dir, source_path);
        return ONVAULT_ERR_IO;
    }

    /* Clean up vault and mount directories */
    remove_directory(vault_dir);
    rmdir(mount_dir);

    return ONVAULT_OK;
}

int onvault_vault_list(char ids[][64], int max_ids)
{
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return 0;

    char vaults_dir[PATH_MAX];
    snprintf(vaults_dir, PATH_MAX, "%s/vaults", data_dir);

    DIR *dir = opendir(vaults_dir);
    if (!dir)
        return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && count < max_ids) {
        if (entry->d_name[0] == '.')
            continue;

        char full[PATH_MAX];
        snprintf(full, PATH_MAX, "%s/%s", vaults_dir, entry->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(ids[count], 64, "%s", entry->d_name);
            count++;
        }
    }

    closedir(dir);
    return count;
}

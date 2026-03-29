/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * onvault_fuse.h — macFUSE encrypted filesystem layer
 */

#ifndef ONVAULT_FUSE_H
#define ONVAULT_FUSE_H

#include "../common/types.h"

/*
 * Mount a vault as a FUSE filesystem.
 * vault_id: which vault to mount
 * vault_key: per-vault encryption key
 * vault_dir: path to ciphertext directory
 * mount_dir: path to mount point
 * Returns 0 on success (blocks until unmounted if foreground).
 */
int onvault_fuse_mount(const char *vault_id,
                        onvault_key_t *vault_key,
                        const char *vault_dir,
                        const char *mount_dir);

/*
 * Unmount a FUSE-mounted vault.
 * mount_dir: path to mount point
 * Returns 0 on success.
 */
int onvault_fuse_unmount(const char *mount_dir);

/*
 * Check if a mount point is currently mounted.
 * Returns 1 if mounted, 0 if not.
 */
int onvault_fuse_is_mounted(const char *mount_dir);

/*
 * Set the policy check callback for Layer 2 (ESF) integration.
 * The callback is called on every file open to verify process identity.
 * Returns 0 on allow, non-zero on deny.
 */
typedef int (*onvault_policy_check_fn)(pid_t pid,
                                        const char *file_path,
                                        const char *mount_dir);
void onvault_fuse_set_policy_check(onvault_policy_check_fn fn);

#endif /* ONVAULT_FUSE_H */

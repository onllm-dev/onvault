/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * vault.h — Vault lifecycle management
 */

#ifndef ONVAULT_VAULT_H
#define ONVAULT_VAULT_H

#include "../common/types.h"

/*
 * Add a new vault: encrypt the source directory contents and
 * create a symlink from source → mount point.
 * master_key: for deriving the vault key
 * source_path: original directory (e.g., ~/.ssh)
 * vault_id: short identifier (e.g., "ssh") — auto-derived if NULL
 * Returns 0 on success.
 */
int onvault_vault_add(const onvault_key_t *master_key,
                       const char *source_path,
                       const char *vault_id);

/*
 * Remove a vault: decrypt back to original location, remove
 * vault data and symlink.
 */
int onvault_vault_remove(const onvault_key_t *master_key,
                          const char *vault_id);

/*
 * Get vault paths from a vault_id.
 * vault_dir: ~/.onvault/vaults/<id>/
 * mount_dir: ~/.onvault/mnt/<id>/
 */
int onvault_vault_get_paths(const char *vault_id,
                             char *vault_dir, char *mount_dir,
                             char *source_path);

/*
 * Auto-derive a vault_id from a source path.
 * e.g., "~/.ssh" → "ssh", "~/.aws" → "aws"
 */
void onvault_vault_id_from_path(const char *source_path, char *vault_id, size_t len);

/*
 * List all vault IDs in ~/.onvault/vaults/.
 * ids: array of vault_id strings (caller allocates)
 * max_ids: max number of IDs to return
 * Returns number of vaults found.
 */
int onvault_vault_list(char ids[][64], int max_ids);

#endif /* ONVAULT_VAULT_H */

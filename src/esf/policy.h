/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * policy.h — Per-process access policy evaluation
 */

#ifndef ONVAULT_POLICY_H
#define ONVAULT_POLICY_H

#include "../common/types.h"

/* Maximum rules per vault */
#define ONVAULT_MAX_RULES_PER_VAULT 64

/* Vault policy */
typedef struct {
    char              vault_id[64];
    char              mount_path[PATH_MAX];
    onvault_rule_t    rules[ONVAULT_MAX_RULES_PER_VAULT];
    int               rule_count;
    onvault_verify_mode_t verify_mode;
    int               allow_escalated; /* Global default for this vault */
} onvault_vault_policy_t;

/*
 * Load all policies. Called on daemon startup after decrypting config.
 */
int onvault_policy_load(const char *config_path);

/*
 * Add a policy for a vault.
 */
int onvault_policy_add_vault(const onvault_vault_policy_t *policy);

/*
 * Remove policy for a vault.
 */
int onvault_policy_remove_vault(const char *vault_id);

/*
 * Get policy for a vault by mount path.
 */
const onvault_vault_policy_t *onvault_policy_get_by_mount(const char *mount_path);

/*
 * Evaluate whether a process should be allowed to access a file.
 * process: identity of the requesting process
 * file_path: path being accessed
 * vault_mount_path: which vault mount this falls under
 * Returns 1 if allowed, 0 if denied.
 */
int onvault_policy_evaluate(const onvault_process_t *process,
                             const char *file_path,
                             const char *vault_mount_path);

/*
 * Add an allow rule for a process to a vault.
 */
int onvault_policy_add_rule(const char *vault_id,
                             const char *process_path,
                             onvault_rule_action_t action);

/*
 * Clear all policies (shutdown).
 */
void onvault_policy_clear(void);

#endif /* ONVAULT_POLICY_H */

/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * policy.c — Per-process access policy evaluation
 */

#include "policy.h"
#include "../common/hash.h"
#include "../common/memwipe.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>

/* In-memory policy store */
#define MAX_VAULT_POLICIES 32
static onvault_vault_policy_t g_policies[MAX_VAULT_POLICIES];
static int g_policy_count = 0;
static pthread_rwlock_t g_policy_lock = PTHREAD_RWLOCK_INITIALIZER;

int onvault_policy_load(const char *config_path)
{
    if (!config_path)
        return ONVAULT_ERR_INVALID;

    /*
     * Policy is stored as a flat binary array of onvault_vault_policy_t
     * encrypted with the config key. This function loads from the already-
     * decrypted in-memory buffer passed by the daemon after decryption.
     *
     * The daemon calls onvault_policy_add_vault() for each vault after
     * decrypting the config, so this function serves as a reload entry
     * point that clears existing policies first.
     */
    pthread_rwlock_wrlock(&g_policy_lock);
    onvault_memzero(g_policies, sizeof(g_policies));
    g_policy_count = 0;
    pthread_rwlock_unlock(&g_policy_lock);

    return ONVAULT_OK;
}

int onvault_policy_add_vault(const onvault_vault_policy_t *policy)
{
    if (!policy || g_policy_count >= MAX_VAULT_POLICIES)
        return ONVAULT_ERR_INVALID;

    pthread_rwlock_wrlock(&g_policy_lock);
    memcpy(&g_policies[g_policy_count], policy, sizeof(onvault_vault_policy_t));
    g_policy_count++;
    pthread_rwlock_unlock(&g_policy_lock);

    return ONVAULT_OK;
}

int onvault_policy_remove_vault(const char *vault_id)
{
    pthread_rwlock_wrlock(&g_policy_lock);

    for (int i = 0; i < g_policy_count; i++) {
        if (strcmp(g_policies[i].vault_id, vault_id) == 0) {
            for (int j = i; j < g_policy_count - 1; j++)
                g_policies[j] = g_policies[j + 1];
            g_policy_count--;
            pthread_rwlock_unlock(&g_policy_lock);
            return ONVAULT_OK;
        }
    }

    pthread_rwlock_unlock(&g_policy_lock);
    return ONVAULT_ERR_NOT_FOUND;
}

const onvault_vault_policy_t *onvault_policy_get_by_mount(const char *mount_path)
{
    pthread_rwlock_rdlock(&g_policy_lock);
    for (int i = 0; i < g_policy_count; i++) {
        if (strcmp(g_policies[i].mount_path, mount_path) == 0) {
            const onvault_vault_policy_t *result = &g_policies[i];
            pthread_rwlock_unlock(&g_policy_lock);
            return result;
        }
    }
    pthread_rwlock_unlock(&g_policy_lock);
    return NULL;
}

/* Match a process against a rule */
static int rule_matches(const onvault_rule_t *rule,
                         const onvault_process_t *process,
                         onvault_verify_mode_t verify_mode)
{
    /* Check process path */
    if (rule->process_path[0] != '\0') {
        if (strcmp(rule->process_path, process->path) != 0)
            return 0;
    }

    /* Verify process identity based on mode */
    switch (verify_mode) {
    case VERIFY_CODESIGN_PREFERRED:
        if (process->is_signed) {
            /* Check Team ID if rule specifies it */
            if (rule->use_team_id && rule->team_id[0] != '\0') {
                if (strcmp(rule->team_id, process->team_id) != 0)
                    return 0;
            }
            /* Check Signing ID if rule specifies it */
            if (rule->signing_id[0] != '\0') {
                if (strcmp(rule->signing_id, process->signing_id) != 0)
                    return 0;
            }
        } else {
            /* Unsigned binary — verify by hash */
            if (rule->use_hash) {
                if (onvault_hash_compare(&rule->binary_hash,
                                          &process->binary_hash) != 0)
                    return 0;
            }
        }
        break;

    case VERIFY_HASH_ONLY:
        /* Always check hash regardless of code signing */
        if (rule->use_hash) {
            if (onvault_hash_compare(&rule->binary_hash,
                                      &process->binary_hash) != 0)
                return 0;
        }
        break;

    case VERIFY_CODESIGN_REQUIRED:
        if (!process->is_signed)
            return 0; /* Reject unsigned binaries entirely */
        if (rule->use_team_id && rule->team_id[0] != '\0') {
            if (strcmp(rule->team_id, process->team_id) != 0)
                return 0;
        }
        break;
    }

    /* Check escalation */
    if (!rule->allow_escalated) {
        /* Deny if process was escalated (ruid != euid) */
        if (process->ruid != process->euid)
            return 0;
    }

    return 1; /* Rule matches */
}

int onvault_policy_evaluate(const onvault_process_t *process,
                             const char *file_path,
                             const char *vault_mount_path)
{
    if (!process || !file_path || !vault_mount_path)
        return 0; /* Deny on error */

    pthread_rwlock_rdlock(&g_policy_lock);

    /* Find the vault policy */
    const onvault_vault_policy_t *policy = NULL;
    for (int i = 0; i < g_policy_count; i++) {
        size_t mlen = strlen(g_policies[i].mount_path);
        if (strncmp(vault_mount_path, g_policies[i].mount_path, mlen) == 0 &&
            (vault_mount_path[mlen] == '/' || vault_mount_path[mlen] == '\0')) {
            policy = &g_policies[i];
            break;
        }
    }

    if (!policy) {
        pthread_rwlock_unlock(&g_policy_lock);
        return 0; /* No policy = deny (default deny) */
    }

    /* Evaluate rules in order — first match wins */
    for (int i = 0; i < policy->rule_count; i++) {
        const onvault_rule_t *rule = &policy->rules[i];

        if (rule_matches(rule, process, policy->verify_mode)) {
            int allowed = (rule->action == RULE_ALLOW);
            pthread_rwlock_unlock(&g_policy_lock);
            return allowed;
        }
    }

    pthread_rwlock_unlock(&g_policy_lock);
    return 0; /* Default deny — no rule matched */
}

int onvault_policy_add_rule(const char *vault_id,
                             const char *process_path,
                             onvault_rule_action_t action)
{
    if (!vault_id || !process_path)
        return ONVAULT_ERR_INVALID;

    pthread_rwlock_wrlock(&g_policy_lock);

    for (int i = 0; i < g_policy_count; i++) {
        if (strcmp(g_policies[i].vault_id, vault_id) == 0) {
            if (g_policies[i].rule_count >= ONVAULT_MAX_RULES_PER_VAULT) {
                pthread_rwlock_unlock(&g_policy_lock);
                return ONVAULT_ERR_MEMORY;
            }

            onvault_rule_t *rule = &g_policies[i].rules[g_policies[i].rule_count];
            memset(rule, 0, sizeof(*rule));
            strlcpy(rule->process_path, process_path, PATH_MAX);
            rule->action = action;

            /* Hash the binary for verification */
            onvault_sha256_file(process_path, &rule->binary_hash);
            rule->use_hash = 1;

            g_policies[i].rule_count++;
            pthread_rwlock_unlock(&g_policy_lock);
            return ONVAULT_OK;
        }
    }

    pthread_rwlock_unlock(&g_policy_lock);
    return ONVAULT_ERR_NOT_FOUND;
}

void onvault_policy_clear(void)
{
    pthread_rwlock_wrlock(&g_policy_lock);
    onvault_memzero(g_policies, sizeof(g_policies));
    g_policy_count = 0;
    pthread_rwlock_unlock(&g_policy_lock);
}

/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * policy.c — Per-process access policy evaluation
 */

#include "policy.h"
#include "../auth/auth.h"
#include "../common/config.h"
#include "../common/hash.h"
#include "../common/memwipe.h"
#include "../fuse/vault.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

/* In-memory policy store */
#define MAX_VAULT_POLICIES 32
#define ONVAULT_POLICY_STORE_VERSION 1

typedef struct {
    uint32_t version;
    uint32_t count;
} onvault_policy_store_header_t;

static onvault_vault_policy_t g_policies[MAX_VAULT_POLICIES];
static int g_policy_count = 0;
static pthread_rwlock_t g_policy_lock = PTHREAD_RWLOCK_INITIALIZER;
static onvault_key_t g_policy_config_key;
static int g_policy_config_key_loaded = 0;

static void clear_policy_config_key(void)
{
    if (g_policy_config_key_loaded) {
        onvault_key_wipe(&g_policy_config_key, sizeof(g_policy_config_key));
        g_policy_config_key_loaded = 0;
    }
}

static int set_policy_config_key(const onvault_key_t *config_key)
{
    if (!config_key)
        return ONVAULT_ERR_INVALID;

    clear_policy_config_key();
    onvault_mlock(&g_policy_config_key, sizeof(g_policy_config_key));
    memcpy(&g_policy_config_key, config_key, sizeof(g_policy_config_key));
    g_policy_config_key_loaded = 1;
    return ONVAULT_OK;
}

static int get_policy_path(char *path, size_t path_len)
{
    char data_dir[PATH_MAX];

    if (!path || path_len == 0)
        return ONVAULT_ERR_INVALID;
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    snprintf(path, path_len, "%s/policies.enc", data_dir);
    return ONVAULT_OK;
}

static int policy_save_locked(void)
{
    char policy_path[PATH_MAX];
    onvault_policy_store_header_t header;
    uint8_t *blob = NULL;
    size_t blob_len;
    int rc;

    if (!g_policy_config_key_loaded)
        return ONVAULT_OK;

    rc = get_policy_path(policy_path, sizeof(policy_path));
    if (rc != ONVAULT_OK)
        return rc;

    blob_len = sizeof(header) +
        (size_t)g_policy_count * sizeof(onvault_vault_policy_t);
    blob = calloc(1, blob_len);
    if (!blob)
        return ONVAULT_ERR_MEMORY;

    header.version = ONVAULT_POLICY_STORE_VERSION;
    header.count = (uint32_t)g_policy_count;
    memcpy(blob, &header, sizeof(header));
    if (g_policy_count > 0) {
        memcpy(blob + sizeof(header), g_policies,
               (size_t)g_policy_count * sizeof(onvault_vault_policy_t));
    }

    rc = onvault_config_write(policy_path, &g_policy_config_key, blob, blob_len);
    onvault_memzero(blob, blob_len);
    free(blob);
    return rc;
}

int onvault_policy_load(const onvault_key_t *config_key)
{
    char policy_path[PATH_MAX];
    uint8_t *blob = NULL;
    size_t blob_len = sizeof(onvault_policy_store_header_t) +
        MAX_VAULT_POLICIES * sizeof(onvault_vault_policy_t);
    onvault_policy_store_header_t header;
    int rc;

    if (!config_key)
        return ONVAULT_ERR_INVALID;

    rc = set_policy_config_key(config_key);
    if (rc != ONVAULT_OK)
        return rc;

    pthread_rwlock_wrlock(&g_policy_lock);
    onvault_memzero(g_policies, sizeof(g_policies));
    g_policy_count = 0;
    pthread_rwlock_unlock(&g_policy_lock);

    rc = get_policy_path(policy_path, sizeof(policy_path));
    if (rc != ONVAULT_OK)
        return rc;

    blob = malloc(blob_len);
    if (!blob)
        return ONVAULT_ERR_MEMORY;

    rc = onvault_config_read(policy_path, &g_policy_config_key, blob, &blob_len);
    if (rc == ONVAULT_ERR_NOT_FOUND) {
        free(blob);
        return ONVAULT_OK;
    }
    if (rc != ONVAULT_OK) {
        free(blob);
        return rc;
    }
    if (blob_len < sizeof(header)) {
        onvault_memzero(blob, blob_len);
        free(blob);
        return ONVAULT_ERR_INVALID;
    }

    memcpy(&header, blob, sizeof(header));
    if (header.version != ONVAULT_POLICY_STORE_VERSION ||
        header.count > MAX_VAULT_POLICIES ||
        blob_len != sizeof(header) +
                   (size_t)header.count * sizeof(onvault_vault_policy_t)) {
        onvault_memzero(blob, blob_len);
        free(blob);
        return ONVAULT_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&g_policy_lock);
    if (header.count > 0) {
        memcpy(g_policies, blob + sizeof(header),
               (size_t)header.count * sizeof(onvault_vault_policy_t));
    }
    g_policy_count = (int)header.count;
    pthread_rwlock_unlock(&g_policy_lock);

    onvault_memzero(blob, blob_len);
    free(blob);
    return ONVAULT_OK;
}

int onvault_policy_save(void)
{
    int rc;

    pthread_rwlock_rdlock(&g_policy_lock);
    rc = policy_save_locked();
    pthread_rwlock_unlock(&g_policy_lock);
    return rc;
}

int onvault_policy_add_vault(const onvault_vault_policy_t *policy)
{
    int rc = ONVAULT_OK;

    if (!policy)
        return ONVAULT_ERR_INVALID;

    pthread_rwlock_wrlock(&g_policy_lock);
    if (g_policy_count >= MAX_VAULT_POLICIES) {
        pthread_rwlock_unlock(&g_policy_lock);
        return ONVAULT_ERR_INVALID;
    }
    memcpy(&g_policies[g_policy_count], policy, sizeof(onvault_vault_policy_t));
    g_policy_count++;
    rc = policy_save_locked();
    pthread_rwlock_unlock(&g_policy_lock);

    return rc;
}

int onvault_policy_remove_vault(const char *vault_id)
{
    int rc = ONVAULT_ERR_NOT_FOUND;

    pthread_rwlock_wrlock(&g_policy_lock);

    for (int i = 0; i < g_policy_count; i++) {
        if (strcmp(g_policies[i].vault_id, vault_id) == 0) {
            for (int j = i; j < g_policy_count - 1; j++)
                g_policies[j] = g_policies[j + 1];
            g_policy_count--;
            rc = policy_save_locked();
            break;
        }
    }

    pthread_rwlock_unlock(&g_policy_lock);
    return rc;
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
    int rc = ONVAULT_OK;

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
            rc = policy_save_locked();
            pthread_rwlock_unlock(&g_policy_lock);
            return rc;
        }
    }

    /* Auto-create a policy for this vault if one doesn't exist */
    if (g_policy_count < MAX_VAULT_POLICIES) {
        onvault_vault_policy_t *new_policy = &g_policies[g_policy_count];
        memset(new_policy, 0, sizeof(*new_policy));
        strlcpy(new_policy->vault_id, vault_id, sizeof(new_policy->vault_id));
        new_policy->verify_mode = VERIFY_CODESIGN_PREFERRED;
        new_policy->allow_escalated = 0;
        onvault_vault_get_paths(vault_id, NULL, new_policy->mount_path, NULL);

        onvault_rule_t *rule = &new_policy->rules[0];
        memset(rule, 0, sizeof(*rule));
        strlcpy(rule->process_path, process_path, PATH_MAX);
        rule->action = action;
        onvault_sha256_file(process_path, &rule->binary_hash);
        rule->use_hash = 1;
        new_policy->rule_count = 1;

        g_policy_count++;
        rc = policy_save_locked();
        pthread_rwlock_unlock(&g_policy_lock);
        return rc;
    }

    pthread_rwlock_unlock(&g_policy_lock);
    return ONVAULT_ERR_NOT_FOUND;
}

int onvault_policy_get_rules(const char *vault_id, char *buf, size_t buf_len)
{
    if (!vault_id || !buf || buf_len == 0)
        return -1;

    pthread_rwlock_rdlock(&g_policy_lock);

    const onvault_vault_policy_t *policy = NULL;
    for (int i = 0; i < g_policy_count; i++) {
        if (strcmp(g_policies[i].vault_id, vault_id) == 0) {
            policy = &g_policies[i];
            break;
        }
    }

    if (!policy) {
        pthread_rwlock_unlock(&g_policy_lock);
        snprintf(buf, buf_len, "No policy found for vault: %s\n", vault_id);
        return -1;
    }

    int off = 0;
    off += snprintf(buf + off, buf_len - (size_t)off,
                    "Vault: %s (mount: %s)\n", policy->vault_id, policy->mount_path);

    const char *mode_str = "codesign_preferred";
    if (policy->verify_mode == VERIFY_HASH_ONLY) mode_str = "hash_only";
    else if (policy->verify_mode == VERIFY_CODESIGN_REQUIRED) mode_str = "codesign_required";
    off += snprintf(buf + off, buf_len - (size_t)off,
                    "Verification: %s\n", mode_str);
    off += snprintf(buf + off, buf_len - (size_t)off,
                    "Rules (%d):\n", policy->rule_count);

    for (int i = 0; i < policy->rule_count; i++) {
        const onvault_rule_t *r = &policy->rules[i];
        const char *action = (r->action == RULE_ALLOW) ? "ALLOW" : "DENY";
        off += snprintf(buf + off, buf_len - (size_t)off,
                        "  [%d] %s %s", i + 1, action, r->process_path);
        if (r->use_team_id && r->team_id[0])
            off += snprintf(buf + off, buf_len - (size_t)off,
                            " (team: %s)", r->team_id);
        if (r->use_hash)
            off += snprintf(buf + off, buf_len - (size_t)off, " [hash verified]");
        off += snprintf(buf + off, buf_len - (size_t)off, "\n");
    }

    if (policy->rule_count == 0)
        off += snprintf(buf + off, buf_len - (size_t)off,
                        "  (none — all access denied by default)\n");

    int count = policy->rule_count;
    pthread_rwlock_unlock(&g_policy_lock);
    return count;
}

int onvault_policy_show(char *buf, size_t buf_len)
{
    if (!buf || buf_len == 0)
        return ONVAULT_ERR_INVALID;

    pthread_rwlock_rdlock(&g_policy_lock);

    int off = 0;
    off += snprintf(buf + off, buf_len - (size_t)off,
                    "Policies (%d vault(s)):\n\n", g_policy_count);

    for (int i = 0; i < g_policy_count; i++) {
        const onvault_vault_policy_t *p = &g_policies[i];
        const char *mode_str = "codesign_preferred";
        if (p->verify_mode == VERIFY_HASH_ONLY) mode_str = "hash_only";
        else if (p->verify_mode == VERIFY_CODESIGN_REQUIRED) mode_str = "codesign_required";

        off += snprintf(buf + off, buf_len - (size_t)off,
                        "[%s] mount=%s verify=%s escalation=%s\n",
                        p->vault_id, p->mount_path, mode_str,
                        p->allow_escalated ? "allowed" : "denied");

        for (int j = 0; j < p->rule_count; j++) {
            const onvault_rule_t *r = &p->rules[j];
            const char *action = (r->action == RULE_ALLOW) ? "ALLOW" : "DENY";
            off += snprintf(buf + off, buf_len - (size_t)off,
                            "  %s %s\n", action, r->process_path);
        }
        if (p->rule_count == 0)
            off += snprintf(buf + off, buf_len - (size_t)off,
                            "  (no rules — default deny)\n");
        off += snprintf(buf + off, buf_len - (size_t)off, "\n");
    }

    if (g_policy_count == 0)
        off += snprintf(buf + off, buf_len - (size_t)off,
                        "No vaults configured.\n");

    pthread_rwlock_unlock(&g_policy_lock);
    return ONVAULT_OK;
}

void onvault_policy_clear(void)
{
    pthread_rwlock_wrlock(&g_policy_lock);
    onvault_memzero(g_policies, sizeof(g_policies));
    g_policy_count = 0;
    pthread_rwlock_unlock(&g_policy_lock);
    clear_policy_config_key();
}

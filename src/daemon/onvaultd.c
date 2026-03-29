/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * onvaultd.c — Main daemon entry point
 *
 * Lifecycle:
 *   1. Authenticate (passphrase / Touch ID / session)
 *   2. Unwrap master key from Secure Enclave
 *   3. Decrypt config
 *   4. Mount FUSE for all vaults
 *   5. Start ESF client
 *   6. Show menu bar
 *   7. Listen on IPC socket for CLI commands
 *   8. On shutdown: wipe keys, unmount FUSE, stop ESF
 */

#include "../common/types.h"
#include "../common/crypto.h"
#include "../common/memwipe.h"
#include "../common/ipc.h"
#include "../common/log.h"
#include "../auth/auth.h"
#include "../keystore/keystore.h"
#include "../fuse/vault.h"
#include "../fuse/onvault_fuse.h"
#include "../esf/agent.h"
#include "../esf/policy.h"
#include "../menubar/menubar.h"
#include "../watch/watch.h"
#include "../common/hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>

/* Forward declarations */
static void release_pid_lock(void);
static void stop_http_server(void);
static void http_clear_token(void);
static void http_reset_unlock_failures(void);

/* Recent denial tracking (shared between menubar, HTTP API, and deny callback) */
#define MAX_RECENT_DENIALS 10

typedef struct {
    char process_name[256];
    char process_path[PATH_MAX];
    char file_path[PATH_MAX];
    char vault_id[64];
    time_t timestamp;
} recent_denial_t;

static recent_denial_t g_recent_denials[MAX_RECENT_DENIALS];
static int g_denial_count = 0;
static pthread_mutex_t g_denial_lock = PTHREAD_MUTEX_INITIALIZER;

static volatile int g_running = 1;
static onvault_key_t g_master_key;
static int g_master_key_loaded = 0;
static onvault_key_t g_config_key;
static int g_config_key_loaded = 0;
static int g_log_initialized = 0;

#define MAX_NONCES 16
#define NONCE_TTL_SECONDS 60

/* Challenge-response nonces for auth-gated commands.
 * Each nonce is single-use and expires after a short TTL. */
typedef struct {
    uint8_t nonce[ONVAULT_HASH_SIZE];
    time_t created;
    int valid;
} auth_nonce_slot_t;

static auth_nonce_slot_t g_nonce_bucket[MAX_NONCES];
static pthread_mutex_t g_nonce_lock = PTHREAD_MUTEX_INITIALIZER;

#define MAX_MOUNTED_VAULTS 32

typedef struct {
    int active;
    pthread_t thread;
    char vault_id[64];
    char mount_dir[PATH_MAX];
} mounted_vault_t;

typedef struct {
    int slot;
    char vault_id[64];
    char vault_dir[PATH_MAX];
    char mount_dir[PATH_MAX];
    onvault_key_t vault_key;
} mount_worker_arg_t;

static mounted_vault_t g_mounted_vaults[MAX_MOUNTED_VAULTS];
static pthread_mutex_t g_mount_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_http_token[65] = {0};
static int g_unlock_failures = 0;
static time_t g_unlock_lockout_until = 0;
static pthread_mutex_t g_http_auth_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Smart defaults: auto-populate allowlist when adding a vault.
 * Maps vault_id to known binaries that should have access.
 */
typedef struct {
    const char *vault_type; /* e.g., "ssh", "aws", "kube" */
    const char *paths[16];  /* binary paths to allow */
} smart_default_t;

static const smart_default_t g_smart_defaults[] = {
    { "ssh", {
        "/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/sftp",
        "/usr/bin/ssh-add", "/usr/bin/ssh-agent", "/usr/bin/ssh-keygen",
        "/usr/bin/git", NULL
    }},
    { "aws", {
        "/usr/local/bin/aws", "/opt/homebrew/bin/aws",
        "/usr/local/bin/terraform", "/opt/homebrew/bin/terraform",
        "/usr/local/bin/pulumi", "/opt/homebrew/bin/pulumi", NULL
    }},
    { "kube", {
        "/usr/local/bin/kubectl", "/opt/homebrew/bin/kubectl",
        "/usr/local/bin/helm", "/opt/homebrew/bin/helm",
        "/usr/local/bin/k9s", "/opt/homebrew/bin/k9s", NULL
    }},
    { "gnupg", {
        "/usr/local/bin/gpg", "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg2", "/opt/homebrew/bin/gpg2",
        "/usr/local/bin/gpg-agent", "/opt/homebrew/bin/gpg-agent",
        "/usr/bin/git", NULL
    }},
    { "docker", {
        "/usr/local/bin/docker", "/opt/homebrew/bin/docker",
        "/Applications/Docker.app/Contents/MacOS/Docker", NULL
    }},
    { NULL, { NULL } }
};

static void apply_smart_defaults(const char *vault_id)
{
    /* Find matching smart defaults for this vault type */
    const smart_default_t *defaults = NULL;
    for (int i = 0; g_smart_defaults[i].vault_type != NULL; i++) {
        if (strcmp(g_smart_defaults[i].vault_type, vault_id) == 0) {
            defaults = &g_smart_defaults[i];
            break;
        }
    }

    if (!defaults)
        return;

    /* Create a vault policy with the smart defaults */
    onvault_vault_policy_t policy;
    memset(&policy, 0, sizeof(policy));
    strlcpy(policy.vault_id, vault_id, sizeof(policy.vault_id));
    policy.verify_mode = VERIFY_CODESIGN_PREFERRED;
    policy.allow_escalated = 0;

    /* Set mount path */
    char mount_dir[PATH_MAX];
    onvault_vault_get_paths(vault_id, NULL, mount_dir, NULL);
    strlcpy(policy.mount_path, mount_dir, PATH_MAX);

    /* Add rules for binaries that exist on this system */
    int rule_count = 0;
    for (int i = 0; defaults->paths[i] != NULL && rule_count < ONVAULT_MAX_RULES_PER_VAULT; i++) {
        struct stat st;
        if (stat(defaults->paths[i], &st) == 0) {
            onvault_rule_t *r = &policy.rules[rule_count];
            memset(r, 0, sizeof(*r));
            strlcpy(r->process_path, defaults->paths[i], PATH_MAX);
            r->action = RULE_ALLOW;
            r->use_hash = 1;
            onvault_sha256_file(defaults->paths[i], &r->binary_hash);
            rule_count++;
            fprintf(stderr, "onvaultd: smart default: allow %s for %s\n",
                    defaults->paths[i], vault_id);
        }
    }
    policy.rule_count = rule_count;

    if (rule_count > 0)
        onvault_policy_add_vault(&policy);
}

static void clear_loaded_keys(void)
{
    if (g_config_key_loaded) {
        onvault_key_wipe(&g_config_key, sizeof(g_config_key));
        g_config_key_loaded = 0;
    }
    if (g_master_key_loaded) {
        onvault_key_wipe(&g_master_key, sizeof(g_master_key));
        g_master_key_loaded = 0;
    }
}

static int build_mount_path(const char *mount_dir,
                            const char *file_path,
                            char *out,
                            size_t out_len)
{
    int n;

    if (!mount_dir || !file_path || !out || out_len == 0)
        return -1;

    if (file_path[0] == '/')
        n = snprintf(out, out_len, "%s%s", mount_dir, file_path);
    else
        n = snprintf(out, out_len, "%s/%s", mount_dir, file_path);

    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

static int daemon_policy_check(pid_t pid,
                               const char *file_path,
                               const char *mount_dir)
{
    onvault_process_t process;
    char mounted_path[PATH_MAX];

    if (!g_master_key_loaded || !file_path || !mount_dir)
        return -1;
    if (onvault_esf_extract_process(pid, &process) != ONVAULT_OK ||
        process.path[0] == '\0')
        return -1;
    if (build_mount_path(mount_dir, file_path, mounted_path, sizeof(mounted_path)) != 0)
        return -1;

    return onvault_policy_evaluate(&process, mounted_path, mount_dir) ? 0 : -1;
}

static void *mount_worker(void *arg)
{
    mount_worker_arg_t *worker = (mount_worker_arg_t *)arg;

    if (!worker)
        return NULL;

    (void)onvault_fuse_mount(worker->vault_id, &worker->vault_key,
                             worker->vault_dir, worker->mount_dir);
    onvault_key_wipe(&worker->vault_key, sizeof(worker->vault_key));

    pthread_mutex_lock(&g_mount_lock);
    memset(&g_mounted_vaults[worker->slot], 0, sizeof(g_mounted_vaults[worker->slot]));
    pthread_mutex_unlock(&g_mount_lock);

    free(worker);
    return NULL;
}

static int find_mount_slot_locked(const char *vault_id, const char *mount_dir)
{
    for (int i = 0; i < MAX_MOUNTED_VAULTS; i++) {
        if (!g_mounted_vaults[i].active)
            continue;
        if ((vault_id && strcmp(g_mounted_vaults[i].vault_id, vault_id) == 0) ||
            (mount_dir && strcmp(g_mounted_vaults[i].mount_dir, mount_dir) == 0))
            return i;
    }
    return -1;
}

static int mount_vault_async(const char *vault_id,
                             const char *vault_dir,
                             const char *mount_dir)
{
    mount_worker_arg_t *worker = NULL;
    int slot = -1;
    int rc = ONVAULT_OK;

    if (!vault_id || !vault_dir || !mount_dir || !g_master_key_loaded)
        return ONVAULT_ERR_INVALID;
    if (onvault_fuse_is_mounted(mount_dir))
        return ONVAULT_OK;

    worker = calloc(1, sizeof(*worker));
    if (!worker)
        return ONVAULT_ERR_MEMORY;

    strlcpy(worker->vault_id, vault_id, sizeof(worker->vault_id));
    strlcpy(worker->vault_dir, vault_dir, sizeof(worker->vault_dir));
    strlcpy(worker->mount_dir, mount_dir, sizeof(worker->mount_dir));
    onvault_mlock(&worker->vault_key, sizeof(worker->vault_key));
    rc = onvault_derive_vault_key(&g_master_key, vault_id, &worker->vault_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&worker->vault_key, sizeof(worker->vault_key));
        free(worker);
        return rc;
    }

    pthread_mutex_lock(&g_mount_lock);
    slot = find_mount_slot_locked(vault_id, mount_dir);
    if (slot >= 0) {
        pthread_mutex_unlock(&g_mount_lock);
        onvault_key_wipe(&worker->vault_key, sizeof(worker->vault_key));
        free(worker);
        return ONVAULT_OK;
    }
    for (int i = 0; i < MAX_MOUNTED_VAULTS; i++) {
        if (!g_mounted_vaults[i].active) {
            slot = i;
            g_mounted_vaults[i].active = 1;
            strlcpy(g_mounted_vaults[i].vault_id, vault_id, sizeof(g_mounted_vaults[i].vault_id));
            strlcpy(g_mounted_vaults[i].mount_dir, mount_dir, sizeof(g_mounted_vaults[i].mount_dir));
            break;
        }
    }
    pthread_mutex_unlock(&g_mount_lock);

    if (slot < 0) {
        onvault_key_wipe(&worker->vault_key, sizeof(worker->vault_key));
        free(worker);
        return ONVAULT_ERR_MEMORY;
    }

    worker->slot = slot;
    if (pthread_create(&g_mounted_vaults[slot].thread, NULL, mount_worker, worker) != 0) {
        pthread_mutex_lock(&g_mount_lock);
        memset(&g_mounted_vaults[slot], 0, sizeof(g_mounted_vaults[slot]));
        pthread_mutex_unlock(&g_mount_lock);
        onvault_key_wipe(&worker->vault_key, sizeof(worker->vault_key));
        free(worker);
        return ONVAULT_ERR_IO;
    }
    pthread_detach(g_mounted_vaults[slot].thread);

    for (int tries = 0; tries < 50; tries++) {
        if (onvault_fuse_is_mounted(mount_dir)) {
            onvault_esf_add_monitored_path(mount_dir);
            if (g_log_initialized)
                onvault_log_write(LOG_VAULT_MOUNTED, vault_id, NULL, 0, mount_dir, "mounted");
            return ONVAULT_OK;
        }

        pthread_mutex_lock(&g_mount_lock);
        rc = g_mounted_vaults[slot].active ? ONVAULT_OK : ONVAULT_ERR_IO;
        pthread_mutex_unlock(&g_mount_lock);
        if (rc != ONVAULT_OK)
            break;
        usleep(100000);
    }

    return ONVAULT_ERR_IO;
}

static int mount_all_vaults(void)
{
    char ids[32][64];
    int count = onvault_vault_list(ids, 32);

    onvault_fuse_set_policy_check(daemon_policy_check);

    for (int i = 0; i < count; i++) {
        char vault_dir[PATH_MAX];
        char mount_dir[PATH_MAX];

        onvault_vault_get_paths(ids[i], vault_dir, mount_dir, NULL);
        if (mount_vault_async(ids[i], vault_dir, mount_dir) != ONVAULT_OK)
            return ONVAULT_ERR_IO;
    }

    return ONVAULT_OK;
}

static void unmount_vault(const char *vault_id, const char *mount_dir)
{
    if (!mount_dir)
        return;

    onvault_esf_remove_monitored_path(mount_dir);
    if (g_log_initialized && vault_id)
        onvault_log_write(LOG_VAULT_UNMOUNTED, vault_id, NULL, 0, mount_dir, "unmounted");
    if (onvault_fuse_is_mounted(mount_dir))
        onvault_fuse_unmount(mount_dir);

    for (int tries = 0; tries < 50; tries++) {
        int active;

        pthread_mutex_lock(&g_mount_lock);
        active = (find_mount_slot_locked(vault_id, mount_dir) >= 0);
        pthread_mutex_unlock(&g_mount_lock);
        if (!active)
            break;
        usleep(100000);
    }
}

static void unmount_all_vaults(void)
{
    char ids[32][64];
    int count = onvault_vault_list(ids, 32);

    for (int i = 0; i < count; i++) {
        char mount_dir[PATH_MAX];
        onvault_vault_get_paths(ids[i], NULL, mount_dir, NULL);
        unmount_vault(ids[i], mount_dir);
    }
}

static int finish_unlock(const onvault_key_t *master_key)
{
    int rc;
    int log_started = 0;

    if (!master_key)
        return ONVAULT_ERR_INVALID;
    if (g_master_key_loaded)
        return ONVAULT_OK;

    onvault_mlock(&g_master_key, sizeof(g_master_key));
    memcpy(&g_master_key, master_key, sizeof(g_master_key));
    g_master_key_loaded = 1;

    onvault_mlock(&g_config_key, sizeof(g_config_key));
    rc = onvault_derive_config_key(&g_master_key, &g_config_key);
    if (rc != ONVAULT_OK) {
        clear_loaded_keys();
        return rc;
    }
    g_config_key_loaded = 1;

    rc = onvault_policy_load(&g_config_key);
    if (rc != ONVAULT_OK) {
        onvault_policy_clear();
        clear_loaded_keys();
        return rc;
    }

    if (!g_log_initialized) {
        if (onvault_log_init(&g_config_key) == ONVAULT_OK) {
            g_log_initialized = 1;
            log_started = 1;
        }
    }

    rc = mount_all_vaults();
    if (rc != ONVAULT_OK) {
        unmount_all_vaults();
        if (log_started) {
            onvault_log_close();
            g_log_initialized = 0;
        }
        onvault_policy_clear();
        clear_loaded_keys();
        return rc;
    }

    return ONVAULT_OK;
}

static void clear_nonce_slot_locked(int slot)
{
    if (slot < 0 || slot >= MAX_NONCES)
        return;
    g_nonce_bucket[slot].valid = 0;
    g_nonce_bucket[slot].created = 0;
    onvault_memzero(g_nonce_bucket[slot].nonce, sizeof(g_nonce_bucket[slot].nonce));
}

static void expire_nonces_locked(time_t now)
{
    for (int i = 0; i < MAX_NONCES; i++) {
        if (!g_nonce_bucket[i].valid)
            continue;
        if ((now - g_nonce_bucket[i].created) > NONCE_TTL_SECONDS)
            clear_nonce_slot_locked(i);
    }
}

static void clear_nonce_bucket(void)
{
    pthread_mutex_lock(&g_nonce_lock);
    for (int i = 0; i < MAX_NONCES; i++)
        clear_nonce_slot_locked(i);
    pthread_mutex_unlock(&g_nonce_lock);
}

static int issue_auth_nonce(uint8_t *nonce_out)
{
    int slot = -1;
    time_t now;

    if (!nonce_out)
        return ONVAULT_ERR_INVALID;

    now = time(NULL);
    pthread_mutex_lock(&g_nonce_lock);
    expire_nonces_locked(now);

    for (int i = 0; i < MAX_NONCES; i++) {
        if (!g_nonce_bucket[i].valid) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        time_t oldest = now;

        slot = 0;
        for (int i = 0; i < MAX_NONCES; i++) {
            if (g_nonce_bucket[i].created <= oldest) {
                oldest = g_nonce_bucket[i].created;
                slot = i;
            }
        }
    }

    clear_nonce_slot_locked(slot);
    if (onvault_random_bytes(g_nonce_bucket[slot].nonce, ONVAULT_HASH_SIZE) != ONVAULT_OK) {
        pthread_mutex_unlock(&g_nonce_lock);
        return ONVAULT_ERR_CRYPTO;
    }
    g_nonce_bucket[slot].created = now;
    g_nonce_bucket[slot].valid = 1;
    memcpy(nonce_out, g_nonce_bucket[slot].nonce, ONVAULT_HASH_SIZE);
    pthread_mutex_unlock(&g_nonce_lock);
    return ONVAULT_OK;
}

static int consume_nonce_for_proof(const uint8_t *proof, const onvault_key_t *verify_key)
{
    onvault_key_t loaded_key;
    const onvault_key_t *key = verify_key;
    time_t now;
    int have_valid = 0;
    int rc = ONVAULT_ERR_AUTH;

    if (!proof)
        return ONVAULT_ERR_INVALID;

    if (!key) {
        onvault_mlock(&loaded_key, sizeof(loaded_key));
        rc = onvault_keystore_load_master_key(&loaded_key);
        if (rc != ONVAULT_OK) {
            onvault_key_wipe(&loaded_key, sizeof(loaded_key));
            return rc;
        }
        key = &loaded_key;
    }

    now = time(NULL);
    pthread_mutex_lock(&g_nonce_lock);
    expire_nonces_locked(now);
    for (int i = 0; i < MAX_NONCES; i++) {
        if (!g_nonce_bucket[i].valid)
            continue;
        have_valid = 1;
        rc = onvault_auth_verify_proof_with_key(proof,
                                                g_nonce_bucket[i].nonce,
                                                ONVAULT_HASH_SIZE,
                                                key);
        if (rc == ONVAULT_OK) {
            clear_nonce_slot_locked(i);
            pthread_mutex_unlock(&g_nonce_lock);
            if (!verify_key)
                onvault_key_wipe(&loaded_key, sizeof(loaded_key));
            return ONVAULT_OK;
        }
    }
    pthread_mutex_unlock(&g_nonce_lock);

    if (!verify_key)
        onvault_key_wipe(&loaded_key, sizeof(loaded_key));
    return have_valid ? ONVAULT_ERR_AUTH : ONVAULT_ERR_NOT_FOUND;
}

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void cleanup(void)
{
    fprintf(stderr, "onvaultd: shutting down\n");

    /* Stop HTTP server */
    stop_http_server();

    /* Release PID lock */
    release_pid_lock();

    /* Close audit log */
    if (g_log_initialized) {
        onvault_log_close();
        g_log_initialized = 0;
    }

    /* Unmount all vaults */
    unmount_all_vaults();

    /* Stop ESF */
    onvault_esf_stop();

    /* Clear policies */
    onvault_policy_clear();

    clear_loaded_keys();
    http_clear_token();
    http_reset_unlock_failures();
    clear_nonce_bucket();

    /* Stop IPC */
    onvault_ipc_server_stop();

    /* Lock session */
    onvault_auth_lock();
}

/* Read exactly n bytes from fd, retrying on partial reads */
static ssize_t read_all(int fd, void *buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, (uint8_t *)buf + total, n - total);
        if (r <= 0)
            return (r == 0 && total > 0) ? (ssize_t)total : r;
        total += (size_t)r;
    }
    return (ssize_t)total;
}

static void append_text(char *buf, size_t buf_len, int *off, const char *fmt, ...)
{
    va_list ap;
    int written;

    if (!buf || !off || !fmt || buf_len == 0)
        return;
    if (*off < 0 || (size_t)*off >= buf_len - 1)
        return;

    va_start(ap, fmt);
    written = vsnprintf(buf + *off, buf_len - (size_t)*off, fmt, ap);
    va_end(ap);

    if (written < 0)
        return;
    if ((size_t)written >= buf_len - (size_t)*off)
        *off = (int)buf_len - 1;
    else
        *off += written;
}

/* Handle IPC commands from CLI */
static void handle_client(int client_fd)
{
    onvault_ipc_header_t header;
    ssize_t n = read_all(client_fd, &header, sizeof(header));
    if (n != sizeof(header)) {
        close(client_fd);
        return;
    }

    /* Read payload if any */
    char payload[ONVAULT_IPC_MAX_MSG] = {0};
    if (header.payload_len > 0 && header.payload_len < ONVAULT_IPC_MAX_MSG) {
        ssize_t pn = read_all(client_fd, payload, header.payload_len);
        if (pn != (ssize_t)header.payload_len) {
            close(client_fd);
            return; /* Reject incomplete payloads */
        }
        payload[pn] = '\0'; /* Ensure null termination */
    }

    /* Process command */
    onvault_ipc_resp_header_t resp = { .status = IPC_RESP_OK, .payload_len = 0 };
    char resp_buf[ONVAULT_IPC_MAX_MSG] = {0};

    switch (header.cmd) {
    case IPC_CMD_STATUS: {
        char ids[32][64];
        int count = onvault_vault_list(ids, 32);
        int off = snprintf(resp_buf, sizeof(resp_buf),
                           "onvaultd running, state=%s, %d vault(s)\n",
                           g_master_key_loaded ? "unlocked" : "locked",
                           count);
        for (int i = 0; i < count; i++) {
            char mount_dir[PATH_MAX], source[PATH_MAX];
            onvault_vault_get_paths(ids[i], NULL, mount_dir, source);
            int mounted = onvault_fuse_is_mounted(mount_dir);
            append_text(resp_buf, sizeof(resp_buf), &off,
                        "  %s (%s) [%s]\n", ids[i], source,
                        mounted ? "mounted" : "locked");
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_VAULT_ADD: {
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            break;
        }
        /* Payload: flags(1) + path */
        if (header.payload_len < 2) {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf), "Invalid payload\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        int smart_defaults = (payload[0] != 0);
        const char *add_path = payload + 1;

        int rc = onvault_vault_add(&g_master_key, add_path, NULL);
        if (rc != ONVAULT_OK) {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf), "Failed to add vault (err=%d)\n", rc);
        } else {
            char vid[64];
            char vault_dir[PATH_MAX];
            char mount_dir[PATH_MAX];
            onvault_vault_id_from_path(add_path, vid, sizeof(vid));
            onvault_vault_get_paths(vid, vault_dir, mount_dir, NULL);

            int off = snprintf(resp_buf, sizeof(resp_buf), "Vault added: %s\n", add_path);

            if (smart_defaults) {
                apply_smart_defaults(vid);
                char rules_buf[2048];
                int nrules = onvault_policy_get_rules(vid, rules_buf, sizeof(rules_buf));
                if (nrules > 0) {
                    append_text(resp_buf, sizeof(resp_buf), &off,
                                "\nSmart defaults applied (%d rules):\n%s", nrules, rules_buf);
                }
            } else {
                append_text(resp_buf, sizeof(resp_buf), &off,
                            "No smart defaults applied. Use --smart to auto-populate allowlist.\n");
            }

            rc = mount_vault_async(vid, vault_dir, mount_dir);
            if (rc != ONVAULT_OK) {
                resp.status = IPC_RESP_ERROR;
                append_text(resp_buf, sizeof(resp_buf), &off,
                            "Vault added but mount failed (err=%d)\n", rc);
            }
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_VAULT_REMOVE: {
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            break;
        }
        /* Payload: proof(32) + vault_id */
        if (header.payload_len <= ONVAULT_HASH_SIZE) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf),
                     "Passphrase required to remove vault\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        int rm_auth = consume_nonce_for_proof((const uint8_t *)payload, &g_master_key);
        if (rm_auth == ONVAULT_ERR_NOT_FOUND) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "No challenge issued\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        if (rm_auth != ONVAULT_OK) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "Wrong passphrase\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        const char *vault_id = payload + ONVAULT_HASH_SIZE;
        char mount_dir[PATH_MAX];
        onvault_vault_get_paths(vault_id, NULL, mount_dir, NULL);
        unmount_vault(vault_id, mount_dir);
        int rc = onvault_vault_remove(&g_master_key, vault_id);
        if (rc != ONVAULT_OK) {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf), "Failed to remove vault (err=%d)\n", rc);
        } else {
            snprintf(resp_buf, sizeof(resp_buf), "Vault removed: %s\n", vault_id);
            onvault_policy_remove_vault(vault_id);
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_VAULT_LIST: {
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            break;
        }
        char ids[32][64];
        int count = onvault_vault_list(ids, 32);
        int off = 0;
        for (int i = 0; i < count; i++) {
            char source[PATH_MAX];
            onvault_vault_get_paths(ids[i], NULL, NULL, source);
            append_text(resp_buf, sizeof(resp_buf), &off,
                        "%s → %s\n", ids[i], source);
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_UNLOCK: {
        if (g_master_key_loaded) {
            snprintf(resp_buf, sizeof(resp_buf), "Already unlocked\n");
        } else {
            onvault_key_t session_key;
            int urc = onvault_auth_check_session(&session_key);
            if (urc == ONVAULT_OK) {
                int frc = finish_unlock(&session_key);
                onvault_key_wipe(&session_key, sizeof(session_key));
                if (frc == ONVAULT_OK)
                    snprintf(resp_buf, sizeof(resp_buf), "Unlocked\n");
                else {
                    resp.status = IPC_RESP_ERROR;
                    snprintf(resp_buf, sizeof(resp_buf), "Unlock failed (err=%d)\n", frc);
                }
            } else {
                resp.status = IPC_RESP_AUTH_REQUIRED;
                snprintf(resp_buf, sizeof(resp_buf), "Unlock failed (err=%d)\n", urc);
            }
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_AUTH_CHALLENGE: {
        int nonce_rc = issue_auth_nonce((uint8_t *)resp_buf);
        if (nonce_rc != ONVAULT_OK) {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf), "Failed to generate challenge\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        resp.payload_len = ONVAULT_HASH_SIZE;
        break;
    }

    case IPC_CMD_LOCK: {
        /* Verify challenge-response proof before allowing lock */
        if (header.payload_len < ONVAULT_HASH_SIZE) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf),
                     "Passphrase required to lock\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        int lock_auth = consume_nonce_for_proof((const uint8_t *)payload,
                                                g_master_key_loaded ? &g_master_key : NULL);
        if (lock_auth == ONVAULT_ERR_NOT_FOUND) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf),
                     "No challenge issued. Request IPC_CMD_AUTH_CHALLENGE first.\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        if (lock_auth != ONVAULT_OK) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "Wrong passphrase\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        /* Auth OK — signal main loop to exit */
        g_running = 0;
        snprintf(resp_buf, sizeof(resp_buf), "Locked\n");
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_ALLOW: {
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            break;
        }
        if (header.payload_len <= ONVAULT_HASH_SIZE + 1) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "Passphrase required\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        int allow_auth = consume_nonce_for_proof((const uint8_t *)payload, &g_master_key);
        if (allow_auth == ONVAULT_ERR_NOT_FOUND) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "No challenge issued\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        if (allow_auth != ONVAULT_OK) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "Wrong passphrase\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        /* payload: proof(32) + process_path\0vault_id */
        char *rule_payload = payload + ONVAULT_HASH_SIZE;
        size_t rule_len = header.payload_len - ONVAULT_HASH_SIZE;
        char *sep = memchr(rule_payload, '\0', rule_len);
        if (sep && sep < rule_payload + rule_len - 1) {
            char *process_path = rule_payload;
            char *vault_id = sep + 1;
            int rc = onvault_policy_add_rule(vault_id, process_path, RULE_ALLOW);
            if (rc == ONVAULT_OK)
                snprintf(resp_buf, sizeof(resp_buf), "Allowed %s for %s\n", process_path, vault_id);
            else {
                resp.status = IPC_RESP_ERROR;
                snprintf(resp_buf, sizeof(resp_buf), "Failed (err=%d)\n", rc);
            }
        } else {
            resp.status = IPC_RESP_ERROR;
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_DENY: {
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            break;
        }
        if (header.payload_len <= ONVAULT_HASH_SIZE + 1) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "Passphrase required\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        int deny_auth = consume_nonce_for_proof((const uint8_t *)payload, &g_master_key);
        if (deny_auth == ONVAULT_ERR_NOT_FOUND) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "No challenge issued\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        if (deny_auth != ONVAULT_OK) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "Wrong passphrase\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        /* payload: proof(32) + process_path\0vault_id */
        char *rule_payload = payload + ONVAULT_HASH_SIZE;
        size_t rule_len = header.payload_len - ONVAULT_HASH_SIZE;
        char *sep = memchr(rule_payload, '\0', rule_len);
        if (sep && sep < rule_payload + rule_len - 1) {
            char *process_path = rule_payload;
            char *vault_id = sep + 1;
            int rc = onvault_policy_add_rule(vault_id, process_path, RULE_DENY);
            if (rc == ONVAULT_OK)
                snprintf(resp_buf, sizeof(resp_buf), "Denied %s for %s\n", process_path, vault_id);
            else {
                resp.status = IPC_RESP_ERROR;
                snprintf(resp_buf, sizeof(resp_buf), "Failed (err=%d)\n", rc);
            }
        } else {
            resp.status = IPC_RESP_ERROR;
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_RULES: {
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            break;
        }
        char rules_buf[ONVAULT_IPC_MAX_MSG];
        onvault_policy_get_rules(payload, rules_buf, sizeof(rules_buf));
        snprintf(resp_buf, sizeof(resp_buf), "%s", rules_buf);
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_POLICY_SHOW: {
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            break;
        }
        onvault_policy_show(resp_buf, sizeof(resp_buf));
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_LOG: {
        if (!g_log_initialized) {
            snprintf(resp_buf, sizeof(resp_buf), "Logging not initialized (unlock first)\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        int denied_only = (header.payload_len > 0 && payload[0] != 0) ? 1 : 0;
        size_t log_buf_len = sizeof(resp_buf) - 1;
        int log_rc = onvault_log_read(resp_buf, &log_buf_len, 50, denied_only);
        if (log_rc != ONVAULT_OK) {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf), "Failed to read logs\n");
        }
        resp.payload_len = (uint32_t)log_buf_len;
        break;
    }

    case IPC_CMD_WATCH_START: {
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            break;
        }
        /* Default 24h watch duration */
        int wrc = onvault_watch_start(payload, 86400);
        if (wrc == ONVAULT_OK) {
            snprintf(resp_buf, sizeof(resp_buf),
                     "Watching %s for 24 hours...\n"
                     "Run 'onvault vault suggest <vault_id>' to see results.\n", payload);
        } else {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf),
                     "Failed to start watch (err=%d)\n", wrc);
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_WATCH_SUGGEST: {
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            break;
        }
        onvault_watch_entry_t entries[ONVAULT_MAX_WATCH_ENTRIES];
        int count = onvault_watch_get_results(entries, ONVAULT_MAX_WATCH_ENTRIES);
        if (count == 0) {
            snprintf(resp_buf, sizeof(resp_buf),
                     "No processes discovered yet.\n"
                     "Run 'onvault vault watch <path>' first.\n");
        } else {
            int off = snprintf(resp_buf, sizeof(resp_buf),
                               "Discovered processes (%d):\n", count);
            for (int i = 0; i < count && (size_t)off < sizeof(resp_buf) - 128; i++) {
                const char *signed_str = entries[i].is_signed ? "signed" : "unsigned";
                append_text(resp_buf, sizeof(resp_buf), &off,
                            "  [%d] %s (%s, %d accesses)",
                            i + 1, entries[i].path, signed_str,
                            entries[i].access_count);
                if (entries[i].team_id[0])
                    append_text(resp_buf, sizeof(resp_buf), &off,
                                " team=%s", entries[i].team_id);
                append_text(resp_buf, sizeof(resp_buf), &off, "\n");
            }
            append_text(resp_buf, sizeof(resp_buf), &off,
                        "\nTo allow a process: onvault allow <path> %s\n", payload);
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    default:
        resp.status = IPC_RESP_ERROR;
        snprintf(resp_buf, sizeof(resp_buf), "Unknown command\n");
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    /* Send response */
    write(client_fd, &resp, sizeof(resp));
    if (resp.payload_len > 0)
        write(client_fd, resp_buf, resp.payload_len);

    close(client_fd);
}

/* Denial notification callback */
static void on_deny(const onvault_process_t *process,
                     const char *file_path,
                     const char *vault_id)
{
    fprintf(stderr, "onvaultd: DENIED %s (pid %d) → %s [vault: %s]\n",
            process->path, process->pid, file_path, vault_id);

    /* Log the denial event */
    onvault_log_write(LOG_ACCESS_DENIED, vault_id, process->path,
                       process->pid, file_path, NULL);

    /* Track denial for HTTP API */
    const char *proc_name = strrchr(process->path, '/');
    proc_name = proc_name ? proc_name + 1 : process->path;

    pthread_mutex_lock(&g_denial_lock);
    if (g_denial_count >= MAX_RECENT_DENIALS) {
        memmove(&g_recent_denials[0], &g_recent_denials[1],
                (MAX_RECENT_DENIALS - 1) * sizeof(recent_denial_t));
        g_denial_count = MAX_RECENT_DENIALS - 1;
    }
    recent_denial_t *d = &g_recent_denials[g_denial_count];
    memset(d, 0, sizeof(*d));
    strlcpy(d->process_name, proc_name, sizeof(d->process_name));
    strlcpy(d->process_path, process->path, sizeof(d->process_path));
    strlcpy(d->file_path, file_path ?: "", sizeof(d->file_path));
    strlcpy(d->vault_id, vault_id ?: "", sizeof(d->vault_id));
    d->timestamp = time(NULL);
    g_denial_count++;
    pthread_mutex_unlock(&g_denial_lock);

    /* Send macOS notification */
    onvault_menubar_notify_deny(proc_name, process->path, file_path, vault_id);
}

/* IPC accept loop — runs on background thread when menu bar is active */
static void *ipc_accept_loop(void *arg)
{
    int server_fd = *(int *)arg;

    while (g_running) {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);

        fd_set fds;
        FD_ZERO(&fds);
        if (server_fd < 0) break;
        FD_SET(server_fd, &fds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ready = select(server_fd + 1, &fds, NULL, NULL, &tv);

        if (ready > 0) {
            int client_fd = accept(server_fd,
                                    (struct sockaddr *)&client_addr,
                                    &client_len);
            if (client_fd >= 0)
                handle_client(client_fd);
        }
    }

    return NULL;
}

/* PID lock file management */
static char g_pid_path[PATH_MAX] = {0};

static int acquire_pid_lock(const char *data_dir)
{
    snprintf(g_pid_path, PATH_MAX, "%s/onvaultd.pid", data_dir);

    /* Check if another instance is already running */
    FILE *f = fopen(g_pid_path, "r");
    if (f) {
        pid_t existing_pid = 0;
        if (fscanf(f, "%d", &existing_pid) == 1 && existing_pid > 0) {
            /* Check if the process is actually running */
            if (kill(existing_pid, 0) == 0) {
                fprintf(stderr, "onvaultd: another instance is already running (pid %d)\n",
                        existing_pid);
                fprintf(stderr, "onvaultd: to stop it, run: onvault lock\n");
                fclose(f);
                return -1;
            }
            /* Stale PID file — process is dead */
            fprintf(stderr, "onvaultd: removing stale PID file (pid %d)\n", existing_pid);
        }
        fclose(f);
    }

    /* Write our PID */
    f = fopen(g_pid_path, "w");
    if (!f) {
        fprintf(stderr, "onvaultd: failed to create PID file\n");
        return -1;
    }
    fprintf(f, "%d\n", getpid());
    fclose(f);
    chmod(g_pid_path, 0600);
    return 0;
}

static void release_pid_lock(void)
{
    if (g_pid_path[0] != '\0')
        unlink(g_pid_path);
}

static const char *http_status_text(int status_code)
{
    switch (status_code) {
    case 200: return "OK";
    case 401: return "Unauthorized";
    case 404: return "Not Found";
    case 429: return "Too Many Requests";
    default: return "Error";
    }
}

static int json_escape(char *out, size_t out_len, const char *in)
{
    size_t j = 0;

    if (!out || out_len == 0)
        return 0;
    if (!in) {
        out[0] = '\0';
        return 0;
    }

    for (size_t i = 0; in[i] != '\0' && j < out_len - 1; i++) {
        const unsigned char ch = (unsigned char)in[i];

        if (ch == '"' || ch == '\\') {
            if (j + 2 >= out_len)
                break;
            out[j++] = '\\';
            out[j++] = (char)ch;
            continue;
        }
        if (ch == '\n' || ch == '\r' || ch == '\t') {
            if (j + 2 >= out_len)
                break;
            out[j++] = '\\';
            out[j++] = (ch == '\n') ? 'n' : (ch == '\r' ? 'r' : 't');
            continue;
        }
        if (ch < 0x20) {
            if (j + 6 >= out_len)
                break;
            j += (size_t)snprintf(out + j, out_len - j, "\\u%04x", ch);
            continue;
        }

        out[j++] = (char)ch;
    }

    out[j] = '\0';
    return (int)j;
}

static void http_copy_token(char out[65])
{
    pthread_mutex_lock(&g_http_auth_lock);
    memcpy(out, g_http_token, 65);
    pthread_mutex_unlock(&g_http_auth_lock);
}

static void http_clear_token(void)
{
    pthread_mutex_lock(&g_http_auth_lock);
    onvault_memzero(g_http_token, sizeof(g_http_token));
    pthread_mutex_unlock(&g_http_auth_lock);
}

static int http_generate_token(void)
{
    uint8_t raw[32];
    static const char hex[] = "0123456789abcdef";

    if (onvault_random_bytes(raw, sizeof(raw)) != ONVAULT_OK)
        return ONVAULT_ERR_CRYPTO;

    pthread_mutex_lock(&g_http_auth_lock);
    for (size_t i = 0; i < sizeof(raw); i++) {
        g_http_token[i * 2] = hex[(raw[i] >> 4) & 0x0f];
        g_http_token[i * 2 + 1] = hex[raw[i] & 0x0f];
    }
    g_http_token[64] = '\0';
    pthread_mutex_unlock(&g_http_auth_lock);

    onvault_memzero(raw, sizeof(raw));
    return ONVAULT_OK;
}

static int http_parse_query_token(const char *request_path, char *token, size_t token_len)
{
    const char *query;
    const char *start;
    size_t len = 0;

    if (!request_path || !token || token_len == 0)
        return 0;

    query = strchr(request_path, '?');
    if (!query)
        return 0;

    start = strstr(query + 1, "token=");
    if (!start)
        return 0;
    start += 6;

    while (start[len] != '\0' && start[len] != '&' && start[len] != ' ' &&
           start[len] != '\r' && start[len] != '\n' && len < token_len - 1) {
        len++;
    }
    if (len == 0)
        return 0;

    memcpy(token, start, len);
    token[len] = '\0';
    return 1;
}

static int http_parse_bearer_token(const char *request, char *token, size_t token_len)
{
    const char *header;
    size_t len = 0;

    if (!request || !token || token_len == 0)
        return 0;

    header = strstr(request, "Authorization: Bearer ");
    if (!header)
        return 0;
    header += strlen("Authorization: Bearer ");

    while (header[len] != '\0' && header[len] != '\r' && header[len] != '\n' &&
           len < token_len - 1) {
        len++;
    }
    if (len == 0)
        return 0;

    memcpy(token, header, len);
    token[len] = '\0';
    return 1;
}

static int http_check_auth(const char *request, const char *request_path)
{
    char presented[65];
    char expected[65];
    int ok = 0;

    if (!request || !request_path)
        return 0;
    if (!http_parse_bearer_token(request, presented, sizeof(presented)) &&
        !http_parse_query_token(request_path, presented, sizeof(presented))) {
        return 0;
    }

    http_copy_token(expected);
    if (expected[0] == '\0')
        return 0;
    if (strlen(presented) != 64 || strlen(expected) != 64)
        return 0;

    ok = onvault_constant_time_eq((const uint8_t *)presented,
                                  (const uint8_t *)expected,
                                  64);
    return ok;
}

static int http_unlock_locked_out(time_t now)
{
    int locked = 0;

    pthread_mutex_lock(&g_http_auth_lock);
    locked = (g_unlock_lockout_until > now) ? 1 : 0;
    pthread_mutex_unlock(&g_http_auth_lock);
    return locked;
}

static void http_record_unlock_failure(time_t now)
{
    pthread_mutex_lock(&g_http_auth_lock);
    g_unlock_failures++;
    if (g_unlock_failures >= 10)
        g_unlock_lockout_until = now + 300;
    else if (g_unlock_failures >= 5)
        g_unlock_lockout_until = now + 30;
    pthread_mutex_unlock(&g_http_auth_lock);
}

static void http_reset_unlock_failures(void)
{
    pthread_mutex_lock(&g_http_auth_lock);
    g_unlock_failures = 0;
    g_unlock_lockout_until = 0;
    pthread_mutex_unlock(&g_http_auth_lock);
}

static void http_audit_log(const char *path, const char *detail)
{
    if (!g_log_initialized || !path)
        return;
    onvault_log_write(LOG_POLICY_CHANGE, "http", "web-ui", 0, path,
                      detail ? detail : "");
}

/* Simple localhost-only HTTP server for menubar web UI */
static int g_http_port = 0;
static int g_http_sock = -1;

static int start_http_server(void)
{
    g_http_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_http_sock < 0) return -1;

    int opt = 1;
    setsockopt(g_http_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 only */
    addr.sin_port = 0; /* Let OS pick a port */

    if (bind(g_http_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(g_http_sock);
        g_http_sock = -1;
        return -1;
    }

    /* Get assigned port */
    socklen_t addrlen = sizeof(addr);
    getsockname(g_http_sock, (struct sockaddr *)&addr, &addrlen);
    g_http_port = ntohs(addr.sin_port);

    if (listen(g_http_sock, 5) != 0) {
        close(g_http_sock);
        g_http_sock = -1;
        return -1;
    }

    /* Write port file so menu bar and tests can find us */
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) == ONVAULT_OK) {
        char port_path[PATH_MAX];
        snprintf(port_path, PATH_MAX, "%s/http.port", data_dir);
        FILE *f = fopen(port_path, "w");
        if (f) {
            fprintf(f, "%d\n", g_http_port);
            fclose(f);
        }
    }

    return 0;
}

static void stop_http_server(void)
{
    if (g_http_sock >= 0) {
        close(g_http_sock);
        g_http_sock = -1;
    }
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) == ONVAULT_OK) {
        char port_path[PATH_MAX];
        snprintf(port_path, PATH_MAX, "%s/http.port", data_dir);
        unlink(port_path);
    }
}

/* Serve the menubar HTML page (embedded) */
static const char *get_menubar_html(void);

static void http_respond(int fd, int status_code, const char *content_type,
                          const char *body, size_t body_len)
{
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: http://127.0.0.1\r\n"
        "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, http_status_text(status_code),
        content_type, body_len);
    write(fd, header, (size_t)hlen);
    if (body_len > 0)
        write(fd, body, body_len);
}

static void handle_http_client(int client_fd)
{
    char request[4096] = {0};
    char unauthorized[] = "{\"ok\":false,\"msg\":\"Unauthorized\"}";
    ssize_t n = read(client_fd, request, sizeof(request) - 1);
    if (n <= 0) { close(client_fd); return; }

    /* Parse first line: GET /path HTTP/1.1 */
    char method[16] = {0}, request_path[256] = {0}, path[256] = {0};
    sscanf(request, "%15s %255s", method, request_path);
    strlcpy(path, request_path, sizeof(path));
    char *query = strchr(path, '?');
    if (query)
        *query = '\0';

    if (strcmp(method, "OPTIONS") != 0 &&
        strcmp(path, "/") != 0 &&
        strcmp(path, "/menubar") != 0 &&
        strcmp(path, "/api/unlock") != 0 &&
        !http_check_auth(request, request_path)) {
        http_respond(client_fd, 401, "application/json",
                     unauthorized, strlen(unauthorized));
        close(client_fd);
        return;
    }

    if (strcmp(path, "/") == 0 || strcmp(path, "/menubar") == 0) {
        const char *html = get_menubar_html();
        http_respond(client_fd, 200, "text/html; charset=utf-8",
                     html, strlen(html));
    } else if (strcmp(path, "/api/status") == 0) {
        /* JSON status */
        char ids[32][64];
        int count = onvault_vault_list(ids, 32);
        char json[ONVAULT_IPC_MAX_MSG];
        int off = snprintf(json, sizeof(json),
            "{\"locked\":%s,\"vault_count\":%d,\"vaults\":[",
            g_master_key_loaded ? "false" : "true", count);
        for (int i = 0; i < count; i++) {
            char mount_dir[PATH_MAX], source[PATH_MAX];
            char escaped_id[128], escaped_source[PATH_MAX * 2];
            onvault_vault_get_paths(ids[i], NULL, mount_dir, source);
            int mounted = onvault_fuse_is_mounted(mount_dir);
            json_escape(escaped_id, sizeof(escaped_id), ids[i]);
            json_escape(escaped_source, sizeof(escaped_source), source);
            if (i > 0) off += snprintf(json + off, sizeof(json) - (size_t)off, ",");
            off += snprintf(json + off, sizeof(json) - (size_t)off,
                "{\"id\":\"%s\",\"source\":\"%s\",\"mounted\":%s}",
                escaped_id, escaped_source, mounted ? "true" : "false");
        }
        off += snprintf(json + off, sizeof(json) - (size_t)off, "]}");
        http_respond(client_fd, 200, "application/json", json, (size_t)off);
    } else if (strcmp(path, "/api/policies") == 0) {
        char buf[ONVAULT_IPC_MAX_MSG];
        if (g_master_key_loaded) {
            onvault_policy_show(buf, sizeof(buf));
        } else {
            snprintf(buf, sizeof(buf), "Locked — unlock to view policies");
        }
        http_respond(client_fd, 200, "text/plain", buf, strlen(buf));
    } else if (strcmp(path, "/api/denials") == 0) {
        /* Return recent denials as JSON */
        char json[ONVAULT_IPC_MAX_MSG];
        int off = snprintf(json, sizeof(json), "[");
        pthread_mutex_lock(&g_denial_lock);
        for (int i = 0; i < g_denial_count; i++) {
            recent_denial_t *d = &g_recent_denials[i];
            char escaped_process[512], escaped_path[PATH_MAX * 2];
            char escaped_file[PATH_MAX * 2], escaped_vault[128];
            if (i > 0) off += snprintf(json + off, sizeof(json) - (size_t)off, ",");
            json_escape(escaped_process, sizeof(escaped_process), d->process_name);
            json_escape(escaped_path, sizeof(escaped_path), d->process_path);
            json_escape(escaped_file, sizeof(escaped_file), d->file_path);
            json_escape(escaped_vault, sizeof(escaped_vault), d->vault_id);
            off += snprintf(json + off, sizeof(json) - (size_t)off,
                "{\"process\":\"%s\",\"path\":\"%s\",\"file\":\"%s\","
                "\"vault\":\"%s\",\"time\":%ld}",
                escaped_process, escaped_path, escaped_file,
                escaped_vault, (long)d->timestamp);
        }
        pthread_mutex_unlock(&g_denial_lock);
        off += snprintf(json + off, sizeof(json) - (size_t)off, "]");
        http_respond(client_fd, 200, "application/json", json, (size_t)off);
    } else if (strncmp(path, "/api/rules", 10) == 0 && strcmp(method, "GET") == 0) {
        /* /api/rules?vault=ssh */
        char *qp = strchr(request_path, '?');
        char vid[64] = {0};
        if (qp) {
            char *vp = strstr(qp, "vault=");
            if (vp) {
                vp += 6;
                size_t vl = 0;
                while (vp[vl] && vp[vl] != '&' && vp[vl] != ' ' && vl < 63) vl++;
                memcpy(vid, vp, vl);
            }
        }
        char buf[ONVAULT_IPC_MAX_MSG] = {0};
        if (vid[0] && g_master_key_loaded) {
            onvault_policy_get_rules(vid, buf, sizeof(buf));
        } else {
            snprintf(buf, sizeof(buf), "Locked or no vault specified");
        }
        http_respond(client_fd, 200, "text/plain", buf, strlen(buf));

    } else if (strcmp(method, "POST") == 0) {
        /* Parse POST body (after blank line) */
        char *body = strstr(request, "\r\n\r\n");
        if (body) body += 4;
        else body = "";

        char resp_json[ONVAULT_IPC_MAX_MSG] = {0};

        if (strcmp(path, "/api/vault/add") == 0) {
            /* Body: path to protect (requires unlocked daemon) */
            if (!g_master_key_loaded) {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":false,\"msg\":\"Unlock required. Click Lock/Unlock button first.\"}");
            } else if (body[0] == '\0') {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":false,\"msg\":\"Path required\"}");
            } else {
                /* Trim whitespace/newlines */
                char add_path[PATH_MAX];
                strlcpy(add_path, body, sizeof(add_path));
                size_t alen = strlen(add_path);
                while (alen > 0 && (add_path[alen-1] == '\n' || add_path[alen-1] == '\r' || add_path[alen-1] == ' '))
                    add_path[--alen] = '\0';

                /* Auto-create directory if it doesn't exist */
                struct stat add_st;
                if (stat(add_path, &add_st) != 0) {
                    if (mkdir(add_path, 0700) != 0) {
                        char escaped_path[PATH_MAX * 2];
                        json_escape(escaped_path, sizeof(escaped_path), add_path);
                        snprintf(resp_json, sizeof(resp_json),
                                 "{\"ok\":false,\"msg\":\"Cannot create directory: %s\"}",
                                 escaped_path);
                        http_respond(client_fd, 200, "application/json",
                                     resp_json, strlen(resp_json));
                        close(client_fd);
                        return;
                    }
                }

                int rc = onvault_vault_add(&g_master_key, add_path, NULL);
                if (rc == ONVAULT_OK) {
                    char vid[64];
                    char vault_dir[PATH_MAX];
                    char mount_dir[PATH_MAX];
                    char escaped_path[PATH_MAX * 2];
                    onvault_vault_id_from_path(add_path, vid, sizeof(vid));
                    apply_smart_defaults(vid);
                    onvault_vault_get_paths(vid, vault_dir, mount_dir, NULL);
                    rc = mount_vault_async(vid, vault_dir, mount_dir);
                    json_escape(escaped_path, sizeof(escaped_path), add_path);
                    if (rc == ONVAULT_OK) {
                        snprintf(resp_json, sizeof(resp_json),
                                 "{\"ok\":true,\"msg\":\"Vault added: %s\"}", escaped_path);
                    } else {
                        snprintf(resp_json, sizeof(resp_json),
                                 "{\"ok\":false,\"msg\":\"Vault added but mount failed: %s\"}",
                                 escaped_path);
                    }
                } else {
                    const char *err_msg = "Unknown error";
                    char escaped_path[PATH_MAX * 2];
                    if (rc == ONVAULT_ERR_NOT_FOUND) err_msg = "Path not found";
                    else if (rc == ONVAULT_ERR_ALREADY_EXISTS) err_msg = "Vault already exists";
                    else if (rc == ONVAULT_ERR_INVALID) err_msg = "Invalid path";
                    else if (rc == ONVAULT_ERR_IO) err_msg = "I/O error";
                    json_escape(escaped_path, sizeof(escaped_path), add_path);
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"%s: %s\"}", err_msg, escaped_path);
                }
            }
            http_audit_log(path, resp_json);
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else if (strcmp(path, "/api/allow") == 0 || strcmp(path, "/api/deny") == 0) {
            /* Body: process_path\nvault_id */
            int is_allow = (strcmp(path, "/api/allow") == 0);
            char proc[PATH_MAX] = {0}, vid[64] = {0};
            char *nl = strchr(body, '\n');
            if (nl && g_master_key_loaded) {
                size_t plen = (size_t)(nl - body);
                if (plen >= PATH_MAX) plen = PATH_MAX - 1;
                memcpy(proc, body, plen);
                /* Trim */
                while (plen > 0 && (proc[plen-1] == '\r' || proc[plen-1] == ' '))
                    proc[--plen] = '\0';
                strlcpy(vid, nl + 1, sizeof(vid));
                size_t vlen = strlen(vid);
                while (vlen > 0 && (vid[vlen-1] == '\n' || vid[vlen-1] == '\r' || vid[vlen-1] == ' '))
                    vid[--vlen] = '\0';

                int rc = onvault_policy_add_rule(vid, proc,
                    is_allow ? RULE_ALLOW : RULE_DENY);
                if (rc == ONVAULT_OK) {
                    char escaped_proc[PATH_MAX * 2], escaped_vid[128];
                    json_escape(escaped_proc, sizeof(escaped_proc), proc);
                    json_escape(escaped_vid, sizeof(escaped_vid), vid);
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":true,\"msg\":\"%s %s for %s\"}",
                             is_allow ? "Allowed" : "Denied", escaped_proc, escaped_vid);
                } else {
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Failed (err=%d)\"}", rc);
                }
            } else {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":false,\"msg\":\"Invalid request or locked\"}");
            }
            http_audit_log(path, resp_json);
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else if (strcmp(path, "/api/unlock") == 0) {
            /* Body: passphrase */
            if (g_master_key_loaded) {
                char token[65], escaped_token[128];
                if (http_generate_token() != ONVAULT_OK) {
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Failed to create session token\"}");
                    http_respond(client_fd, 200, "application/json",
                                 resp_json, strlen(resp_json));
                    close(client_fd);
                    return;
                }
                http_copy_token(token);
                http_reset_unlock_failures();
                json_escape(escaped_token, sizeof(escaped_token), token);
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":true,\"msg\":\"Already unlocked\",\"token\":\"%s\"}",
                         escaped_token);
            } else {
                char pass[256];
                time_t now = time(NULL);
                strlcpy(pass, body, sizeof(pass));
                size_t pl = strlen(pass);
                while (pl > 0 && (pass[pl-1] == '\n' || pass[pl-1] == '\r'))
                    pass[--pl] = '\0';

                if (http_unlock_locked_out(now)) {
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Too many attempts. Try again later.\"}");
                    http_respond(client_fd, 429, "application/json",
                                 resp_json, strlen(resp_json));
                    close(client_fd);
                    return;
                }

                onvault_key_t mk;
                memset(&mk, 0, sizeof(mk));
                int urc = onvault_auth_unlock(pass, &mk);
                onvault_memzero(pass, sizeof(pass));

                if (urc == ONVAULT_OK) {
                    char token[65], escaped_token[128];
                    int frc = finish_unlock(&mk);
                    onvault_key_wipe(&mk, sizeof(mk));
                    if (frc == ONVAULT_OK) {
                        if (http_generate_token() == ONVAULT_OK) {
                            http_copy_token(token);
                            http_reset_unlock_failures();
                            json_escape(escaped_token, sizeof(escaped_token), token);
                            snprintf(resp_json, sizeof(resp_json),
                                     "{\"ok\":true,\"msg\":\"Unlocked\",\"token\":\"%s\"}",
                                     escaped_token);
                        } else {
                            snprintf(resp_json, sizeof(resp_json),
                                     "{\"ok\":false,\"msg\":\"Failed to create session token\"}");
                        }
                    } else {
                        snprintf(resp_json, sizeof(resp_json),
                                 "{\"ok\":false,\"msg\":\"Unlock failed (err=%d)\"}", frc);
                    }
                } else {
                    onvault_key_wipe(&mk, sizeof(mk));
                    http_record_unlock_failure(now);
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Wrong passphrase\"}");
                }
            }
            http_audit_log(path, resp_json);
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else if (strcmp(path, "/api/lock") == 0) {
            /* Body: passphrase — verify before locking */
            char pass[256];
            strlcpy(pass, body, sizeof(pass));
            size_t pl = strlen(pass);
            while (pl > 0 && (pass[pl-1] == '\n' || pass[pl-1] == '\r'))
                pass[--pl] = '\0';

            int vrc = onvault_auth_verify_passphrase(pass);
            onvault_memzero(pass, sizeof(pass));

            if (vrc == ONVAULT_OK) {
                http_clear_token();
                g_running = 0;
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":true,\"msg\":\"Locked. Daemon stopping.\"}");
            } else {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":false,\"msg\":\"Wrong passphrase\"}");
            }
            http_audit_log(path, resp_json);
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else if (strcmp(path, "/api/vault/remove") == 0) {
            snprintf(resp_json, sizeof(resp_json),
                     "{\"ok\":false,\"msg\":\"Use CLI: onvault vault remove (passphrase required)\"}");
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else {
            http_respond(client_fd, 404, "text/plain", "Not Found", 9);
        }

    } else if (strcmp(method, "OPTIONS") == 0) {
        /* CORS preflight */
        http_respond(client_fd, 200, "text/plain", "", 0);

    } else {
        const char *msg = "Not Found";
        http_respond(client_fd, 404, "text/plain", msg, strlen(msg));
    }

    close(client_fd);
}

/* Thread wrapper for HTTP client handling */
static void *handle_http_client_thread(void *arg)
{
    int *fd_ptr = (int *)arg;
    int fd = *fd_ptr;
    free(fd_ptr);
    handle_http_client(fd);
    return NULL;
}

/* HTTP accept loop — runs on background thread */
static void *http_accept_loop(void *arg)
{
    (void)arg;
    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        fd_set fds;
        FD_ZERO(&fds);
        if (g_http_sock < 0) break;
        FD_SET(g_http_sock, &fds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ready = select(g_http_sock + 1, &fds, NULL, NULL, &tv);

        if (ready > 0) {
            int client_fd = accept(g_http_sock,
                                    (struct sockaddr *)&client_addr,
                                    &client_len);
            if (client_fd >= 0) {
                /* Handle each HTTP request in a new thread to avoid
                 * blocking on slow operations (Argon2id ~2-3s) */
                int *fd_ptr = malloc(sizeof(int));
                if (fd_ptr) {
                    *fd_ptr = client_fd;
                    pthread_t ht;
                    if (pthread_create(&ht, NULL, (void *(*)(void *))handle_http_client_thread, fd_ptr) == 0) {
                        pthread_detach(ht);
                    } else {
                        handle_http_client(client_fd);
                        free(fd_ptr);
                    }
                } else {
                    handle_http_client(client_fd);
                }
            }
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    fprintf(stderr, "onvaultd starting...\n");

    /* Install signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize crypto */
    onvault_crypto_init();

    /* Check if initialized (just check for salt file — no Keychain access) */
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK) {
        fprintf(stderr, "onvaultd: failed to access data directory\n");
        return 1;
    }

    /* PID lock — prevent multiple daemons */
    if (acquire_pid_lock(data_dir) != 0)
        return 1;

    {
        char salt_path[PATH_MAX];
        snprintf(salt_path, PATH_MAX, "%s/salt", data_dir);
        struct stat check_st;
        if (stat(salt_path, &check_st) != 0) {
            fprintf(stderr, "onvaultd: not initialized. Run 'onvault init' first.\n");
            release_pid_lock();
            return 1;
        }
    }

    /* Don't try to load key at startup — wait for explicit unlock via IPC.
     * This avoids Keychain/iCloud permission popups on daemon start. */
    fprintf(stderr, "onvaultd: waiting for unlock via 'onvault unlock'\n");

    /* Start IPC server */
    if (onvault_ipc_server_start() != ONVAULT_OK) {
        fprintf(stderr, "onvaultd: failed to start IPC server\n");
        return 1;
    }

    /* Initialize ESF (may fail without entitlement — non-fatal for dev) */
    int rc = onvault_esf_init();
    if (rc == ONVAULT_OK) {
        onvault_esf_set_deny_callback(on_deny);
        fprintf(stderr, "onvaultd: ESF agent active\n");
    } else {
        fprintf(stderr, "onvaultd: ESF not available (running without Layer 2)\n");
    }

    /* Start HTTP server for web-based menu bar UI */
    if (start_http_server() == 0) {
        fprintf(stderr, "onvaultd: web UI at http://127.0.0.1:%d/menubar\n", g_http_port);

        /* HTTP accept loop on background thread */
        pthread_t http_thread;
        pthread_create(&http_thread, NULL, http_accept_loop, NULL);
        pthread_detach(http_thread);
    } else {
        fprintf(stderr, "onvaultd: web UI not available\n");
    }

    fprintf(stderr, "onvaultd: ready\n");

    /* IPC accept loop (runs on background thread when menu bar is active) */
    int server_fd = onvault_ipc_server_fd();

    /* Check if we should show the menu bar (default: yes, unless --no-gui) */
    int show_gui = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-gui") == 0) {
            show_gui = 0;
            break;
        }
    }

    if (show_gui) {
        /* Run IPC accept loop on background thread */
        pthread_t ipc_thread;
        pthread_create(&ipc_thread, NULL, ipc_accept_loop, &server_fd);
        pthread_detach(ipc_thread);

        /* Menu bar runs on main thread (required by macOS for UI) */
        fprintf(stderr, "onvaultd: menu bar active\n");
        onvault_menubar_init(); /* Blocks — runs NSApp event loop */

        /* If we get here, menu bar was closed */
        g_running = 0;
    } else {
        /* Headless mode: IPC loop on main thread */
        ipc_accept_loop(&server_fd);
    }

    cleanup();
    fprintf(stderr, "onvaultd: stopped\n");
    return 0;
}

static const char *get_menubar_html(void)
{
    return
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "<meta charset=\"UTF-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
    "<title>onvault</title>\n"
    "<style>\n"
    ":root {\n"
    "    color-scheme: dark;\n"
    "    --bg: #0d0d0d;\n"
    "    --card: rgba(26, 26, 26, 0.96);\n"
    "    --card-hover: rgba(34, 34, 34, 0.98);\n"
    "    --border: rgba(255, 255, 255, 0.08);\n"
    "    --text: #ffffff;\n"
    "    --text-soft: rgba(255, 255, 255, 0.72);\n"
    "    --text-muted: rgba(255, 255, 255, 0.42);\n"
    "    --green: #22c55e;\n"
    "    --green-dim: rgba(34, 197, 94, 0.15);\n"
    "    --red: #ef4444;\n"
    "    --red-dim: rgba(239, 68, 68, 0.15);\n"
    "    --orange: #f59e0b;\n"
    "    --orange-dim: rgba(245, 158, 11, 0.15);\n"
    "    --blue: #3b82f6;\n"
    "    --blue-dim: rgba(59, 130, 246, 0.12);\n"
    "    --radius: 10px;\n"
    "    --radius-sm: 6px;\n"
    "}\n"
    "* { margin: 0; padding: 0; box-sizing: border-box; }\n"
    "body {\n"
    "    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', system-ui, sans-serif;\n"
    "    background: var(--bg); color: var(--text);\n"
    "    width: 300px; font-size: 12px;\n"
    "    -webkit-font-smoothing: antialiased;\n"
    "    overflow: hidden;\n"
    "}\n"
    ".header {\n"
    "    display: flex; align-items: center; justify-content: space-between;\n"
    "    padding: 14px 16px 10px; border-bottom: 1px solid var(--border);\n"
    "}\n"
    ".header .logo { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 13px; }\n"
    ".header .logo svg { width: 18px; height: 18px; }\n"
    ".badge { font-size: 10px; padding: 3px 8px; border-radius: 20px; font-weight: 500; }\n"
    ".badge.locked { background: var(--red-dim); color: var(--red); }\n"
    ".badge.unlocked { background: var(--green-dim); color: var(--green); }\n"
    ".section { padding: 8px 12px 4px; }\n"
    ".section-title { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); padding: 4px 4px 6px; }\n"
    ".vault-card { background: var(--card); border-radius: var(--radius); padding: 10px 12px; margin-bottom: 6px; border: 1px solid var(--border); cursor: pointer; transition: background 0.15s; }\n"
    ".vault-card:hover { background: var(--card-hover); }\n"
    ".vault-row { display: flex; align-items: center; justify-content: space-between; }\n"
    ".vault-name { font-weight: 600; font-size: 12px; display: flex; align-items: center; gap: 6px; }\n"
    ".vault-name .icon { font-size: 14px; }\n"
    ".vault-source { font-size: 10px; color: var(--text-muted); margin-top: 2px; font-family: 'SF Mono', Menlo, monospace; }\n"
    ".vault-status { font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: 500; }\n"
    ".vault-status.mounted { background: var(--green-dim); color: var(--green); }\n"
    ".vault-status.locked { background: var(--red-dim); color: var(--red); }\n"
    ".vault-detail { display: none; }\n"
    ".vault-card.expanded .vault-detail { display: block; padding-top: 8px; margin-top: 8px; border-top: 1px solid var(--border); }\n"
    ".vault-actions { display: flex; gap: 4px; flex-wrap: wrap; }\n"
    ".vault-actions button { font-size: 10px; padding: 4px 10px; border-radius: var(--radius-sm); border: 1px solid var(--border); background: transparent; color: var(--text-soft); cursor: pointer; transition: all 0.15s; font-family: inherit; }\n"
    ".vault-actions button:hover { background: var(--blue-dim); color: var(--blue); border-color: rgba(59, 130, 246, 0.3); }\n"
    ".vault-actions button.danger:hover { background: var(--red-dim); color: var(--red); border-color: rgba(239, 68, 68, 0.3); }\n"
    ".denial-card { background: var(--card); border-radius: var(--radius-sm); padding: 8px 10px; margin-bottom: 4px; border: 1px solid var(--border); font-size: 11px; display: flex; align-items: center; justify-content: space-between; }\n"
    ".denial-info { flex: 1; }\n"
    ".denial-proc { font-weight: 600; color: var(--orange); }\n"
    ".denial-file { font-size: 10px; color: var(--text-muted); font-family: 'SF Mono', Menlo, monospace; }\n"
    ".denial-time { font-size: 9px; color: var(--text-muted); white-space: nowrap; margin-left: 8px; }\n"
    ".denial-allow { font-size: 9px; padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(34, 197, 94, 0.3); background: var(--green-dim); color: var(--green); cursor: pointer; margin-left: 6px; font-family: inherit; }\n"
    ".action-bar { display: flex; gap: 6px; padding: 8px 12px; border-top: 1px solid var(--border); }\n"
    ".action-bar button { flex: 1; padding: 8px; border-radius: var(--radius-sm); border: 1px solid var(--border); background: var(--card); color: var(--text-soft); cursor: pointer; font-size: 11px; font-weight: 500; transition: all 0.15s; font-family: inherit; }\n"
    ".action-bar button:hover { background: var(--card-hover); color: var(--text); }\n"
    ".action-bar button.primary { background: var(--blue-dim); color: var(--blue); border-color: rgba(59, 130, 246, 0.25); }\n"
    ".action-bar button.primary:hover { background: rgba(59, 130, 246, 0.2); border-color: rgba(59, 130, 246, 0.4); }\n"
    ".footer { display: flex; align-items: center; justify-content: space-between; padding: 8px 16px; border-top: 1px solid var(--border); font-size: 10px; color: var(--text-muted); }\n"
    "@keyframes spin { to { transform: rotate(360deg); } }\n"
    ".spinning { animation: spin 1s linear infinite; display: inline-block; }\n"
    ".empty-state { text-align: center; padding: 20px 16px; }\n"
    ".empty-state .icon { font-size: 28px; margin-bottom: 8px; }\n"
    ".empty-state p { color: var(--text-muted); margin-bottom: 4px; font-size: 11px; }\n"
    "/* Toast notification (replaces browser alerts) */\n"
    ".toast { position: fixed; bottom: 40px; left: 50%; transform: translateX(-50%); background: var(--card); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 8px 16px; font-size: 11px; color: var(--green); opacity: 0; transition: opacity 0.3s; pointer-events: none; z-index: 100; white-space: nowrap; }\n"
    ".toast.show { opacity: 1; }\n"
    ".toast.error { color: var(--red); }\n"
    "/* Input row for inline allow/deny */\n"
    ".input-row { display: flex; gap: 4px; margin-top: 6px; }\n"
    ".input-row input { flex: 1; padding: 4px 8px; border-radius: var(--radius-sm); border: 1px solid var(--border); background: rgba(0,0,0,0.3); color: var(--text); font-size: 10px; font-family: 'SF Mono', Menlo, monospace; outline: none; }\n"
    ".input-row input:focus { border-color: rgba(59, 130, 246, 0.5); }\n"
    ".input-row button { padding: 4px 8px; border-radius: var(--radius-sm); border: 1px solid var(--border); background: var(--green-dim); color: var(--green); font-size: 10px; cursor: pointer; font-family: inherit; }\n"
    "/* Overlay panel */\n"
    ".panel-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.6); z-index: 200; }\n"
    ".panel-overlay.show { display: flex; align-items: center; justify-content: center; }\n"
    ".panel { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); width: 280px; max-height: 350px; overflow: hidden; }\n"
    ".panel-header { display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; border-bottom: 1px solid var(--border); font-weight: 600; font-size: 12px; }\n"
    ".panel-body { padding: 10px 12px; font-size: 10px; color: var(--text-soft); white-space: pre-wrap; font-family: 'SF Mono', Menlo, monospace; overflow-y: auto; max-height: 280px; margin: 0; }\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "\n"
    "<div class=\"header\">\n"
    "    <div class=\"logo\">\n"
    "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\">\n"
    "            <rect x=\"3\" y=\"11\" width=\"18\" height=\"11\" rx=\"2\" ry=\"2\"/>\n"
    "            <path d=\"M7 11V7a5 5 0 0 1 10 0v4\"/>\n"
    "        </svg>\n"
    "        onvault\n"
    "    </div>\n"
    "    <span class=\"badge locked\" id=\"statusBadge\">Locked</span>\n"
    "</div>\n"
    "\n"
    "<div id=\"vaultSection\" class=\"section\">\n"
    "    <div class=\"section-title\">Vaults</div>\n"
    "    <div id=\"vaultList\"></div>\n"
    "</div>\n"
    "\n"
    "<div id=\"denialSection\" class=\"section\" style=\"display:none\">\n"
    "    <div class=\"section-title\">Recent Denials</div>\n"
    "    <div id=\"denialList\"></div>\n"
    "</div>\n"
    "\n"
    "<div id=\"addVaultPanel\" style=\"display:none; padding: 8px 12px;\">\n"
    "    <div class=\"section-title\">Add Vault</div>\n"
    "    <div class=\"input-row\">\n"
    "        <input placeholder=\"~/.ssh or /path/to/dir\" id=\"addVaultInput\">\n"
    "        <button onclick=\"doAddVault()\">Protect</button>\n"
    "    </div>\n"
    "</div>\n"
    "\n"
    "<div class=\"action-bar\">\n"
    "    <button class=\"primary\" onclick=\"promptAddVault()\">+ Add Vault</button>\n"
    "    <button onclick=\"viewPolicies()\">Policies</button>\n"
    "    <button id=\"lockBtn\" onclick=\"doLockUnlock()\">Lock</button>\n"
    "    <button onclick=\"refresh()\" id=\"refreshBtn\">Refresh</button>\n"
    "</div>\n"
    "\n"
    "<div class=\"footer\">\n"
    "    <span>onvault 0.1.0</span>\n"
    "    <span id=\"lastUpdate\"></span>\n"
    "</div>\n"
    "\n"
    "<div class=\"toast\" id=\"toast\"></div>\n"
    "\n"
    "<div class=\"panel-overlay\" id=\"panelOverlay\" onclick=\"hidePanel()\">\n"
    "    <div class=\"panel\" onclick=\"event.stopPropagation()\">\n"
    "        <div class=\"panel-header\">\n"
    "            <span id=\"panelTitle\"></span>\n"
    "            <button onclick=\"hidePanel()\" style=\"background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:14px\">✕</button>\n"
    "        </div>\n"
    "        <pre class=\"panel-body\" id=\"panelBody\"></pre>\n"
    "        <div id=\"panelAuth\" style=\"display:none;padding:10px 12px;border-top:1px solid var(--border)\">\n"
    "            <div class=\"input-row\">\n"
    "                <input type=\"password\" placeholder=\"Passphrase\" id=\"panelPassInput\">\n"
    "                <button id=\"panelAuthBtn\" onclick=\"panelAuthSubmit()\">Confirm</button>\n"
    "            </div>\n"
    "        </div>\n"
    "    </div>\n"
    "</div>\n"
    "\n"
    "<script>\n"
    "var API = window.location.origin;\n"
    "var data = { locked: true, vault_count: 0, vaults: [] };\n"
    "var denials = [];\n"
    "var expandedVaults = {};\n"
    "var pendingAuthAction = null;\n"
    "var authToken = null;\n"
    "var _refreshInterval = null;\n"
    "\n"
    "function esc(s) {\n"
    "    if (!s) return '';\n"
    "    return String(s)\n"
    "        .replace(/&/g, '&amp;')\n"
    "        .replace(/</g, '&lt;')\n"
    "        .replace(/>/g, '&gt;')\n"
    "        .replace(/\"/g, '&quot;')\n"
    "        .replace(/'/g, '&#39;');\n"
    "}\n"
    "\n"
    "function toast(msg, isError) {\n"
    "    var t = document.getElementById('toast');\n"
    "    t.innerHTML = msg;\n"
    "    t.className = 'toast show' + (isError ? ' error' : '');\n"
    "    setTimeout(function() { t.className = 'toast'; }, 2500);\n"
    "}\n"
    "\n"
    "function fetchJSON(path) {\n"
    "    return fetch(API + path).then(function(r) {\n"
    "        return r.json().then(function(j) {\n"
    "            if (r.status === 401 || (j && !j.ok && j.msg && j.msg.indexOf('Unauthorized') >= 0)) {\n"
    "                authToken = null;\n"
    "            }\n"
    "            if (r.status === 401) throw j;\n"
    "            return j;\n"
    "        });\n"
    "    });\n"
    "}\n"
    "\n"
    "function fetchText(path) {\n"
    "    return fetch(API + path).then(function(r) {\n"
    "        return r.text().then(function(text) {\n"
    "            if (r.status === 401) {\n"
    "                authToken = null;\n"
    "                throw { ok: false, msg: text || 'Unauthorized' };\n"
    "            }\n"
    "            return text;\n"
    "        });\n"
    "    });\n"
    "}\n"
    "\n"
    "function postAPI(path, body) {\n"
    "    var headers = {};\n"
    "    if (authToken) headers['Authorization'] = 'Bearer ' + authToken;\n"
    "    return fetch(API + path, { method: 'POST', body: body, headers: headers }).then(function(r) {\n"
    "        return r.json().then(function(j) {\n"
    "            if (r.status === 401 || (j && !j.ok && j.msg && j.msg.indexOf('Unauthorized') >= 0)) {\n"
    "                authToken = null;\n"
    "            }\n"
    "            j._status = r.status;\n"
    "            return j;\n"
    "        });\n"
    "    });\n"
    "}\n"
    "\n"
    "function fetchData() {\n"
    "    var tokenParam = authToken ? '?token=' + encodeURIComponent(authToken) : '';\n"
    "    return Promise.all([\n"
    "        fetchJSON('/api/status' + tokenParam),\n"
    "        fetchJSON('/api/denials' + tokenParam)\n"
    "    ]).then(function(results) {\n"
    "        data = results[0];\n"
    "        denials = results[1];\n"
    "        render();\n"
    "    }).catch(function(err) {\n"
    "        if (err && err.msg && err.msg.indexOf('Unauthorized') >= 0) authToken = null;\n"
    "        data = { locked: true, vault_count: 0, vaults: [] };\n"
    "        denials = [];\n"
    "        render();\n"
    "    });\n"
    "}\n"
    "\n"
    "function timeAgo(ts) {\n"
    "    var s = Math.floor(Date.now() / 1000) - ts;\n"
    "    if (s < 60) return s + 's';\n"
    "    if (s < 3600) return Math.floor(s / 60) + 'm';\n"
    "    return Math.floor(s / 3600) + 'h';\n"
    "}\n"
    "\n"
    "function render() {\n"
    "    var badge = document.getElementById('statusBadge');\n"
    "    badge.className = 'badge ' + (data.locked ? 'locked' : 'unlocked');\n"
    "    badge.textContent = data.locked ? 'Locked' : data.vault_count + ' vault(s)';\n"
    "\n"
    "    var vl = document.getElementById('vaultList');\n"
    "    if (data.vaults.length === 0) {\n"
    "        vl.innerHTML = '<div class=\"empty-state\"><div class=\"icon\">' + (data.locked ? '🔒' : '🛡️') + '</div>' +\n"
    "            '<p>' + (data.locked ? 'Locked — click Unlock below.' : 'No vaults yet. Click + Add Vault.') + '</p></div>';\n"
    "    } else {\n"
    "        vl.innerHTML = data.vaults.map(function(v) {\n"
    "            var exp = expandedVaults[v.id] ? ' expanded' : '';\n"
    "            var vidArg = encodeURIComponent(v.id);\n"
    "            return '<div class=\"vault-card' + exp + '\" onclick=\"toggle(decodeURIComponent(\\'' + vidArg + '\\'))\">' +\n"
    "                '<div class=\"vault-row\"><div class=\"vault-name\"><span class=\"icon\">' +\n"
    "                (v.mounted ? '🔓' : '🔒') + '</span>' + esc(v.id) + '</div>' +\n"
    "                '<span class=\"vault-status ' + (v.mounted ? 'mounted' : 'locked') + '\">' +\n"
    "                (v.mounted ? 'Active' : 'Locked') + '</span></div>' +\n"
    "                '<div class=\"vault-source\">' + esc(v.source) + '</div>' +\n"
    "                '<div class=\"vault-detail\">' +\n"
    "                '<div class=\"vault-actions\">' +\n"
    "                '<button onclick=\"event.stopPropagation();viewRules(decodeURIComponent(\\'' + vidArg + '\\'))\">Rules</button>' +\n"
    "                '<button onclick=\"event.stopPropagation();showInput(\\'allow\\',decodeURIComponent(\\'' + vidArg + '\\'))\">Allow</button>' +\n"
    "                '<button onclick=\"event.stopPropagation();showInput(\\'deny\\',decodeURIComponent(\\'' + vidArg + '\\'))\">Deny</button>' +\n"
    "                '<button class=\"danger\" onclick=\"event.stopPropagation();toast(\\'Use CLI: onvault vault remove ' + esc(v.id) + '\\')\">Remove</button>' +\n"
    "                '</div>' +\n"
    "                '<div class=\"input-row\" id=\"allow-' + v.id + '\" style=\"display:none\">' +\n"
    "                '<input placeholder=\"/usr/bin/process\" id=\"allow-input-' + v.id + '\">' +\n"
    "                '<button onclick=\"event.stopPropagation();doRule(\\'allow\\',decodeURIComponent(\\'' + vidArg + '\\'))\">Allow</button>' +\n"
    "                '</div>' +\n"
    "                '<div class=\"input-row\" id=\"deny-' + v.id + '\" style=\"display:none\">' +\n"
    "                '<input placeholder=\"/usr/bin/process\" id=\"deny-input-' + v.id + '\">' +\n"
    "                '<button onclick=\"event.stopPropagation();doRule(\\'deny\\',decodeURIComponent(\\'' + vidArg + '\\'))\">Deny</button>' +\n"
    "                '</div></div>';\n"
    "        }).join('');\n"
    "    }\n"
    "\n"
    "    var ds = document.getElementById('denialSection');\n"
    "    var dl = document.getElementById('denialList');\n"
    "    if (denials.length > 0) {\n"
    "        ds.style.display = 'block';\n"
    "        dl.innerHTML = denials.slice(-5).reverse().map(function(d) {\n"
    "            var pathArg = encodeURIComponent(d.path || '');\n"
    "            var vaultArg = encodeURIComponent(d.vault || '');\n"
    "            return '<div class=\"denial-card\"><div class=\"denial-info\">' +\n"
    "                '<span class=\"denial-proc\">' + esc(d.process) + '</span> \\u2192 ' + esc(d.vault) +\n"
    "                '<div class=\"denial-file\">' + esc(d.file) + '</div></div>' +\n"
    "                '<span class=\"denial-time\">' + timeAgo(d.time) + '</span>' +\n"
    "                '<button class=\"denial-allow\" onclick=\"quickAllow(decodeURIComponent(\\'' + pathArg + '\\'),decodeURIComponent(\\'' + vaultArg + '\\'))\">Allow</button></div>';\n"
    "        }).join('');\n"
    "    } else { ds.style.display = 'none'; }\n"
    "\n"
    "    var lockBtn = document.getElementById('lockBtn');\n"
    "    if (lockBtn) lockBtn.textContent = data.locked ? 'Unlock' : 'Lock';\n"
    "\n"
    "    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});\n"
    "    notifyResize();\n"
    "}\n"
    "\n"
    "function toggle(id) {\n"
    "    expandedVaults[id] = !expandedVaults[id];\n"
    "    render();\n"
    "}\n"
    "\n"
    "function showInput(type, id) {\n"
    "    var el = document.getElementById(type + '-' + id);\n"
    "    var other = type === 'allow' ? 'deny' : 'allow';\n"
    "    el.style.display = el.style.display === 'none' ? 'flex' : 'none';\n"
    "    document.getElementById(other + '-' + id).style.display = 'none';\n"
    "}\n"
    "\n"
    "function doRule(type, id) {\n"
    "    var input = document.getElementById(type + '-input-' + id);\n"
    "    var proc = input.value.trim();\n"
    "    if (!proc) return;\n"
    "    input.value = '';\n"
    "    document.getElementById(type + '-' + id).style.display = 'none';\n"
    "    postAPI('/api/' + type, proc + '\\n' + id).then(function(j) {\n"
    "        toast(esc(j.msg), !j.ok);\n"
    "        fetchData();\n"
    "    }).catch(function() { toast('Failed', true); });\n"
    "}\n"
    "\n"
    "function promptAddVault() {\n"
    "    var panel = document.getElementById('addVaultPanel');\n"
    "    panel.style.display = panel.style.display === 'none' ? 'block' : 'none';\n"
    "    if (panel.style.display === 'block') document.getElementById('addVaultInput').focus();\n"
    "    notifyResize();\n"
    "}\n"
    "\n"
    "function doAddVault() {\n"
    "    var input = document.getElementById('addVaultInput');\n"
    "    var path = input.value.trim();\n"
    "    if (!path) return;\n"
    "    input.value = '';\n"
    "    document.getElementById('addVaultPanel').style.display = 'none';\n"
    "    postAPI('/api/vault/add', path).then(function(j) {\n"
    "        toast(esc(j.msg), !j.ok);\n"
    "        fetchData();\n"
    "    }).catch(function() { toast('Failed to add vault', true); });\n"
    "}\n"
    "\n"
    "function viewRules(id) {\n"
    "    var tokenParam = authToken ? '&token=' + encodeURIComponent(authToken) : '';\n"
    "    fetchText('/api/rules?vault=' + encodeURIComponent(id) + tokenParam).then(function(text) {\n"
    "        showPanel('Rules: ' + id, text);\n"
    "    }).catch(function(err) {\n"
    "        toast(esc(err && err.msg ? err.msg : 'Failed to load rules'), true);\n"
    "    });\n"
    "}\n"
    "\n"
    "function quickAllow(proc, vault) {\n"
    "    postAPI('/api/allow', proc + '\\n' + vault).then(function(j) {\n"
    "        toast(esc(j.msg), !j.ok);\n"
    "        fetchData();\n"
    "    }).catch(function() { toast('Failed', true); });\n"
    "}\n"
    "\n"
    "function refresh() {\n"
    "    var btn = document.getElementById('refreshBtn');\n"
    "    btn.innerHTML = '<span class=\"spinning\">\\u21bb</span>';\n"
    "    fetchData().then(function() { btn.textContent = 'Refresh'; });\n"
    "}\n"
    "\n"
    "function doLockUnlock() {\n"
    "    if (data.locked) {\n"
    "        showPanel('Unlock', 'Enter your passphrase to unlock all vaults.');\n"
    "        pendingAuthAction = 'unlock';\n"
    "    } else {\n"
    "        showPanel('Lock All Vaults', 'Enter your passphrase to lock and unmount all vaults.');\n"
    "        pendingAuthAction = 'lock';\n"
    "    }\n"
    "    document.getElementById('panelAuth').style.display = 'block';\n"
    "    document.getElementById('panelPassInput').value = '';\n"
    "    setTimeout(function() { document.getElementById('panelPassInput').focus(); }, 100);\n"
    "}\n"
    "\n"
    "function panelAuthSubmit() {\n"
    "    var pass = document.getElementById('panelPassInput').value;\n"
    "    if (!pass) return;\n"
    "    document.getElementById('panelPassInput').value = '';\n"
    "    var action = pendingAuthAction;\n"
    "    pendingAuthAction = null;\n"
    "\n"
    "    /* Show loading state */\n"
    "    document.getElementById('panelBody').textContent = 'Authenticating...';\n"
    "    document.getElementById('panelAuth').style.display = 'none';\n"
    "\n"
    "    postAPI('/api/' + action, pass).then(function(j) {\n"
    "        if (action === 'unlock' && j.ok && j.token) {\n"
    "            authToken = j.token;\n"
    "        }\n"
    "        if (action === 'lock' && j.ok) {\n"
    "            authToken = null;\n"
    "        }\n"
    "        toast(esc(j.msg), !j.ok);\n"
    "        hidePanel();\n"
    "        fetchData();\n"
    "    }).catch(function() {\n"
    "        toast('Failed — try again', true);\n"
    "        hidePanel();\n"
    "    });\n"
    "}\n"
    "\n"
    "function viewPolicies() {\n"
    "    var tokenParam = authToken ? '?token=' + encodeURIComponent(authToken) : '';\n"
    "    fetchText('/api/policies' + tokenParam).then(function(text) {\n"
    "        showPanel('All Policies', text);\n"
    "    }).catch(function(err) {\n"
    "        toast(esc(err && err.msg ? err.msg : 'Failed to load policies'), true);\n"
    "    });\n"
    "}\n"
    "\n"
    "function showPanel(title, body) {\n"
    "    document.getElementById('panelTitle').textContent = title;\n"
    "    document.getElementById('panelBody').textContent = body || '';\n"
    "    document.getElementById('panelAuth').style.display = 'none';\n"
    "    document.getElementById('panelOverlay').className = 'panel-overlay show';\n"
    "}\n"
    "\n"
    "function hidePanel() {\n"
    "    document.getElementById('panelOverlay').className = 'panel-overlay';\n"
    "}\n"
    "\n"
    "function notifyResize() {\n"
    "    try { window.webkit.messageHandlers.resize.postMessage(document.body.scrollHeight); } catch(e) {}\n"
    "}\n"
    "\n"
    "fetchData();\n"
    "if (_refreshInterval) clearInterval(_refreshInterval);\n"
    "_refreshInterval = setInterval(fetchData, 5000);\n"
    "</script>\n"
    "</body>\n"
    "</html>\n"
    ;
}

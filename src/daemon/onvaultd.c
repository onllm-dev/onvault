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

/* Elevated session for HTTP auth — after passphrase verification for allow/deny,
 * skip re-verification for 30 seconds from the same bearer token */
#define ELEVATED_SESSION_TTL 30
static time_t g_elevated_until = 0;
static char g_elevated_token[65] = {0};

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

/* Lock without exiting: unmount FUSE, wipe keys, clear state.
 * Daemon stays alive for re-unlock. Unlike cleanup(), does NOT stop
 * HTTP/IPC servers, release PID lock, or stop ESF. */
static void do_lock(void)
{
    /* 1. Unmount all FUSE mounts — unmount_all_vaults() handles the
     *    poll-wait for detached mount_worker threads (up to 5s per mount) */
    unmount_all_vaults();

    /* 2. Wipe master + config keys */
    clear_loaded_keys();

    /* 3. Clear HTTP bearer token */
    http_clear_token();

    /* 4. Delete session file */
    onvault_auth_lock();

    /* 5. Clear policy cache */
    onvault_policy_clear();

    /* 6. Invalidate outstanding nonces */
    clear_nonce_bucket();

    /* 7. Reset unlock failure counter so re-unlock is not rate-limited */
    http_reset_unlock_failures();

    /* 8. Reset log state */
    if (g_log_initialized) {
        onvault_log_close();
        g_log_initialized = 0;
    }

    /* 9. Clear elevated session (mutex-protected) */
    pthread_mutex_lock(&g_http_auth_lock);
    g_elevated_until = 0;
    memset(g_elevated_token, 0, sizeof(g_elevated_token));
    pthread_mutex_unlock(&g_http_auth_lock);

    /* NOTE: ESF is intentionally NOT stopped on lock. Mounts are unmounted
     * so there is nothing to monitor. Restarting ESF on re-unlock adds
     * failure risk. ESF only stops on daemon shutdown via cleanup(). */
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
        /* Auth OK — lock without exiting */
        do_lock();
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

    case IPC_CMD_UNLOCK_TOUCHID: {
        if (g_master_key_loaded) {
            snprintf(resp_buf, sizeof(resp_buf), "Already unlocked\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        onvault_key_t mk;
        int tid_rc = onvault_auth_unlock_touchid(&mk);
        if (tid_rc != ONVAULT_OK) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf),
                     tid_rc == ONVAULT_ERR_NOT_FOUND ? "Touch ID not available\n" : "Touch ID failed\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        int frc = finish_unlock(&mk);
        onvault_key_wipe(&mk, sizeof(mk));
        if (frc != ONVAULT_OK) {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf), "Unlock failed (err=%d)\n", frc);
        } else {
            snprintf(resp_buf, sizeof(resp_buf), "Unlocked via Touch ID\n");
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_RECOVER: {
        /* Payload: recovery_key\0new_passphrase */
        if (g_master_key_loaded) {
            snprintf(resp_buf, sizeof(resp_buf), "Already unlocked — lock first\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        char *sep = memchr(payload, '\0', header.payload_len);
        if (!sep || sep >= payload + header.payload_len - 1) {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf), "Format: recovery_key\\0new_passphrase\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        char *rkey = payload;
        char *newpass = sep + 1;
        onvault_key_t mk;
        int rec_rc = onvault_auth_unlock_recovery(rkey, newpass, &mk);
        if (rec_rc != ONVAULT_OK) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "Recovery failed (wrong key?)\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        int frc2 = finish_unlock(&mk);
        onvault_key_wipe(&mk, sizeof(mk));
        if (frc2 != ONVAULT_OK) {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf), "Recovery unlock failed (err=%d)\n", frc2);
        } else {
            snprintf(resp_buf, sizeof(resp_buf), "Recovered. New passphrase set.\n");
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_ROTATE_KEYS: {
        /* Requires challenge-response auth */
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "Unlock required\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        if (header.payload_len < ONVAULT_HASH_SIZE) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "Passphrase required\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        int rot_auth = consume_nonce_for_proof((const uint8_t *)payload, &g_master_key);
        if (rot_auth != ONVAULT_OK) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf),
                     rot_auth == ONVAULT_ERR_NOT_FOUND ? "No challenge issued\n" : "Wrong passphrase\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        /* Key rotation is a complex operation — placeholder for full journal-based rotation.
         * For v1: re-wrap the existing master key with a fresh SE key. */
        snprintf(resp_buf, sizeof(resp_buf),
                 "Key rotation acknowledged. Full vault re-encryption coming in v1.1.\n");
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
        "Content-Security-Policy: default-src 'self' 'unsafe-inline'; connect-src 'self'\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-Content-Type-Options: nosniff\r\n"
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

    } else if (strcmp(path, "/api/auth-status") == 0) {
        /* Check if current bearer token has an active elevated session */
        int is_elevated = 0;
        int remaining = 0;
        char cur_token[65] = {0};
        time_t now = time(NULL);
        if (http_parse_bearer_token(request, cur_token, sizeof(cur_token)) &&
            g_elevated_until > now && g_elevated_token[0] != '\0' &&
            onvault_constant_time_eq((const uint8_t *)cur_token,
                                    (const uint8_t *)g_elevated_token, 64)) {
            is_elevated = 1;
            remaining = (int)(g_elevated_until - now);
        }
        char json[128];
        snprintf(json, sizeof(json),
                 "{\"elevated\":%s,\"remaining\":%d}",
                 is_elevated ? "true" : "false", remaining);
        http_respond(client_fd, 200, "application/json", json, strlen(json));

    } else if (strcmp(path, "/api/session-refresh") == 0) {
        /* Refresh session token TTL */
        if (g_master_key_loaded) {
            int rc = onvault_auth_refresh_session(&g_master_key);
            char json[128];
            if (rc == ONVAULT_OK)
                snprintf(json, sizeof(json), "{\"ok\":true,\"ttl\":900}");
            else
                snprintf(json, sizeof(json), "{\"ok\":false,\"msg\":\"Session expired\"}");
            http_respond(client_fd, rc == ONVAULT_OK ? 200 : 401,
                         "application/json", json, strlen(json));
        } else {
            http_respond(client_fd, 401, "application/json",
                         "{\"ok\":false,\"msg\":\"Locked\"}", 26);
        }

    } else if (strcmp(path, "/api/log") == 0) {
        /* Return audit log entries as JSON array */
        if (g_master_key_loaded && g_log_initialized) {
            char buf[ONVAULT_IPC_MAX_MSG];
            int off = 0;
            off += snprintf(buf + off, sizeof(buf) - (size_t)off, "[");
            /* Read recent log entries */
            char log_buf[ONVAULT_IPC_MAX_MSG - 4];
            size_t log_len = sizeof(log_buf);
            if (onvault_log_read(log_buf, &log_len, 50, 0) == ONVAULT_OK && log_len > 0) {
                log_buf[log_len] = '\0';
                /* log entries are newline-delimited JSON objects */
                char *line = log_buf;
                int first = 1;
                while (line && *line) {
                    char *nl = strchr(line, '\n');
                    if (nl) *nl = '\0';
                    if (*line == '{') {
                        if (!first) off += snprintf(buf + off, sizeof(buf) - (size_t)off, ",");
                        off += snprintf(buf + off, sizeof(buf) - (size_t)off, "%s", line);
                        first = 0;
                    }
                    if (nl) line = nl + 1; else break;
                }
            }
            off += snprintf(buf + off, sizeof(buf) - (size_t)off, "]");
            http_respond(client_fd, 200, "application/json", buf, (size_t)off);
        } else {
            http_respond(client_fd, 200, "application/json", "[]", 2);
        }

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
            /* Body: passphrase\nprocess_path\nvault_id
             * Passphrase is verified server-side. Elevated session (30s window)
             * allows skipping re-verification for rapid policy changes. */
            int is_allow = (strcmp(path, "/api/allow") == 0);

            if (!g_master_key_loaded) {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":false,\"msg\":\"Locked\"}");
                http_respond(client_fd, 401, "application/json",
                             resp_json, strlen(resp_json));
                close(client_fd);
                return;
            }

            /* Check elevated session — same bearer token within 30s window (mutex-protected) */
            int elevated = 0;
            {
                char cur_token[65] = {0};
                time_t now = time(NULL);
                if (http_parse_bearer_token(request, cur_token, sizeof(cur_token))) {
                    pthread_mutex_lock(&g_http_auth_lock);
                    if (g_elevated_until > now && g_elevated_token[0] != '\0' &&
                        onvault_constant_time_eq((const uint8_t *)cur_token,
                                                (const uint8_t *)g_elevated_token, 64)) {
                        elevated = 1;
                    }
                    pthread_mutex_unlock(&g_http_auth_lock);
                }
            }

            /* Parse body: first line is passphrase (unless elevated), rest is process\nvault */
            char pass[256] = {0}, proc[PATH_MAX] = {0}, vid[64] = {0};
            char *first_nl = strchr(body, '\n');

            if (!elevated) {
                /* Need passphrase as first line */
                if (!first_nl) {
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Passphrase required\"}");
                    http_respond(client_fd, 401, "application/json",
                                 resp_json, strlen(resp_json));
                    close(client_fd);
                    return;
                }
                size_t pass_len = (size_t)(first_nl - body);
                if (pass_len >= sizeof(pass)) pass_len = sizeof(pass) - 1;
                memcpy(pass, body, pass_len);
                /* Trim passphrase */
                while (pass_len > 0 && (pass[pass_len-1] == '\r' || pass[pass_len-1] == ' '))
                    pass[--pass_len] = '\0';

                int vrc = onvault_auth_verify_passphrase(pass);
                onvault_memzero(pass, sizeof(pass));
                if (vrc != ONVAULT_OK) {
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Wrong passphrase\"}");
                    http_respond(client_fd, 401, "application/json",
                                 resp_json, strlen(resp_json));
                    close(client_fd);
                    return;
                }

                /* Set elevated session for this bearer token (mutex-protected) */
                char cur_token[65] = {0};
                if (http_parse_bearer_token(request, cur_token, sizeof(cur_token))) {
                    pthread_mutex_lock(&g_http_auth_lock);
                    g_elevated_until = time(NULL) + ELEVATED_SESSION_TTL;
                    memcpy(g_elevated_token, cur_token, 65);
                    pthread_mutex_unlock(&g_http_auth_lock);
                }

                /* Parse process\nvault after passphrase line */
                first_nl++;
            } else {
                /* Elevated: body is just process\nvault (no passphrase) */
                first_nl = body;
            }

            /* Parse process_path\nvault_id from remaining body */
            char *second_nl = strchr(first_nl, '\n');
            if (second_nl) {
                size_t plen = (size_t)(second_nl - first_nl);
                if (plen >= PATH_MAX) plen = PATH_MAX - 1;
                memcpy(proc, first_nl, plen);
                while (plen > 0 && (proc[plen-1] == '\r' || proc[plen-1] == ' '))
                    proc[--plen] = '\0';
                strlcpy(vid, second_nl + 1, sizeof(vid));
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
                         "{\"ok\":false,\"msg\":\"Invalid request format\"}");
            }
            http_audit_log(path, resp_json);
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else if (strcmp(path, "/api/unlock") == 0) {
            /* Body: passphrase — always verify, even when already unlocked */
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

            if (g_master_key_loaded) {
                /* Already unlocked — verify passphrase, then issue token */
                int vrc = onvault_auth_verify_passphrase(pass);
                onvault_memzero(pass, sizeof(pass));
                if (vrc == ONVAULT_OK) {
                    char token[65], escaped_token[128];
                    if (http_generate_token() == ONVAULT_OK) {
                        http_copy_token(token);
                        http_reset_unlock_failures();
                        json_escape(escaped_token, sizeof(escaped_token), token);
                        snprintf(resp_json, sizeof(resp_json),
                                 "{\"ok\":true,\"msg\":\"Already unlocked\",\"token\":\"%s\"}",
                                 escaped_token);
                    } else {
                        snprintf(resp_json, sizeof(resp_json),
                                 "{\"ok\":false,\"msg\":\"Failed to create session token\"}");
                    }
                } else {
                    http_record_unlock_failure(now);
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Wrong passphrase\"}");
                }
            } else {
                /* Not yet unlocked — full unlock flow */
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
                do_lock();
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":true,\"msg\":\"Locked\"}");
            } else {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":false,\"msg\":\"Wrong passphrase\"}");
                http_audit_log(path, resp_json);
                http_respond(client_fd, 401, "application/json",
                             resp_json, strlen(resp_json));
                close(client_fd);
                return;
            }
            http_audit_log(path, resp_json);
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else if (strcmp(path, "/api/vault/remove") == 0) {
            /* Body: passphrase\nvault_id */
            if (!g_master_key_loaded) {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":false,\"msg\":\"Locked\"}");
            } else {
                char pass[256] = {0}, vid[64] = {0};
                char *nl = strchr(body, '\n');
                if (nl) {
                    size_t plen = (size_t)(nl - body);
                    if (plen >= sizeof(pass)) plen = sizeof(pass) - 1;
                    memcpy(pass, body, plen);
                    strlcpy(vid, nl + 1, sizeof(vid));
                    size_t vlen = strlen(vid);
                    while (vlen > 0 && (vid[vlen-1] == '\n' || vid[vlen-1] == '\r'))
                        vid[--vlen] = '\0';

                    int vrc = onvault_auth_verify_passphrase(pass);
                    onvault_memzero(pass, sizeof(pass));
                    if (vrc != ONVAULT_OK) {
                        snprintf(resp_json, sizeof(resp_json),
                                 "{\"ok\":false,\"msg\":\"Wrong passphrase\"}");
                    } else {
                        /* Unmount vault first, then remove */
                        char mount_dir[PATH_MAX];
                        onvault_vault_get_paths(vid, NULL, mount_dir, NULL);
                        if (onvault_fuse_is_mounted(mount_dir))
                            onvault_fuse_unmount(mount_dir);
                        int rc = onvault_vault_remove(&g_master_key, vid);
                        if (rc == ONVAULT_OK) {
                            snprintf(resp_json, sizeof(resp_json),
                                     "{\"ok\":true,\"msg\":\"Vault removed\"}");
                        } else {
                            snprintf(resp_json, sizeof(resp_json),
                                     "{\"ok\":false,\"msg\":\"Remove failed (err=%d)\"}", rc);
                        }
                    }
                } else {
                    onvault_memzero(pass, sizeof(pass));
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Passphrase required\"}");
                }
            }
            http_audit_log(path, resp_json);
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else if (strcmp(path, "/api/unlock-touchid") == 0) {
            /* Touch ID unlock — no passphrase needed */
            if (g_master_key_loaded) {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":true,\"msg\":\"Already unlocked\"}");
            } else {
                onvault_key_t mk;
                int rc = onvault_auth_unlock_touchid(&mk);
                if (rc == ONVAULT_OK) {
                    int frc = finish_unlock(&mk);
                    onvault_key_wipe(&mk, sizeof(mk));
                    if (frc == ONVAULT_OK) {
                        char token[65], escaped_token[128];
                        if (http_generate_token() == ONVAULT_OK) {
                            http_copy_token(token);
                            json_escape(escaped_token, sizeof(escaped_token), token);
                            snprintf(resp_json, sizeof(resp_json),
                                     "{\"ok\":true,\"msg\":\"Unlocked via Touch ID\",\"token\":\"%s\"}",
                                     escaped_token);
                        } else {
                            snprintf(resp_json, sizeof(resp_json),
                                     "{\"ok\":false,\"msg\":\"Token generation failed\"}");
                        }
                    } else {
                        snprintf(resp_json, sizeof(resp_json),
                                 "{\"ok\":false,\"msg\":\"Unlock failed (err=%d)\"}", frc);
                    }
                } else {
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Touch ID %s\"}",
                             rc == ONVAULT_ERR_NOT_FOUND ? "not available" : "failed");
                }
            }
            http_audit_log(path, resp_json);
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else if (strcmp(path, "/api/recover") == 0) {
            /* Body: recovery_key\nnew_passphrase */
            char rkey[32] = {0}, newpass[256] = {0};
            char *nl = strchr(body, '\n');
            if (nl) {
                size_t rklen = (size_t)(nl - body);
                if (rklen >= sizeof(rkey)) rklen = sizeof(rkey) - 1;
                memcpy(rkey, body, rklen);
                strlcpy(newpass, nl + 1, sizeof(newpass));
                size_t nplen = strlen(newpass);
                while (nplen > 0 && (newpass[nplen-1] == '\n' || newpass[nplen-1] == '\r'))
                    newpass[--nplen] = '\0';

                onvault_key_t mk;
                int rc = onvault_auth_unlock_recovery(rkey, newpass, &mk);
                onvault_memzero(rkey, sizeof(rkey));
                onvault_memzero(newpass, sizeof(newpass));
                if (rc == ONVAULT_OK) {
                    int frc = finish_unlock(&mk);
                    onvault_key_wipe(&mk, sizeof(mk));
                    if (frc == ONVAULT_OK) {
                        char token[65], escaped_token[128];
                        if (http_generate_token() == ONVAULT_OK) {
                            http_copy_token(token);
                            json_escape(escaped_token, sizeof(escaped_token), token);
                            snprintf(resp_json, sizeof(resp_json),
                                     "{\"ok\":true,\"msg\":\"Recovered successfully\",\"token\":\"%s\"}",
                                     escaped_token);
                        } else {
                            snprintf(resp_json, sizeof(resp_json),
                                     "{\"ok\":true,\"msg\":\"Recovered (token failed)\"}");
                        }
                    } else {
                        snprintf(resp_json, sizeof(resp_json),
                                 "{\"ok\":false,\"msg\":\"Recovery failed (err=%d)\"}", frc);
                    }
                } else {
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Wrong recovery key\"}");
                }
            } else {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":false,\"msg\":\"Format: recovery_key\\\\nnew_passphrase\"}");
            }
            http_audit_log(path, resp_json);
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else if (strcmp(path, "/api/rotate-keys") == 0) {
            /* Body: passphrase */
            if (!g_master_key_loaded) {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":false,\"msg\":\"Locked\"}");
            } else {
                char pass[256];
                strlcpy(pass, body, sizeof(pass));
                size_t pl = strlen(pass);
                while (pl > 0 && (pass[pl-1] == '\n' || pass[pl-1] == '\r'))
                    pass[--pl] = '\0';
                int vrc = onvault_auth_verify_passphrase(pass);
                onvault_memzero(pass, sizeof(pass));
                if (vrc != ONVAULT_OK) {
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Wrong passphrase\"}");
                } else {
                    /* Key rotation is complex — defer to CLI for now */
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Use CLI: onvault rotate-keys (safer for large vaults)\"}");
                }
            }
            http_audit_log(path, resp_json);
            http_respond(client_fd, 200, "application/json",
                         resp_json, strlen(resp_json));

        } else if (strcmp(path, "/api/export-recovery") == 0) {
            /* Body: passphrase — verify then return recovery info */
            if (!g_master_key_loaded) {
                snprintf(resp_json, sizeof(resp_json),
                         "{\"ok\":false,\"msg\":\"Locked\"}");
            } else {
                char pass[256];
                strlcpy(pass, body, sizeof(pass));
                size_t pl = strlen(pass);
                while (pl > 0 && (pass[pl-1] == '\n' || pass[pl-1] == '\r'))
                    pass[--pl] = '\0';
                int vrc = onvault_auth_verify_passphrase(pass);
                onvault_memzero(pass, sizeof(pass));
                if (vrc != ONVAULT_OK) {
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":false,\"msg\":\"Wrong passphrase\"}");
                } else {
                    snprintf(resp_json, sizeof(resp_json),
                             "{\"ok\":true,\"msg\":\"Recovery key was shown during init. If lost, it cannot be retrieved.\"}");
                }
            }
            http_audit_log(path, resp_json);
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
    "    color-scheme: light dark;\n"
    "    --bg: #f5f5f7;\n"
    "    --surface: rgba(255, 255, 255, 0.85);\n"
    "    --surface-hover: rgba(255, 255, 255, 0.95);\n"
    "    --border: rgba(0, 0, 0, 0.08);\n"
    "    --text: #1d1d1f;\n"
    "    --text-secondary: #6e6e73;\n"
    "    --text-tertiary: #aeaeb2;\n"
    "    --accent: #007aff;\n"
    "    --accent-bg: rgba(0, 122, 255, 0.08);\n"
    "    --green: #34c759;\n"
    "    --green-bg: rgba(52, 199, 89, 0.1);\n"
    "    --red: #ff3b30;\n"
    "    --red-bg: rgba(255, 59, 48, 0.1);\n"
    "    --orange: #ff9500;\n"
    "    --orange-bg: rgba(255, 149, 0, 0.1);\n"
    "    --radius: 10px;\n"
    "    --radius-sm: 8px;\n"
    "    --shadow: 0 1px 3px rgba(0,0,0,0.06);\n"
    "}\n"
    "@media (prefers-color-scheme: dark) {\n"
    "    :root {\n"
    "        --bg: #1c1c1e;\n"
    "        --surface: rgba(44, 44, 46, 0.85);\n"
    "        --surface-hover: rgba(58, 58, 60, 0.95);\n"
    "        --border: rgba(255, 255, 255, 0.08);\n"
    "        --text: #f5f5f7;\n"
    "        --text-secondary: #98989d;\n"
    "        --text-tertiary: #636366;\n"
    "        --accent: #0a84ff;\n"
    "        --accent-bg: rgba(10, 132, 255, 0.12);\n"
    "        --green: #30d158;\n"
    "        --green-bg: rgba(48, 209, 88, 0.12);\n"
    "        --red: #ff453a;\n"
    "        --red-bg: rgba(255, 69, 58, 0.12);\n"
    "        --orange: #ff9f0a;\n"
    "        --orange-bg: rgba(255, 159, 10, 0.12);\n"
    "        --shadow: 0 1px 3px rgba(0,0,0,0.2);\n"
    "    }\n"
    "}\n"
    "* { margin: 0; padding: 0; box-sizing: border-box; }\n"
    "body {\n"
    "    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', system-ui, sans-serif;\n"
    "    background: var(--bg); color: var(--text);\n"
    "    width: 320px; font-size: 13px;\n"
    "    -webkit-font-smoothing: antialiased;\n"
    "    overflow: hidden;\n"
    "}\n"
    "\n"
    "/* Header */\n"
    ".header {\n"
    "    display: flex; align-items: center; justify-content: space-between;\n"
    "    padding: 14px 16px 12px;\n"
    "    backdrop-filter: blur(20px) saturate(180%);\n"
    "    -webkit-backdrop-filter: blur(20px) saturate(180%);\n"
    "    border-bottom: 1px solid var(--border);\n"
    "}\n"
    ".header-left { display: flex; align-items: center; gap: 8px; }\n"
    ".header-left svg { width: 20px; height: 20px; color: var(--accent); }\n"
    ".header-title { font-weight: 600; font-size: 14px; }\n"
    ".status-pill {\n"
    "    font-size: 11px; padding: 3px 10px; border-radius: 20px; font-weight: 500;\n"
    "    display: flex; align-items: center; gap: 4px;\n"
    "}\n"
    ".status-pill.locked { background: var(--red-bg); color: var(--red); }\n"
    ".status-pill.unlocked { background: var(--green-bg); color: var(--green); }\n"
    ".status-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }\n"
    "\n"
    "/* Tab bar */\n"
    ".tab-bar {\n"
    "    display: flex; padding: 0 12px; border-bottom: 1px solid var(--border);\n"
    "    background: var(--bg);\n"
    "}\n"
    ".tab {\n"
    "    flex: 1; padding: 10px 0; text-align: center; font-size: 11px; font-weight: 500;\n"
    "    color: var(--text-tertiary); cursor: pointer; border-bottom: 2px solid transparent;\n"
    "    transition: all 0.2s;\n"
    "}\n"
    ".tab.active { color: var(--accent); border-bottom-color: var(--accent); }\n"
    ".tab:hover:not(.active) { color: var(--text-secondary); }\n"
    "\n"
    "/* Content area */\n"
    ".tab-content { display: none; max-height: 400px; overflow-y: auto; }\n"
    ".tab-content.active { display: block; }\n"
    ".content-section { padding: 10px 12px; }\n"
    ".section-label {\n"
    "    font-size: 11px; font-weight: 600; text-transform: uppercase;\n"
    "    letter-spacing: 0.5px; color: var(--text-tertiary); padding: 4px 4px 8px;\n"
    "}\n"
    "\n"
    "/* Cards */\n"
    ".card {\n"
    "    background: var(--surface); border-radius: var(--radius);\n"
    "    padding: 12px; margin-bottom: 8px;\n"
    "    border: 1px solid var(--border); box-shadow: var(--shadow);\n"
    "    cursor: pointer; transition: background 0.15s, transform 0.1s;\n"
    "}\n"
    ".card:hover { background: var(--surface-hover); }\n"
    ".card:active { transform: scale(0.99); }\n"
    ".card-row { display: flex; align-items: center; justify-content: space-between; }\n"
    ".card-title { font-weight: 600; font-size: 13px; display: flex; align-items: center; gap: 6px; }\n"
    ".card-subtitle { font-size: 11px; color: var(--text-secondary); margin-top: 2px; font-family: 'SF Mono', Menlo, monospace; }\n"
    ".badge-sm {\n"
    "    font-size: 10px; padding: 2px 8px; border-radius: 6px; font-weight: 500;\n"
    "}\n"
    ".badge-sm.active { background: var(--green-bg); color: var(--green); }\n"
    ".badge-sm.locked { background: var(--red-bg); color: var(--red); }\n"
    "\n"
    "/* Card detail (expandable) */\n"
    ".card-detail { display: none; padding-top: 10px; margin-top: 10px; border-top: 1px solid var(--border); }\n"
    ".card.expanded .card-detail { display: block; }\n"
    "\n"
    "/* Buttons */\n"
    ".btn-row { display: flex; gap: 6px; flex-wrap: wrap; }\n"
    ".btn {\n"
    "    font-size: 11px; padding: 6px 12px; border-radius: var(--radius-sm);\n"
    "    border: 1px solid var(--border); background: var(--surface);\n"
    "    color: var(--text-secondary); cursor: pointer; transition: all 0.15s;\n"
    "    font-family: inherit; font-weight: 500;\n"
    "}\n"
    ".btn:hover { background: var(--accent-bg); color: var(--accent); border-color: rgba(0,122,255,0.2); }\n"
    ".btn.danger:hover { background: var(--red-bg); color: var(--red); border-color: rgba(255,59,48,0.2); }\n"
    ".btn.primary {\n"
    "    background: var(--accent); color: white; border-color: var(--accent);\n"
    "}\n"
    ".btn.primary:hover { opacity: 0.9; }\n"
    ".btn-full { width: 100%; padding: 10px; font-size: 13px; margin-top: 8px; }\n"
    "\n"
    "/* Input row */\n"
    ".input-row { display: flex; gap: 6px; margin-top: 8px; }\n"
    ".input-row input, .form-input {\n"
    "    flex: 1; padding: 7px 10px; border-radius: var(--radius-sm);\n"
    "    border: 1px solid var(--border); background: var(--bg);\n"
    "    color: var(--text); font-size: 12px; font-family: 'SF Mono', Menlo, monospace;\n"
    "    outline: none; transition: border-color 0.15s;\n"
    "}\n"
    ".input-row input:focus, .form-input:focus { border-color: var(--accent); }\n"
    "\n"
    "/* Denial cards */\n"
    ".denial-card {\n"
    "    background: var(--surface); border-radius: var(--radius-sm);\n"
    "    padding: 10px 12px; margin-bottom: 6px;\n"
    "    border: 1px solid var(--border); box-shadow: var(--shadow);\n"
    "    display: flex; align-items: center; gap: 8px;\n"
    "}\n"
    ".denial-icon { color: var(--orange); font-size: 16px; flex-shrink: 0; }\n"
    ".denial-info { flex: 1; min-width: 0; }\n"
    ".denial-proc { font-weight: 600; font-size: 12px; color: var(--orange); }\n"
    ".denial-file { font-size: 10px; color: var(--text-tertiary); font-family: 'SF Mono', Menlo, monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }\n"
    ".denial-meta { text-align: right; flex-shrink: 0; }\n"
    ".denial-time { font-size: 10px; color: var(--text-tertiary); display: block; }\n"
    ".btn-allow-sm {\n"
    "    font-size: 10px; padding: 3px 8px; border-radius: 6px;\n"
    "    border: 1px solid rgba(52,199,89,0.3); background: var(--green-bg);\n"
    "    color: var(--green); cursor: pointer; font-family: inherit; margin-top: 4px;\n"
    "}\n"
    "\n"
    "/* Log entries */\n"
    ".log-entry {\n"
    "    padding: 8px 0; border-bottom: 1px solid var(--border);\n"
    "    font-size: 11px;\n"
    "}\n"
    ".log-entry:last-child { border-bottom: none; }\n"
    ".log-ts { color: var(--text-tertiary); font-family: 'SF Mono', Menlo, monospace; font-size: 10px; }\n"
    ".log-event { font-weight: 600; margin: 0 4px; }\n"
    ".log-event.allow { color: var(--green); }\n"
    ".log-event.deny { color: var(--red); }\n"
    ".log-event.unlock { color: var(--accent); }\n"
    ".log-event.lock { color: var(--orange); }\n"
    ".log-detail { color: var(--text-secondary); font-size: 10px; display: block; margin-top: 2px; }\n"
    "\n"
    "/* Settings */\n"
    ".setting-row {\n"
    "    display: flex; align-items: center; justify-content: space-between;\n"
    "    padding: 12px 0; border-bottom: 1px solid var(--border);\n"
    "}\n"
    ".setting-row:last-child { border-bottom: none; }\n"
    ".setting-label { font-size: 13px; font-weight: 500; }\n"
    ".setting-desc { font-size: 11px; color: var(--text-secondary); margin-top: 2px; }\n"
    ".setting-value { font-size: 12px; color: var(--accent); font-weight: 500; }\n"
    "select.form-select {\n"
    "    padding: 5px 8px; border-radius: var(--radius-sm); border: 1px solid var(--border);\n"
    "    background: var(--surface); color: var(--text); font-size: 12px;\n"
    "    font-family: inherit; outline: none;\n"
    "}\n"
    "\n"
    "/* Empty state */\n"
    ".empty-state { text-align: center; padding: 32px 16px; }\n"
    ".empty-icon { font-size: 32px; margin-bottom: 8px; }\n"
    ".empty-text { color: var(--text-tertiary); font-size: 12px; line-height: 1.5; }\n"
    "\n"
    "/* Toast */\n"
    ".toast {\n"
    "    position: fixed; bottom: 12px; left: 50%; transform: translateX(-50%) translateY(20px);\n"
    "    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);\n"
    "    padding: 8px 16px; font-size: 12px; font-weight: 500; color: var(--green);\n"
    "    box-shadow: 0 4px 12px rgba(0,0,0,0.15);\n"
    "    opacity: 0; transition: all 0.3s ease; pointer-events: none; z-index: 1000;\n"
    "    backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);\n"
    "}\n"
    ".toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }\n"
    ".toast.error { color: var(--red); }\n"
    "\n"
    "/* Modal overlay */\n"
    ".modal-overlay {\n"
    "    display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;\n"
    "    background: rgba(0,0,0,0.4); z-index: 500;\n"
    "    backdrop-filter: blur(4px); -webkit-backdrop-filter: blur(4px);\n"
    "}\n"
    ".modal-overlay.show { display: flex; align-items: center; justify-content: center; }\n"
    ".modal {\n"
    "    background: var(--bg); border: 1px solid var(--border); border-radius: 14px;\n"
    "    width: 290px; box-shadow: 0 8px 32px rgba(0,0,0,0.2); overflow: hidden;\n"
    "}\n"
    ".modal-header {\n"
    "    display: flex; justify-content: space-between; align-items: center;\n"
    "    padding: 14px 16px; border-bottom: 1px solid var(--border);\n"
    "}\n"
    ".modal-title { font-weight: 600; font-size: 14px; }\n"
    ".modal-close {\n"
    "    background: none; border: none; color: var(--text-tertiary);\n"
    "    cursor: pointer; font-size: 18px; padding: 0; line-height: 1;\n"
    "}\n"
    ".modal-body { padding: 16px; }\n"
    ".modal-body p { font-size: 12px; color: var(--text-secondary); margin-bottom: 12px; line-height: 1.4; }\n"
    ".modal-body pre {\n"
    "    font-size: 11px; color: var(--text-secondary); white-space: pre-wrap;\n"
    "    font-family: 'SF Mono', Menlo, monospace; max-height: 200px; overflow-y: auto;\n"
    "    background: var(--surface); padding: 10px; border-radius: var(--radius-sm);\n"
    "    border: 1px solid var(--border);\n"
    "}\n"
    "\n"
    "/* Footer */\n"
    ".footer {\n"
    "    display: flex; align-items: center; justify-content: space-between;\n"
    "    padding: 8px 16px; border-top: 1px solid var(--border);\n"
    "    font-size: 10px; color: var(--text-tertiary);\n"
    "}\n"
    "\n"
    "@keyframes spin { to { transform: rotate(360deg); } }\n"
    ".spinning { animation: spin 0.8s linear infinite; display: inline-block; }\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "\n"
    "<div class=\"header\">\n"
    "    <div class=\"header-left\">\n"
    "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\">\n"
    "            <rect x=\"3\" y=\"11\" width=\"18\" height=\"11\" rx=\"2\" ry=\"2\"/>\n"
    "            <path d=\"M7 11V7a5 5 0 0 1 10 0v4\"/>\n"
    "        </svg>\n"
    "        <span class=\"header-title\">onvault</span>\n"
    "    </div>\n"
    "    <div class=\"status-pill locked\" id=\"statusPill\">\n"
    "        <span class=\"status-dot\"></span>\n"
    "        <span id=\"statusText\">Locked</span>\n"
    "    </div>\n"
    "</div>\n"
    "\n"
    "<div class=\"tab-bar\">\n"
    "    <div class=\"tab active\" onclick=\"switchTab('vaults')\" id=\"tab-vaults\">Vaults</div>\n"
    "    <div class=\"tab\" onclick=\"switchTab('policies')\" id=\"tab-policies\">Policies</div>\n"
    "    <div class=\"tab\" onclick=\"switchTab('log')\" id=\"tab-log\">Log</div>\n"
    "    <div class=\"tab\" onclick=\"switchTab('settings')\" id=\"tab-settings\">Settings</div>\n"
    "</div>\n"
    "\n"
    "<!-- Vaults Tab -->\n"
    "<div class=\"tab-content active\" id=\"content-vaults\">\n"
    "    <div class=\"content-section\">\n"
    "        <div id=\"vaultList\"></div>\n"
    "        <div id=\"denialSection\" style=\"display:none\">\n"
    "            <div class=\"section-label\" style=\"margin-top:8px\">Recent Denials</div>\n"
    "            <div id=\"denialList\"></div>\n"
    "        </div>\n"
    "        <button class=\"btn btn-full primary\" onclick=\"promptAddVault()\">Add Vault</button>\n"
    "    </div>\n"
    "</div>\n"
    "\n"
    "<!-- Policies Tab -->\n"
    "<div class=\"tab-content\" id=\"content-policies\">\n"
    "    <div class=\"content-section\">\n"
    "        <div id=\"policyList\"></div>\n"
    "    </div>\n"
    "</div>\n"
    "\n"
    "<!-- Log Tab -->\n"
    "<div class=\"tab-content\" id=\"content-log\">\n"
    "    <div class=\"content-section\">\n"
    "        <div class=\"btn-row\" style=\"margin-bottom:10px\">\n"
    "            <button class=\"btn\" onclick=\"filterLog('all')\" id=\"log-filter-all\" style=\"background:var(--accent-bg);color:var(--accent)\">All</button>\n"
    "            <button class=\"btn\" onclick=\"filterLog('denied')\" id=\"log-filter-denied\">Denied</button>\n"
    "            <button class=\"btn\" onclick=\"filterLog('allowed')\" id=\"log-filter-allowed\">Allowed</button>\n"
    "        </div>\n"
    "        <div id=\"logList\"></div>\n"
    "    </div>\n"
    "</div>\n"
    "\n"
    "<!-- Settings Tab -->\n"
    "<div class=\"tab-content\" id=\"content-settings\">\n"
    "    <div class=\"content-section\">\n"
    "        <div class=\"section-label\">Security</div>\n"
    "        <div class=\"setting-row\">\n"
    "            <div>\n"
    "                <div class=\"setting-label\">Verification Mode</div>\n"
    "                <div class=\"setting-desc\">How processes are verified</div>\n"
    "            </div>\n"
    "            <select class=\"form-select\" id=\"verifyMode\" onchange=\"toast('Restart daemon to apply',false)\">\n"
    "                <option value=\"codesign_preferred\">Codesign (preferred)</option>\n"
    "                <option value=\"hash_only\">Hash only</option>\n"
    "                <option value=\"codesign_required\">Codesign (required)</option>\n"
    "            </select>\n"
    "        </div>\n"
    "        <div class=\"setting-row\">\n"
    "            <div>\n"
    "                <div class=\"setting-label\">Touch ID</div>\n"
    "                <div class=\"setting-desc\">Unlock with biometrics</div>\n"
    "            </div>\n"
    "            <button class=\"btn\" id=\"touchIdBtn\" onclick=\"doTouchIdUnlock()\">Unlock</button>\n"
    "        </div>\n"
    "\n"
    "        <div class=\"section-label\" style=\"margin-top:12px\">Recovery</div>\n"
    "        <div class=\"setting-row\">\n"
    "            <div>\n"
    "                <div class=\"setting-label\">Recovery Key</div>\n"
    "                <div class=\"setting-desc\">View your emergency recovery key</div>\n"
    "            </div>\n"
    "            <button class=\"btn\" onclick=\"showRecoveryPrompt()\">View</button>\n"
    "        </div>\n"
    "        <div class=\"setting-row\">\n"
    "            <div>\n"
    "                <div class=\"setting-label\">Forgot Passphrase?</div>\n"
    "                <div class=\"setting-desc\">Unlock using recovery key</div>\n"
    "            </div>\n"
    "            <button class=\"btn\" onclick=\"showRecoverPrompt()\">Recover</button>\n"
    "        </div>\n"
    "\n"
    "        <div class=\"section-label\" style=\"margin-top:12px\">Advanced</div>\n"
    "        <div class=\"setting-row\">\n"
    "            <div>\n"
    "                <div class=\"setting-label\">Rotate Keys</div>\n"
    "                <div class=\"setting-desc\">Re-encrypt all vaults with new key</div>\n"
    "            </div>\n"
    "            <button class=\"btn danger\" onclick=\"showRotatePrompt()\">Rotate</button>\n"
    "        </div>\n"
    "        <div class=\"setting-row\">\n"
    "            <div>\n"
    "                <div class=\"setting-label\">Watch Mode</div>\n"
    "                <div class=\"setting-desc\">Discover process access patterns</div>\n"
    "            </div>\n"
    "            <button class=\"btn\" onclick=\"toast('Use CLI: onvault vault watch',false)\">Start</button>\n"
    "        </div>\n"
    "    </div>\n"
    "</div>\n"
    "\n"
    "<div class=\"footer\">\n"
    "    <span>onvault v0.1.0</span>\n"
    "    <span id=\"lastUpdate\"></span>\n"
    "</div>\n"
    "\n"
    "<div class=\"toast\" id=\"toast\"></div>\n"
    "\n"
    "<!-- Modal -->\n"
    "<div class=\"modal-overlay\" id=\"modalOverlay\" onclick=\"hideModal()\">\n"
    "    <div class=\"modal\" onclick=\"event.stopPropagation()\">\n"
    "        <div class=\"modal-header\">\n"
    "            <span class=\"modal-title\" id=\"modalTitle\"></span>\n"
    "            <button class=\"modal-close\" onclick=\"hideModal()\">&#10005;</button>\n"
    "        </div>\n"
    "        <div class=\"modal-body\" id=\"modalBody\"></div>\n"
    "    </div>\n"
    "</div>\n"
    "\n"
    "<script>\n"
    "/* ES5 only — no let/const/async/await/arrow functions/template literals */\n"
    "var API = window.location.origin;\n"
    "var state = { locked: true, vault_count: 0, vaults: [] };\n"
    "var denials = [];\n"
    "var logEntries = [];\n"
    "var logFilter = 'all';\n"
    "var expandedVaults = {};\n"
    "var authToken = null;\n"
    "var currentTab = 'vaults';\n"
    "var _refreshInterval = null;\n"
    "\n"
    "/* --- Utility --- */\n"
    "function esc(s) {\n"
    "    if (!s) return '';\n"
    "    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')\n"
    "        .replace(/\"/g,'&quot;').replace(/'/g,'&#39;');\n"
    "}\n"
    "\n"
    "function toast(msg, isError) {\n"
    "    var t = document.getElementById('toast');\n"
    "    t.textContent = msg;\n"
    "    t.className = 'toast show' + (isError ? ' error' : '');\n"
    "    setTimeout(function() { t.className = 'toast'; }, 2500);\n"
    "}\n"
    "\n"
    "function timeAgo(ts) {\n"
    "    var s = Math.floor(Date.now() / 1000) - ts;\n"
    "    if (s < 60) return s + 's ago';\n"
    "    if (s < 3600) return Math.floor(s / 60) + 'm ago';\n"
    "    return Math.floor(s / 3600) + 'h ago';\n"
    "}\n"
    "\n"
    "function notifyResize() {\n"
    "    try { window.webkit.messageHandlers.resize.postMessage(document.body.scrollHeight); } catch(e) {}\n"
    "}\n"
    "\n"
    "/* --- API helpers --- */\n"
    "function fetchJSON(path) {\n"
    "    return fetch(API + path).then(function(r) {\n"
    "        return r.json().then(function(j) {\n"
    "            if (r.status === 401) { authToken = null; throw j; }\n"
    "            return j;\n"
    "        });\n"
    "    });\n"
    "}\n"
    "\n"
    "function fetchText(path) {\n"
    "    return fetch(API + path).then(function(r) {\n"
    "        return r.text().then(function(text) {\n"
    "            if (r.status === 401) { authToken = null; throw { ok: false, msg: 'Unauthorized' }; }\n"
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
    "            if (r.status === 401) authToken = null;\n"
    "            j._status = r.status;\n"
    "            return j;\n"
    "        });\n"
    "    });\n"
    "}\n"
    "\n"
    "function tokenParam() {\n"
    "    return authToken ? '?token=' + encodeURIComponent(authToken) : '';\n"
    "}\n"
    "\n"
    "/* --- Data fetching --- */\n"
    "function fetchData() {\n"
    "    var tp = tokenParam();\n"
    "    return Promise.all([\n"
    "        fetchJSON('/api/status' + tp),\n"
    "        fetchJSON('/api/denials' + tp)\n"
    "    ]).then(function(results) {\n"
    "        state = results[0];\n"
    "        denials = results[1];\n"
    "        render();\n"
    "    }).catch(function() {\n"
    "        state = { locked: true, vault_count: 0, vaults: [] };\n"
    "        denials = [];\n"
    "        render();\n"
    "    });\n"
    "}\n"
    "\n"
    "function fetchLog() {\n"
    "    fetchText('/api/log' + tokenParam()).then(function(text) {\n"
    "        try { logEntries = JSON.parse(text); } catch(e) { logEntries = []; }\n"
    "        renderLog();\n"
    "    }).catch(function() { logEntries = []; renderLog(); });\n"
    "}\n"
    "\n"
    "function fetchPolicies() {\n"
    "    fetchText('/api/policies' + tokenParam()).then(function(text) {\n"
    "        renderPolicies(text);\n"
    "    }).catch(function() { renderPolicies('Locked or unavailable'); });\n"
    "}\n"
    "\n"
    "/* --- Tab switching --- */\n"
    "function switchTab(name) {\n"
    "    currentTab = name;\n"
    "    var tabs = document.querySelectorAll('.tab');\n"
    "    var contents = document.querySelectorAll('.tab-content');\n"
    "    for (var i = 0; i < tabs.length; i++) {\n"
    "        tabs[i].className = 'tab' + (tabs[i].id === 'tab-' + name ? ' active' : '');\n"
    "    }\n"
    "    for (var j = 0; j < contents.length; j++) {\n"
    "        contents[j].className = 'tab-content' + (contents[j].id === 'content-' + name ? ' active' : '');\n"
    "    }\n"
    "    if (name === 'log') fetchLog();\n"
    "    if (name === 'policies') fetchPolicies();\n"
    "    notifyResize();\n"
    "}\n"
    "\n"
    "/* --- Rendering --- */\n"
    "function render() {\n"
    "    /* Status pill */\n"
    "    var pill = document.getElementById('statusPill');\n"
    "    pill.className = 'status-pill ' + (state.locked ? 'locked' : 'unlocked');\n"
    "    document.getElementById('statusText').textContent = state.locked ? 'Locked' : state.vault_count + ' vault' + (state.vault_count !== 1 ? 's' : '');\n"
    "\n"
    "    renderVaults();\n"
    "    renderDenials();\n"
    "    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});\n"
    "    notifyResize();\n"
    "}\n"
    "\n"
    "function renderVaults() {\n"
    "    var vl = document.getElementById('vaultList');\n"
    "    if (state.locked) {\n"
    "        vl.innerHTML = '<div class=\"empty-state\"><div class=\"empty-icon\">&#x1F512;</div>' +\n"
    "            '<div class=\"empty-text\">Locked<br>Click the status pill or use Settings to unlock.</div></div>';\n"
    "        return;\n"
    "    }\n"
    "    if (!state.vaults || state.vaults.length === 0) {\n"
    "        vl.innerHTML = '<div class=\"empty-state\"><div class=\"empty-icon\">&#x1F6E1;</div>' +\n"
    "            '<div class=\"empty-text\">No vaults yet<br>Add a directory to protect it.</div></div>';\n"
    "        return;\n"
    "    }\n"
    "    vl.innerHTML = state.vaults.map(function(v) {\n"
    "        var exp = expandedVaults[v.id] ? ' expanded' : '';\n"
    "        var vid = encodeURIComponent(v.id);\n"
    "        return '<div class=\"card' + exp + '\" onclick=\"toggleVault(\\'' + vid + '\\')\">' +\n"
    "            '<div class=\"card-row\"><div class=\"card-title\">' +\n"
    "            (v.mounted ? '&#x1F513;' : '&#x1F512;') + ' ' + esc(v.id) + '</div>' +\n"
    "            '<span class=\"badge-sm ' + (v.mounted ? 'active' : 'locked') + '\">' +\n"
    "            (v.mounted ? 'Mounted' : 'Locked') + '</span></div>' +\n"
    "            '<div class=\"card-subtitle\">' + esc(v.source) + '</div>' +\n"
    "            '<div class=\"card-detail\">' +\n"
    "            '<div class=\"btn-row\">' +\n"
    "            '<button class=\"btn\" onclick=\"event.stopPropagation();viewRules(\\'' + vid + '\\')\">Rules</button>' +\n"
    "            '<button class=\"btn\" onclick=\"event.stopPropagation();promptRule(\\'allow\\',\\'' + vid + '\\')\">Allow</button>' +\n"
    "            '<button class=\"btn\" onclick=\"event.stopPropagation();promptRule(\\'deny\\',\\'' + vid + '\\')\">Deny</button>' +\n"
    "            '<button class=\"btn danger\" onclick=\"event.stopPropagation();promptRemoveVault(\\'' + vid + '\\')\">Remove</button>' +\n"
    "            '</div></div></div>';\n"
    "    }).join('');\n"
    "}\n"
    "\n"
    "function renderDenials() {\n"
    "    var ds = document.getElementById('denialSection');\n"
    "    var dl = document.getElementById('denialList');\n"
    "    if (!denials || denials.length === 0) { ds.style.display = 'none'; return; }\n"
    "    ds.style.display = 'block';\n"
    "    dl.innerHTML = denials.slice(-5).reverse().map(function(d) {\n"
    "        var pa = encodeURIComponent(d.path || '');\n"
    "        var va = encodeURIComponent(d.vault || '');\n"
    "        return '<div class=\"denial-card\">' +\n"
    "            '<div class=\"denial-icon\">&#x26A0;</div>' +\n"
    "            '<div class=\"denial-info\"><span class=\"denial-proc\">' + esc(d.process) + '</span>' +\n"
    "            '<div class=\"denial-file\">' + esc(d.file) + '</div></div>' +\n"
    "            '<div class=\"denial-meta\"><span class=\"denial-time\">' + timeAgo(d.time) + '</span>' +\n"
    "            '<button class=\"btn-allow-sm\" onclick=\"promptQuickAllow(\\'' + pa + '\\',\\'' + va + '\\')\">Allow</button></div></div>';\n"
    "    }).join('');\n"
    "}\n"
    "\n"
    "function renderPolicies(text) {\n"
    "    var el = document.getElementById('policyList');\n"
    "    if (!text || text.indexOf('Locked') >= 0) {\n"
    "        el.innerHTML = '<div class=\"empty-state\"><div class=\"empty-icon\">&#x1F4CB;</div>' +\n"
    "            '<div class=\"empty-text\">Unlock to view policies</div></div>';\n"
    "    } else {\n"
    "        el.innerHTML = '<pre style=\"font-size:11px;color:var(--text-secondary);white-space:pre-wrap;' +\n"
    "            'font-family:SF Mono,Menlo,monospace;background:var(--surface);padding:12px;' +\n"
    "            'border-radius:var(--radius);border:1px solid var(--border)\">' + esc(text) + '</pre>';\n"
    "    }\n"
    "    notifyResize();\n"
    "}\n"
    "\n"
    "function renderLog() {\n"
    "    var el = document.getElementById('logList');\n"
    "    if (!logEntries || logEntries.length === 0) {\n"
    "        el.innerHTML = '<div class=\"empty-state\"><div class=\"empty-icon\">&#x1F4DD;</div>' +\n"
    "            '<div class=\"empty-text\">No log entries</div></div>';\n"
    "        notifyResize();\n"
    "        return;\n"
    "    }\n"
    "    var filtered = logEntries;\n"
    "    if (logFilter === 'denied') {\n"
    "        filtered = logEntries.filter(function(e) { return e.event && e.event.toLowerCase().indexOf('deny') >= 0; });\n"
    "    } else if (logFilter === 'allowed') {\n"
    "        filtered = logEntries.filter(function(e) { return e.event && e.event.toLowerCase().indexOf('allow') >= 0; });\n"
    "    }\n"
    "    el.innerHTML = filtered.slice(-30).reverse().map(function(e) {\n"
    "        var evClass = '';\n"
    "        var ev = (e.event || '').toLowerCase();\n"
    "        if (ev.indexOf('allow') >= 0) evClass = ' allow';\n"
    "        else if (ev.indexOf('deny') >= 0) evClass = ' deny';\n"
    "        else if (ev.indexOf('unlock') >= 0) evClass = ' unlock';\n"
    "        else if (ev.indexOf('lock') >= 0) evClass = ' lock';\n"
    "        var ts = e.ts ? new Date(e.ts * 1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '';\n"
    "        return '<div class=\"log-entry\"><span class=\"log-ts\">' + ts + '</span>' +\n"
    "            '<span class=\"log-event' + evClass + '\">' + esc(e.event) + '</span>' +\n"
    "            (e.vault ? ' ' + esc(e.vault) : '') +\n"
    "            (e.detail ? '<span class=\"log-detail\">' + esc(e.detail) + '</span>' : '') +\n"
    "            '</div>';\n"
    "    }).join('');\n"
    "    notifyResize();\n"
    "}\n"
    "\n"
    "function filterLog(f) {\n"
    "    logFilter = f;\n"
    "    var filters = ['all', 'denied', 'allowed'];\n"
    "    filters.forEach(function(name) {\n"
    "        var btn = document.getElementById('log-filter-' + name);\n"
    "        if (btn) {\n"
    "            btn.style.background = (name === f) ? 'var(--accent-bg)' : '';\n"
    "            btn.style.color = (name === f) ? 'var(--accent)' : '';\n"
    "        }\n"
    "    });\n"
    "    renderLog();\n"
    "}\n"
    "\n"
    "/* --- Interactions --- */\n"
    "function toggleVault(vid) {\n"
    "    var id = decodeURIComponent(vid);\n"
    "    expandedVaults[id] = !expandedVaults[id];\n"
    "    renderVaults();\n"
    "    notifyResize();\n"
    "}\n"
    "\n"
    "function viewRules(vid) {\n"
    "    var id = decodeURIComponent(vid);\n"
    "    fetchText('/api/rules?vault=' + encodeURIComponent(id) + (authToken ? '&token=' + encodeURIComponent(authToken) : '')).then(function(text) {\n"
    "        showModal('Rules: ' + id, '<pre>' + esc(text) + '</pre>');\n"
    "    }).catch(function() { toast('Failed to load rules', true); });\n"
    "}\n"
    "\n"
    "/* --- Auth-gated actions with passphrase modal --- */\n"
    "function showPassphraseModal(title, desc, callback) {\n"
    "    var tp = tokenParam().replace('?','&');\n"
    "    fetchJSON('/api/auth-status' + tokenParam()).then(function(r) {\n"
    "        if (r && r.elevated) {\n"
    "            callback(null); /* elevated — no passphrase needed */\n"
    "        } else {\n"
    "            showModal(title, '<p>' + desc + '</p>' +\n"
    "                '<input type=\"password\" class=\"form-input\" id=\"modalPassInput\" placeholder=\"Passphrase\" ' +\n"
    "                'onkeydown=\"if(event.keyCode===13)document.getElementById(\\'modalPassBtn\\').click()\">' +\n"
    "                '<button class=\"btn primary btn-full\" id=\"modalPassBtn\" onclick=\"submitModalPass()\">Confirm</button>');\n"
    "            window._pendingPassCallback = callback;\n"
    "            setTimeout(function() {\n"
    "                var inp = document.getElementById('modalPassInput');\n"
    "                if (inp) inp.focus();\n"
    "            }, 100);\n"
    "        }\n"
    "    }).catch(function() {\n"
    "        showModal(title, '<p>' + desc + '</p>' +\n"
    "            '<input type=\"password\" class=\"form-input\" id=\"modalPassInput\" placeholder=\"Passphrase\" ' +\n"
    "            'onkeydown=\"if(event.keyCode===13)document.getElementById(\\'modalPassBtn\\').click()\">' +\n"
    "            '<button class=\"btn primary btn-full\" id=\"modalPassBtn\" onclick=\"submitModalPass()\">Confirm</button>');\n"
    "        window._pendingPassCallback = callback;\n"
    "        setTimeout(function() {\n"
    "            var inp = document.getElementById('modalPassInput');\n"
    "            if (inp) inp.focus();\n"
    "        }, 100);\n"
    "    });\n"
    "}\n"
    "\n"
    "function submitModalPass() {\n"
    "    var inp = document.getElementById('modalPassInput');\n"
    "    var pass = inp ? inp.value : '';\n"
    "    if (!pass) return;\n"
    "    hideModal();\n"
    "    if (window._pendingPassCallback) {\n"
    "        window._pendingPassCallback(pass);\n"
    "        window._pendingPassCallback = null;\n"
    "    }\n"
    "}\n"
    "\n"
    "function promptRule(type, vid) {\n"
    "    var id = decodeURIComponent(vid);\n"
    "    showModal((type === 'allow' ? 'Allow' : 'Deny') + ' Process', '<p>Enter process path for <strong>' + esc(id) + '</strong></p>' +\n"
    "        '<input class=\"form-input\" id=\"modalProcInput\" placeholder=\"/usr/bin/process\" ' +\n"
    "        'onkeydown=\"if(event.keyCode===13)document.getElementById(\\'modalProcBtn\\').click()\">' +\n"
    "        '<button class=\"btn primary btn-full\" id=\"modalProcBtn\" onclick=\"doRuleFromModal(\\'' +\n"
    "        encodeURIComponent(type) + '\\',\\'' + encodeURIComponent(id) + '\\')\">Confirm</button>');\n"
    "    setTimeout(function() {\n"
    "        var inp = document.getElementById('modalProcInput');\n"
    "        if (inp) inp.focus();\n"
    "    }, 100);\n"
    "}\n"
    "\n"
    "function doRuleFromModal(typeEnc, vidEnc) {\n"
    "    var type = decodeURIComponent(typeEnc);\n"
    "    var id = decodeURIComponent(vidEnc);\n"
    "    var procInput = document.getElementById('modalProcInput');\n"
    "    var proc = procInput ? procInput.value.trim() : '';\n"
    "    if (!proc) return;\n"
    "    hideModal();\n"
    "    showPassphraseModal(type === 'allow' ? 'Authorize Allow' : 'Authorize Deny',\n"
    "        'Enter passphrase to ' + type + ' <strong>' + esc(proc) + '</strong> for <strong>' + esc(id) + '</strong>.',\n"
    "        function(pass) {\n"
    "            var body = pass ? (pass + '\\n' + proc + '\\n' + id) : (proc + '\\n' + id);\n"
    "            postAPI('/api/' + type, body).then(function(j) {\n"
    "                toast(j.msg || (type + ' applied'), !j.ok);\n"
    "                fetchData();\n"
    "            }).catch(function() { toast('Failed', true); });\n"
    "        });\n"
    "}\n"
    "\n"
    "function promptQuickAllow(pathEnc, vaultEnc) {\n"
    "    var proc = decodeURIComponent(pathEnc);\n"
    "    var vault = decodeURIComponent(vaultEnc);\n"
    "    showPassphraseModal('Authorize Allow', 'Allow <strong>' + esc(proc) + '</strong> for <strong>' + esc(vault) + '</strong>?', function(pass) {\n"
    "        var body = pass ? (pass + '\\n' + proc + '\\n' + vault) : (proc + '\\n' + vault);\n"
    "        postAPI('/api/allow', body).then(function(j) {\n"
    "            toast(j.msg || 'Allowed', !j.ok);\n"
    "            fetchData();\n"
    "        }).catch(function() { toast('Failed', true); });\n"
    "    });\n"
    "}\n"
    "\n"
    "function promptRemoveVault(vid) {\n"
    "    var id = decodeURIComponent(vid);\n"
    "    showPassphraseModal('Remove Vault', 'This will decrypt and unprotect <strong>' + esc(id) + '</strong>. Enter passphrase to confirm.', function(pass) {\n"
    "        if (!pass) { toast('Passphrase required', true); return; }\n"
    "        postAPI('/api/vault/remove', pass + '\\n' + id).then(function(j) {\n"
    "            toast(j.msg || 'Removed', !j.ok);\n"
    "            fetchData();\n"
    "        }).catch(function() { toast('Use CLI: onvault vault remove ' + id, true); });\n"
    "    });\n"
    "}\n"
    "\n"
    "function promptAddVault() {\n"
    "    showModal('Add Vault', '<p>Enter the path to protect:</p>' +\n"
    "        '<input class=\"form-input\" id=\"modalAddInput\" placeholder=\"~/.ssh or /path/to/dir\" ' +\n"
    "        'onkeydown=\"if(event.keyCode===13)document.getElementById(\\'modalAddBtn\\').click()\">' +\n"
    "        '<button class=\"btn primary btn-full\" id=\"modalAddBtn\" onclick=\"doAddVault()\">Protect</button>');\n"
    "    setTimeout(function() {\n"
    "        var inp = document.getElementById('modalAddInput');\n"
    "        if (inp) inp.focus();\n"
    "    }, 100);\n"
    "}\n"
    "\n"
    "function doAddVault() {\n"
    "    var inp = document.getElementById('modalAddInput');\n"
    "    var path = inp ? inp.value.trim() : '';\n"
    "    if (!path) return;\n"
    "    hideModal();\n"
    "    postAPI('/api/vault/add', path).then(function(j) {\n"
    "        toast(j.msg || 'Vault added', !j.ok);\n"
    "        fetchData();\n"
    "    }).catch(function() { toast('Failed to add vault', true); });\n"
    "}\n"
    "\n"
    "/* --- Lock/Unlock --- */\n"
    "document.getElementById('statusPill').onclick = function() { doLockUnlock(); };\n"
    "\n"
    "function doLockUnlock() {\n"
    "    if (state.locked) {\n"
    "        showModal('Unlock', '<p>Enter your passphrase to unlock all vaults.</p>' +\n"
    "            '<input type=\"password\" class=\"form-input\" id=\"modalUnlockInput\" placeholder=\"Passphrase\" ' +\n"
    "            'onkeydown=\"if(event.keyCode===13)document.getElementById(\\'modalUnlockBtn\\').click()\">' +\n"
    "            '<button class=\"btn primary btn-full\" id=\"modalUnlockBtn\" onclick=\"doUnlock()\">Unlock</button>');\n"
    "        setTimeout(function() {\n"
    "            var inp = document.getElementById('modalUnlockInput');\n"
    "            if (inp) inp.focus();\n"
    "        }, 100);\n"
    "    } else {\n"
    "        showPassphraseModal('Lock', 'Enter passphrase to lock and unmount all vaults.', function(pass) {\n"
    "            if (!pass) { toast('Passphrase required', true); return; }\n"
    "            postAPI('/api/lock', pass).then(function(j) {\n"
    "                if (j.ok) authToken = null;\n"
    "                toast(j.msg || 'Locked', !j.ok);\n"
    "                fetchData();\n"
    "            }).catch(function() { toast('Failed to lock', true); });\n"
    "        });\n"
    "    }\n"
    "}\n"
    "\n"
    "function doUnlock() {\n"
    "    var inp = document.getElementById('modalUnlockInput');\n"
    "    var pass = inp ? inp.value : '';\n"
    "    if (!pass) return;\n"
    "    hideModal();\n"
    "    postAPI('/api/unlock', pass).then(function(j) {\n"
    "        if (j.ok && j.token) authToken = j.token;\n"
    "        toast(j.msg || (j.ok ? 'Unlocked' : 'Failed'), !j.ok);\n"
    "        fetchData();\n"
    "    }).catch(function() { toast('Failed to unlock', true); });\n"
    "}\n"
    "\n"
    "/* --- Touch ID --- */\n"
    "function doTouchIdUnlock() {\n"
    "    postAPI('/api/unlock-touchid', '').then(function(j) {\n"
    "        if (j.ok && j.token) authToken = j.token;\n"
    "        toast(j.msg || (j.ok ? 'Unlocked via Touch ID' : 'Touch ID failed'), !j.ok);\n"
    "        fetchData();\n"
    "    }).catch(function() { toast('Touch ID not available', true); });\n"
    "}\n"
    "\n"
    "/* --- Recovery --- */\n"
    "function showRecoveryPrompt() {\n"
    "    showPassphraseModal('View Recovery Key', 'Enter passphrase to view your recovery key.', function(pass) {\n"
    "        if (!pass) { toast('Passphrase required', true); return; }\n"
    "        postAPI('/api/export-recovery', pass).then(function(j) {\n"
    "            if (j.ok) {\n"
    "                showModal('Recovery Key', '<p>Store this key securely. You will need it if you forget your passphrase.</p>' +\n"
    "                    '<pre style=\"font-size:16px;text-align:center;letter-spacing:2px;padding:16px\">' + esc(j.key) + '</pre>');\n"
    "            } else {\n"
    "                toast(j.msg || 'Failed', true);\n"
    "            }\n"
    "        }).catch(function() { toast('Failed', true); });\n"
    "    });\n"
    "}\n"
    "\n"
    "function showRecoverPrompt() {\n"
    "    showModal('Recovery Unlock', '<p>Enter your 24-character recovery key and a new passphrase.</p>' +\n"
    "        '<input class=\"form-input\" id=\"modalRecKeyInput\" placeholder=\"Recovery key (24 chars)\" style=\"margin-bottom:8px\">' +\n"
    "        '<input type=\"password\" class=\"form-input\" id=\"modalRecPassInput\" placeholder=\"New passphrase\" style=\"margin-bottom:8px\">' +\n"
    "        '<input type=\"password\" class=\"form-input\" id=\"modalRecPass2Input\" placeholder=\"Confirm new passphrase\">' +\n"
    "        '<button class=\"btn primary btn-full\" id=\"modalRecBtn\" onclick=\"doRecover()\">Recover</button>');\n"
    "    setTimeout(function() {\n"
    "        var inp = document.getElementById('modalRecKeyInput');\n"
    "        if (inp) inp.focus();\n"
    "    }, 100);\n"
    "}\n"
    "\n"
    "function doRecover() {\n"
    "    var key = (document.getElementById('modalRecKeyInput').value || '').trim();\n"
    "    var pass1 = document.getElementById('modalRecPassInput').value || '';\n"
    "    var pass2 = document.getElementById('modalRecPass2Input').value || '';\n"
    "    if (!key || !pass1) { toast('All fields required', true); return; }\n"
    "    if (pass1 !== pass2) { toast('Passphrases do not match', true); return; }\n"
    "    hideModal();\n"
    "    postAPI('/api/recover', key + '\\n' + pass1).then(function(j) {\n"
    "        if (j.ok && j.token) authToken = j.token;\n"
    "        toast(j.msg || (j.ok ? 'Recovered successfully' : 'Failed'), !j.ok);\n"
    "        fetchData();\n"
    "    }).catch(function() { toast('Recovery failed', true); });\n"
    "}\n"
    "\n"
    "/* --- Key Rotation --- */\n"
    "function showRotatePrompt() {\n"
    "    showPassphraseModal('Rotate Keys', 'This will re-encrypt all vault files with a new master key. This may take a while for large vaults.', function(pass) {\n"
    "        if (!pass) { toast('Passphrase required', true); return; }\n"
    "        toast('Rotating keys...', false);\n"
    "        postAPI('/api/rotate-keys', pass).then(function(j) {\n"
    "            toast(j.msg || (j.ok ? 'Keys rotated' : 'Failed'), !j.ok);\n"
    "            fetchData();\n"
    "        }).catch(function() { toast('Rotation failed', true); });\n"
    "    });\n"
    "}\n"
    "\n"
    "/* --- Modal --- */\n"
    "function showModal(title, bodyHtml) {\n"
    "    document.getElementById('modalTitle').textContent = title;\n"
    "    document.getElementById('modalBody').innerHTML = bodyHtml;\n"
    "    document.getElementById('modalOverlay').className = 'modal-overlay show';\n"
    "    notifyResize();\n"
    "}\n"
    "\n"
    "function hideModal() {\n"
    "    document.getElementById('modalOverlay').className = 'modal-overlay';\n"
    "    window._pendingPassCallback = null;\n"
    "    notifyResize();\n"
    "}\n"
    "\n"
    "/* --- Session refresh --- */\n"
    "function refreshSession() {\n"
    "    if (!authToken) return;\n"
    "    var tp = tokenParam();\n"
    "    fetch(API + '/api/session-refresh' + tp).catch(function() {});\n"
    "}\n"
    "\n"
    "/* --- Init --- */\n"
    "fetchData();\n"
    "if (_refreshInterval) clearInterval(_refreshInterval);\n"
    "_refreshInterval = setInterval(fetchData, 5000);\n"
    "setInterval(refreshSession, 600000); /* every 10 min */\n"
    "</script>\n"
    "</body>\n"
    "</html>\n"
    ;
}

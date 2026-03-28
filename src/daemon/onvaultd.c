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

/* Challenge-response nonce for auth-gated commands.
 * Single-use: invalidated after one verification attempt. */
static uint8_t g_auth_nonce[ONVAULT_HASH_SIZE];
static int g_nonce_valid = 0;
static pthread_mutex_t g_nonce_lock = PTHREAD_MUTEX_INITIALIZER;

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

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static int g_log_initialized = 0;

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
    char ids[32][64];
    int count = onvault_vault_list(ids, 32);
    for (int i = 0; i < count; i++) {
        char mount_dir[PATH_MAX];
        onvault_vault_get_paths(ids[i], NULL, mount_dir, NULL);
        if (onvault_fuse_is_mounted(mount_dir))
            onvault_fuse_unmount(mount_dir);
    }

    /* Stop ESF */
    onvault_esf_stop();

    /* Clear policies */
    onvault_policy_clear();

    /* Wipe master key */
    if (g_master_key_loaded) {
        onvault_key_wipe(&g_master_key, sizeof(g_master_key));
        g_master_key_loaded = 0;
    }

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
                           "onvaultd running, %d vault(s)\n", count);
        for (int i = 0; i < count; i++) {
            char mount_dir[PATH_MAX], source[PATH_MAX];
            onvault_vault_get_paths(ids[i], NULL, mount_dir, source);
            int mounted = onvault_fuse_is_mounted(mount_dir);
            off += snprintf(resp_buf + off, sizeof(resp_buf) - (size_t)off,
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
            onvault_vault_id_from_path(add_path, vid, sizeof(vid));

            int off = snprintf(resp_buf, sizeof(resp_buf), "Vault added: %s\n", add_path);

            if (smart_defaults) {
                apply_smart_defaults(vid);
                char rules_buf[2048];
                int nrules = onvault_policy_get_rules(vid, rules_buf, sizeof(rules_buf));
                if (nrules > 0) {
                    off += snprintf(resp_buf + off, sizeof(resp_buf) - (size_t)off,
                                    "\nSmart defaults applied (%d rules):\n%s", nrules, rules_buf);
                }
            } else {
                off += snprintf(resp_buf + off, sizeof(resp_buf) - (size_t)off,
                                "No smart defaults applied. Use --smart to auto-populate allowlist.\n");
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
        /* Consume the nonce (single-use) */
        pthread_mutex_lock(&g_nonce_lock);
        if (!g_nonce_valid) {
            pthread_mutex_unlock(&g_nonce_lock);
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "No challenge issued\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        uint8_t rm_nonce[ONVAULT_HASH_SIZE];
        memcpy(rm_nonce, g_auth_nonce, ONVAULT_HASH_SIZE);
        g_nonce_valid = 0;
        onvault_memzero(g_auth_nonce, ONVAULT_HASH_SIZE);
        pthread_mutex_unlock(&g_nonce_lock);

        int rm_auth = onvault_auth_verify_proof(
            (const uint8_t *)payload, rm_nonce, ONVAULT_HASH_SIZE);
        onvault_memzero(rm_nonce, sizeof(rm_nonce));
        if (rm_auth != ONVAULT_OK) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf), "Wrong passphrase\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        const char *vault_id = payload + ONVAULT_HASH_SIZE;
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
            off += snprintf(resp_buf + off, sizeof(resp_buf) - (size_t)off,
                            "%s → %s\n", ids[i], source);
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_UNLOCK: {
        /* CLI has already verified passphrase and stored a session.
         * Daemon loads the master key from session/Keychain. */
        if (g_master_key_loaded) {
            snprintf(resp_buf, sizeof(resp_buf), "Already unlocked\n");
        } else {
            int urc = onvault_auth_check_session(&g_master_key);
            if (urc == ONVAULT_OK) {
                g_master_key_loaded = 1;

                /* Initialize audit logging */
                if (!g_log_initialized) {
                    onvault_key_t config_key;
                    onvault_mlock(&config_key, sizeof(config_key));
                    onvault_derive_config_key(&g_master_key, &config_key);
                    if (onvault_log_init(&config_key) == ONVAULT_OK)
                        g_log_initialized = 1;
                    onvault_key_wipe(&config_key, sizeof(config_key));
                }

                snprintf(resp_buf, sizeof(resp_buf), "Unlocked\n");
            } else {
                resp.status = IPC_RESP_AUTH_REQUIRED;
                snprintf(resp_buf, sizeof(resp_buf), "Unlock failed (err=%d)\n", urc);
            }
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_AUTH_CHALLENGE: {
        /* Issue a fresh random nonce for challenge-response */
        pthread_mutex_lock(&g_nonce_lock);
        onvault_random_bytes(g_auth_nonce, ONVAULT_HASH_SIZE);
        g_nonce_valid = 1;
        memcpy(resp_buf, g_auth_nonce, ONVAULT_HASH_SIZE);
        resp.payload_len = ONVAULT_HASH_SIZE;
        pthread_mutex_unlock(&g_nonce_lock);
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
        /* Consume the nonce (single-use) */
        pthread_mutex_lock(&g_nonce_lock);
        if (!g_nonce_valid) {
            pthread_mutex_unlock(&g_nonce_lock);
            resp.status = IPC_RESP_AUTH_REQUIRED;
            snprintf(resp_buf, sizeof(resp_buf),
                     "No challenge issued. Request IPC_CMD_AUTH_CHALLENGE first.\n");
            resp.payload_len = (uint32_t)strlen(resp_buf);
            break;
        }
        uint8_t nonce_copy[ONVAULT_HASH_SIZE];
        memcpy(nonce_copy, g_auth_nonce, ONVAULT_HASH_SIZE);
        g_nonce_valid = 0; /* Invalidate — single use */
        onvault_memzero(g_auth_nonce, ONVAULT_HASH_SIZE);
        pthread_mutex_unlock(&g_nonce_lock);

        int lock_auth = onvault_auth_verify_proof(
            (const uint8_t *)payload, nonce_copy, ONVAULT_HASH_SIZE);
        onvault_memzero(nonce_copy, sizeof(nonce_copy));

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
        /* payload: "process_path\0vault_id" */
        char *sep = memchr(payload, '\0', header.payload_len);
        if (sep && sep < payload + header.payload_len - 1) {
            char *process_path = payload;
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
        /* payload: "process_path\0vault_id" */
        char *sep = memchr(payload, '\0', header.payload_len);
        if (sep && sep < payload + header.payload_len - 1) {
            char *process_path = payload;
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
                off += snprintf(resp_buf + off, sizeof(resp_buf) - (size_t)off,
                                "  [%d] %s (%s, %d accesses)",
                                i + 1, entries[i].path, signed_str,
                                entries[i].access_count);
                if (entries[i].team_id[0])
                    off += snprintf(resp_buf + off, sizeof(resp_buf) - (size_t)off,
                                    " team=%s", entries[i].team_id);
                off += snprintf(resp_buf + off, sizeof(resp_buf) - (size_t)off, "\n");
            }
            off += snprintf(resp_buf + off, sizeof(resp_buf) - (size_t)off,
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
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_code == 200 ? "OK" : "Error",
        content_type, body_len);
    write(fd, header, (size_t)hlen);
    if (body_len > 0)
        write(fd, body, body_len);
}

static void handle_http_client(int client_fd)
{
    char request[4096] = {0};
    ssize_t n = read(client_fd, request, sizeof(request) - 1);
    if (n <= 0) { close(client_fd); return; }

    /* Parse first line: GET /path HTTP/1.1 */
    char method[16] = {0}, path[256] = {0};
    sscanf(request, "%15s %255s", method, path);

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
            onvault_vault_get_paths(ids[i], NULL, mount_dir, source);
            int mounted = onvault_fuse_is_mounted(mount_dir);
            if (i > 0) off += snprintf(json + off, sizeof(json) - (size_t)off, ",");
            off += snprintf(json + off, sizeof(json) - (size_t)off,
                "{\"id\":\"%s\",\"source\":\"%s\",\"mounted\":%s}",
                ids[i], source, mounted ? "true" : "false");
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
            if (i > 0) off += snprintf(json + off, sizeof(json) - (size_t)off, ",");
            off += snprintf(json + off, sizeof(json) - (size_t)off,
                "{\"process\":\"%s\",\"path\":\"%s\",\"file\":\"%s\","
                "\"vault\":\"%s\",\"time\":%ld}",
                d->process_name, d->process_path, d->file_path,
                d->vault_id, (long)d->timestamp);
        }
        pthread_mutex_unlock(&g_denial_lock);
        off += snprintf(json + off, sizeof(json) - (size_t)off, "]");
        http_respond(client_fd, 200, "application/json", json, (size_t)off);
    } else {
        const char *msg = "Not Found";
        http_respond(client_fd, 404, "text/plain", msg, strlen(msg));
    }

    close(client_fd);
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
            if (client_fd >= 0)
                handle_http_client(client_fd);
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
    "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>onvault</title>\n<style>\n:root {\n    color-scheme: dark;\n    --bg: #0d0d0d;\n    --panel: rgba(18, 18, 18, 0.98);\n    --card: rgba(26, 26, 26, 0.96);\n    --card-hover: rgba(34, 34, 34, 0.98);\n    --border: rgba(255, 255, 255, 0.08);\n    --text: #ffffff;\n    --text-soft: rgba(255, 255, 255, 0.72);\n    --text-muted: rgba(255, 255, 255, 0"
    ".42);\n    --green: #22c55e;\n    --green-dim: rgba(34, 197, 94, 0.15);\n    --red: #ef4444;\n    --red-dim: rgba(239, 68, 68, 0.15);\n    --orange: #f59e0b;\n    --orange-dim: rgba(245, 158, 11, 0.15);\n    --blue: #3b82f6;\n    --blue-dim: rgba(59, 130, 246, 0.12);\n    --radius: 10px;\n    --radius-sm: 6px;\n}\n* { margin: 0; padding: 0; box-sizing: border-box; }\nbody {\n    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', system-ui, sans-serif;\n    background: var(--bg);\n   "
    " color: var(--text);\n    width: 300px;\n    min-height: 200px;\n    font-size: 12px;\n    -webkit-font-smoothing: antialiased;\n    overflow-x: hidden;\n}\n\n/* Header */\n.header {\n    display: flex; align-items: center; justify-content: space-between;\n    padding: 14px 16px 10px;\n    border-bottom: 1px solid var(--border);\n}\n.header .logo {\n    display: flex; align-items: center; gap: 8px;\n    font-weight: 600; font-size: 13px;\n}\n.header .logo svg { width: 18px; height: 18px; }\n.sta"
    "tus-badge {\n    font-size: 10px; padding: 3px 8px; border-radius: 20px;\n    font-weight: 500;\n}\n.status-badge.locked { background: var(--red-dim); color: var(--red); }\n.status-badge.unlocked { background: var(--green-dim); color: var(--green); }\n\n/* Section */\n.section { padding: 8px 12px; }\n.section-title {\n    font-size: 10px; font-weight: 600; text-transform: uppercase;\n    letter-spacing: 0.5px; color: var(--text-muted); padding: 4px 4px 6px;\n}\n\n/* Vault cards */\n.vault-card {"
    "\n    background: var(--card); border-radius: var(--radius);\n    padding: 10px 12px; margin-bottom: 6px;\n    border: 1px solid var(--border);\n    cursor: pointer; transition: background 0.15s;\n}\n.vault-card:hover { background: var(--card-hover); }\n.vault-card .vault-row {\n    display: flex; align-items: center; justify-content: space-between;\n}\n.vault-card .vault-name {\n    font-weight: 600; font-size: 12px;\n    display: flex; align-items: center; gap: 6px;\n}\n.vault-card .vault-name"
    " .icon { font-size: 14px; }\n.vault-card .vault-source {\n    font-size: 10px; color: var(--text-muted); margin-top: 2px;\n    font-family: 'SF Mono', Menlo, monospace;\n}\n.vault-card .vault-status {\n    font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: 500;\n}\n.vault-card .vault-status.mounted { background: var(--green-dim); color: var(--green); }\n.vault-card .vault-status.locked { background: var(--red-dim); color: var(--red); }\n\n/* Vault detail panel (hidden by default"
    ") */\n.vault-detail {\n    display: none; margin-top: 8px; padding-top: 8px;\n    border-top: 1px solid var(--border);\n}\n.vault-card.expanded .vault-detail { display: block; }\n.vault-actions {\n    display: flex; gap: 4px; flex-wrap: wrap;\n}\n.vault-actions button {\n    font-size: 10px; padding: 4px 10px; border-radius: var(--radius-sm);\n    border: 1px solid var(--border); background: transparent;\n    color: var(--text-soft); cursor: pointer; transition: all 0.15s;\n    font-family: inhe"
    "rit;\n}\n.vault-actions button:hover {\n    background: var(--blue-dim); color: var(--blue); border-color: rgba(59, 130, 246, 0.3);\n}\n.vault-actions button.danger:hover {\n    background: var(--red-dim); color: var(--red); border-color: rgba(239, 68, 68, 0.3);\n}\n\n/* Denial cards */\n.denial-card {\n    background: var(--card); border-radius: var(--radius-sm);\n    padding: 8px 10px; margin-bottom: 4px;\n    border: 1px solid var(--border); font-size: 11px;\n    display: flex; align-items: c"
    "enter; justify-content: space-between;\n}\n.denial-info { flex: 1; }\n.denial-proc { font-weight: 600; color: var(--orange); }\n.denial-file { font-size: 10px; color: var(--text-muted); font-family: 'SF Mono', Menlo, monospace; }\n.denial-time { font-size: 9px; color: var(--text-muted); white-space: nowrap; margin-left: 8px; }\n.denial-allow {\n    font-size: 9px; padding: 2px 6px; border-radius: 4px;\n    border: 1px solid rgba(34, 197, 94, 0.3); background: var(--green-dim);\n    color: var(--"
    "green); cursor: pointer; margin-left: 6px; font-family: inherit;\n}\n\n/* Empty state */\n.empty {\n    text-align: center; padding: 16px; color: var(--text-muted); font-size: 11px;\n}\n\n/* Action buttons */\n.action-bar {\n    display: flex; gap: 6px; padding: 8px 12px;\n    border-top: 1px solid var(--border);\n}\n.action-bar button {\n    flex: 1; padding: 8px; border-radius: var(--radius-sm);\n    border: 1px solid var(--border); background: var(--card);\n    color: var(--text-soft); cursor"
    ": pointer; font-size: 11px;\n    font-weight: 500; transition: all 0.15s; font-family: inherit;\n}\n.action-bar button:hover {\n    background: var(--card-hover); color: var(--text);\n}\n.action-bar button.primary {\n    background: var(--blue-dim); color: var(--blue);\n    border-color: rgba(59, 130, 246, 0.25);\n}\n.action-bar button.primary:hover {\n    background: rgba(59, 130, 246, 0.2); border-color: rgba(59, 130, 246, 0.4);\n}\n\n/* Footer */\n.footer {\n    display: flex; align-items: ce"
    "nter; justify-content: space-between;\n    padding: 8px 16px; border-top: 1px solid var(--border);\n    font-size: 10px; color: var(--text-muted);\n}\n.footer a { color: var(--text-muted); text-decoration: none; }\n.footer a:hover { color: var(--text-soft); }\n\n/* Refresh spinner */\n@keyframes spin { to { transform: rotate(360deg); } }\n.spinning { animation: spin 1s linear infinite; display: inline-block; }\n\n/* No vaults state */\n.add-vault-prompt {\n    text-align: center; padding: 20px 1"
    "6px;\n}\n.add-vault-prompt .icon { font-size: 28px; margin-bottom: 8px; }\n.add-vault-prompt p { color: var(--text-muted); margin-bottom: 12px; font-size: 11px; }\n.add-vault-prompt button {\n    padding: 8px 20px; border-radius: var(--radius-sm);\n    background: var(--green-dim); color: var(--green);\n    border: 1px solid rgba(34, 197, 94, 0.3);\n    cursor: pointer; font-size: 12px; font-weight: 500; font-family: inherit;\n}\n</style>\n</head>\n<body>\n\n<div class=\"header\">\n    <div clas"
    "s=\"logo\">\n        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\">\n            <rect x=\"3\" y=\"11\" width=\"18\" height=\"11\" rx=\"2\" ry=\"2\"/>\n            <path d=\"M7 11V7a5 5 0 0 1 10 0v4\"/>\n        </svg>\n        onvault\n    </div>\n    <span class=\"status-badge locked\" id=\"statusBadge\">Locked</span>\n</div>\n\n<div id=\"vaultSection\" class=\"section\">\n    <div class=\"section-title\">Vaults</div>\n    <div id=\"vaultList\"></div>\n</d"
    "iv>\n\n<div id=\"denialSection\" class=\"section\" style=\"display:none\">\n    <div class=\"section-title\">Recent Denials</div>\n    <div id=\"denialList\"></div>\n</div>\n\n<div class=\"action-bar\">\n    <button class=\"primary\" onclick=\"addVault()\">+ Add Vault</button>\n    <button onclick=\"viewPolicies()\">Policies</button>\n    <button onclick=\"refresh()\" id=\"refreshBtn\">Refresh</button>\n</div>\n\n<div class=\"footer\">\n    <span>onvault 0.1.0</span>\n    <span id=\"lastUpdate\""
    ">—</span>\n</div>\n\n<script>\nconst API = window.location.origin;\nlet data = { locked: true, vault_count: 0, vaults: [] };\nlet denials = [];\n\nasync function fetchData() {\n    try {\n        const [statusRes, denialsRes] = await Promise.all([\n            fetch(API + '/api/status'),\n            fetch(API + '/api/denials')\n        ]);\n        data = await statusRes.json();\n        denials = await denialsRes.json();\n    } catch (e) {\n        data = { locked: true, vault_count: 0, vaults"
    ": [] };\n        denials = [];\n    }\n    render();\n}\n\nfunction timeAgo(ts) {\n    const secs = Math.floor(Date.now() / 1000) - ts;\n    if (secs < 60) return secs + 's ago';\n    if (secs < 3600) return Math.floor(secs / 60) + 'm ago';\n    return Math.floor(secs / 3600) + 'h ago';\n}\n\nfunction render() {\n    // Status badge\n    const badge = document.getElementById('statusBadge');\n    if (data.locked) {\n        badge.className = 'status-badge locked';\n        badge.textContent = 'Lo"
    "cked';\n    } else {\n        badge.className = 'status-badge unlocked';\n        badge.textContent = data.vault_count + ' vault(s)';\n    }\n\n    // Vaults\n    const vaultList = document.getElementById('vaultList');\n    if (data.vaults.length === 0) {\n        vaultList.innerHTML = '<div class=\"add-vault-prompt\">' +\n            '<div class=\"icon\">🔒</div>' +\n            '<p>No vaults configured yet.<br>Protect your first directory.</p>' +\n            '</div>';\n    } else {\n        va"
    "ultList.innerHTML = data.vaults.map(v =>\n            '<div class=\"vault-card\" onclick=\"toggleVault(this)\">' +\n                '<div class=\"vault-row\">' +\n                    '<div class=\"vault-name\">' +\n                        '<span class=\"icon\">' + (v.mounted ? '🔓' : '🔒') + '</span>' +\n                        v.id +\n                    '</div>' +\n                    '<span class=\"vault-status ' + (v.mounted ? 'mounted' : 'locked') + '\">' +\n                        (v.mounted"
    " ? 'Active' : 'Locked') +\n                    '</span>' +\n                '</div>' +\n                '<div class=\"vault-source\">' + v.source + '</div>' +\n                '<div class=\"vault-detail\">' +\n                    '<div class=\"vault-actions\">' +\n                        '<button onclick=\"event.stopPropagation();viewRules(\\'' + v.id + '\\')\">View Rules</button>' +\n                        '<button onclick=\"event.stopPropagation();allowProcess(\\'' + v.id + '\\')\">Allow Proc"
    "ess</button>' +\n                        '<button onclick=\"event.stopPropagation();denyProcess(\\'' + v.id + '\\')\">Deny Process</button>' +\n                        '<button class=\"danger\" onclick=\"event.stopPropagation();removeVault(\\'' + v.id + '\\')\">Remove</button>' +\n                    '</div>' +\n                '</div>' +\n            '</div>'\n        ).join('');\n    }\n\n    // Denials\n    const denialSection = document.getElementById('denialSection');\n    const denialList "
    "= document.getElementById('denialList');\n    if (denials.length > 0) {\n        denialSection.style.display = 'block';\n        denialList.innerHTML = denials.slice(-5).reverse().map(d =>\n            '<div class=\"denial-card\">' +\n                '<div class=\"denial-info\">' +\n                    '<span class=\"denial-proc\">' + d.process + '</span>' +\n                    ' → ' + d.vault +\n                    '<div class=\"denial-file\">' + d.file + '</div>' +\n                '</div>' +"
    "\n                '<span class=\"denial-time\">' + timeAgo(d.time) + '</span>' +\n                '<button class=\"denial-allow\" onclick=\"allowDenied(\\'' + d.path + '\\',\\'' + d.vault + '\\')\">Allow</button>' +\n            '</div>'\n        ).join('');\n    } else {\n        denialSection.style.display = 'none';\n    }\n\n    document.getElementById('lastUpdate').textContent =\n        new Date().toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});\n}\n\nfunction toggleVault(el) {"
    " el.classList.toggle('expanded'); }\n\nasync function refresh() {\n    const btn = document.getElementById('refreshBtn');\n    btn.innerHTML = '<span class=\"spinning\">↻</span>';\n    await fetchData();\n    btn.textContent = 'Refresh';\n}\n\nfunction addVault() { alert('Use CLI: onvault vault add <path> --smart'); }\nfunction viewPolicies() { window.open(API + '/api/policies', '_blank'); }\nfunction viewRules(id) { alert('Use CLI: onvault rules ' + id); }\nfunction allowProcess(id) { alert('Us"
    "e CLI: onvault allow <process_path> ' + id); }\nfunction denyProcess(id) { alert('Use CLI: onvault deny <process_path> ' + id); }\nfunction removeVault(id) { alert('Use CLI: onvault vault remove ' + id); }\nfunction allowDenied(path, vault) { alert('Use CLI: onvault allow ' + path + ' ' + vault); }\n\n// Auto-refresh\nfetchData();\nsetInterval(fetchData, 5000);\n</script>\n</body>\n</html>\n"
    ;
}

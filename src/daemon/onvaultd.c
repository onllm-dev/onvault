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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

static volatile int g_running = 1;
static onvault_key_t g_master_key;
static int g_master_key_loaded = 0;

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static int g_log_initialized = 0;

static void cleanup(void)
{
    fprintf(stderr, "onvaultd: shutting down\n");

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

/* Handle IPC commands from CLI */
static void handle_client(int client_fd)
{
    onvault_ipc_header_t header;
    ssize_t n = read(client_fd, &header, sizeof(header));
    if (n != sizeof(header)) {
        close(client_fd);
        return;
    }

    /* Read payload if any */
    char payload[ONVAULT_IPC_MAX_MSG] = {0};
    if (header.payload_len > 0 && header.payload_len < ONVAULT_IPC_MAX_MSG) {
        ssize_t pn = read(client_fd, payload, header.payload_len);
        if (pn <= 0) {
            close(client_fd);
            return;
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
        int rc = onvault_vault_add(&g_master_key, payload, NULL);
        if (rc != ONVAULT_OK) {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf), "Failed to add vault (err=%d)\n", rc);
        } else {
            snprintf(resp_buf, sizeof(resp_buf), "Vault added: %s\n", payload);
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_VAULT_REMOVE: {
        if (!g_master_key_loaded) {
            resp.status = IPC_RESP_AUTH_REQUIRED;
            break;
        }
        int rc = onvault_vault_remove(&g_master_key, payload);
        if (rc != ONVAULT_OK) {
            resp.status = IPC_RESP_ERROR;
            snprintf(resp_buf, sizeof(resp_buf), "Failed to remove vault (err=%d)\n", rc);
        } else {
            snprintf(resp_buf, sizeof(resp_buf), "Vault removed: %s\n", payload);
        }
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;
    }

    case IPC_CMD_VAULT_LIST: {
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

    case IPC_CMD_LOCK:
        /* Signal main loop to exit — cleanup happens there */
        g_running = 0;
        snprintf(resp_buf, sizeof(resp_buf), "Locked\n");
        resp.payload_len = (uint32_t)strlen(resp_buf);
        break;

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

    /* Send macOS notification with Allow Once / Allow Always actions */
    const char *proc_name = strrchr(process->path, '/');
    proc_name = proc_name ? proc_name + 1 : process->path;
    onvault_menubar_notify_deny(proc_name, file_path, vault_id);
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
    {
        char salt_path[PATH_MAX];
        snprintf(salt_path, PATH_MAX, "%s/salt", data_dir);
        struct stat check_st;
        if (stat(salt_path, &check_st) != 0) {
            fprintf(stderr, "onvaultd: not initialized. Run 'onvault init' first.\n");
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

/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * onvault.c — CLI entry point
 */

#include "../common/types.h"
#include "../common/crypto.h"
#include "../common/ipc.h"
#include "../common/memwipe.h"
#include "../auth/auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>

static void usage(void)
{
    fprintf(stderr,
        "onvault — Seamless File Encryption & Access Control for macOS\n"
        "\n"
        "Usage: onvault <command> [args]\n"
        "\n"
        "Daemon:\n"
        "  start [--no-gui]              Start the daemon (menu bar + web UI)\n"
        "  stop                          Stop the daemon\n"
        "\n"
        "Setup:\n"
        "  init                          First-time setup\n"
        "  unlock                        Authenticate and mount vaults\n"
        "  lock                          Unmount vaults, wipe keys\n"
        "\n"
        "Vault management:\n"
        "  vault add <path> [--smart]    Encrypt and protect a directory\n"
        "  vault remove <vault_id>       Decrypt and unprotect a vault\n"
        "  vault list                    List all vaults\n"
        "  vault watch <path>            Learning mode (24h observation)\n"
        "  vault suggest <vault_id>      Show watch suggestions\n"
        "\n"
        "Access control:\n"
        "  allow <process> <vault_id>    Allow a process to access a vault\n"
        "  deny <process> <vault_id>     Deny a process from a vault\n"
        "  rules <vault_id>              Show rules for a vault\n"
        "\n"
        "Policy:\n"
        "  policy show                   Show current policy\n"
        "  policy edit                   Edit config in $EDITOR\n"
        "\n"
        "Configuration:\n"
        "  configure                     Interactive configuration\n"
        "\n"
        "Other:\n"
        "  status                        Show daemon and vault status\n"
        "  log [--denied] [--tail]       View audit log\n"
        "  rotate-keys                   Rotate master key\n"
        "  export-recovery               Show recovery key\n"
        "\n"
    );
}

/* Read passphrase without echoing */
static int read_passphrase(const char *prompt, char *buf, size_t buf_len)
{
    fprintf(stderr, "%s", prompt);

    struct termios old, new;
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    if (fgets(buf, (int)buf_len, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        return -1;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    fprintf(stderr, "\n");

    /* Strip newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    return 0;
}

static int cmd_init(void)
{
    if (onvault_auth_is_initialized()) {
        fprintf(stderr, "onvault is already initialized.\n");
        fprintf(stderr, "To reset, delete ~/.onvault/ and run init again.\n");
        return 1;
    }

    char pass1[256], pass2[256];
    read_passphrase("Set passphrase: ", pass1, sizeof(pass1));
    read_passphrase("Confirm passphrase: ", pass2, sizeof(pass2));

    if (strcmp(pass1, pass2) != 0) {
        fprintf(stderr, "Passphrases don't match.\n");
        onvault_memzero(pass1, sizeof(pass1));
        onvault_memzero(pass2, sizeof(pass2));
        return 1;
    }

    if (strlen(pass1) < 8) {
        fprintf(stderr, "Passphrase must be at least 8 characters.\n");
        onvault_memzero(pass1, sizeof(pass1));
        onvault_memzero(pass2, sizeof(pass2));
        return 1;
    }

    char recovery_key[ONVAULT_RECOVERY_LEN + 1];

    onvault_crypto_init();
    int rc = onvault_auth_init(pass1, recovery_key);

    onvault_memzero(pass1, sizeof(pass1));
    onvault_memzero(pass2, sizeof(pass2));

    if (rc != ONVAULT_OK) {
        fprintf(stderr, "Initialization failed (err=%d)\n", rc);
        return 1;
    }

    printf("onvault initialized.\n\n");
    printf("Recovery key (save this somewhere safe):\n");
    printf("  %s\n\n", recovery_key);
    printf("Run 'onvault unlock' to start, then 'onvault vault add <path>' to protect files.\n");

    onvault_memzero(recovery_key, sizeof(recovery_key));
    return 0;
}

static int cmd_unlock(void)
{
    char pass[256];
    read_passphrase("Passphrase: ", pass, sizeof(pass));

    onvault_crypto_init();
    onvault_key_t master_key;
    int rc = onvault_auth_unlock(pass, &master_key);
    onvault_memzero(pass, sizeof(pass));

    if (rc != ONVAULT_OK) {
        if (rc == ONVAULT_ERR_AUTH)
            fprintf(stderr, "Wrong passphrase.\n");
        else
            fprintf(stderr, "Unlock failed (err=%d)\n", rc);
        return 1;
    }

    onvault_key_wipe(&master_key, sizeof(master_key));

    /* Notify daemon to load the master key from session */
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int ipc_rc = onvault_ipc_send(IPC_CMD_UNLOCK, NULL, 0, response, &resp_len);
    if (ipc_rc != ONVAULT_OK) {
        printf("Unlocked (daemon not running — start with: onvaultd)\n");
    } else {
        printf("Unlocked. Vaults are now accessible.\n");
    }
    return 0;
}

/* Request a challenge nonce from the daemon, compute proof, return it.
 * Prompts the user for passphrase.
 * proof_out: 32-byte proof buffer
 * Returns 0 on success. */
static int auth_challenge_response(const char *prompt, uint8_t *proof_out)
{
    char pass[256];
    read_passphrase(prompt, pass, sizeof(pass));

    /* Step 1: Request challenge nonce from daemon */
    uint8_t nonce[ONVAULT_HASH_SIZE];
    uint32_t nonce_len = sizeof(nonce);
    int rc = onvault_ipc_send(IPC_CMD_AUTH_CHALLENGE, NULL, 0,
                               nonce, &nonce_len);
    if (rc != ONVAULT_OK || nonce_len != ONVAULT_HASH_SIZE) {
        onvault_memzero(pass, sizeof(pass));
        fprintf(stderr, "Failed to get auth challenge (daemon not running?)\n");
        return 1;
    }

    /* Step 2: Compute proof = SHA-256(derived_key || nonce) */
    onvault_crypto_init();
    int auth_rc = onvault_auth_compute_proof(pass, nonce, nonce_len, proof_out);
    onvault_memzero(pass, sizeof(pass));
    onvault_memzero(nonce, sizeof(nonce));

    if (auth_rc != ONVAULT_OK) {
        fprintf(stderr, "Authentication failed.\n");
        return 1;
    }
    return 0;
}

static int cmd_lock(void)
{
    uint8_t proof[ONVAULT_HASH_SIZE];
    if (auth_challenge_response("Passphrase (required to lock): ", proof) != 0)
        return 1;

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_LOCK, proof, ONVAULT_HASH_SIZE,
                               response, &resp_len);
    onvault_memzero(proof, sizeof(proof));

    if (rc == ONVAULT_ERR_AUTH) {
        fprintf(stderr, "Wrong passphrase.\n");
        return 1;
    }
    if (rc != ONVAULT_OK) {
        fprintf(stderr, "Failed to lock (daemon not running?)\n");
        return 1;
    }

    printf("Locked. All vaults unmounted.\n");
    return 0;
}

static int cmd_status(void)
{
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_STATUS, NULL, 0, response, &resp_len);

    if (rc != ONVAULT_OK) {
        fprintf(stderr, "Daemon not running. Start with: onvaultd\n");
        return 1;
    }

    response[resp_len] = '\0';
    printf("%s", response);
    return 0;
}

static int cmd_vault_add(const char *path, int smart_defaults)
{
    if (!path) {
        fprintf(stderr, "Usage: onvault vault add <path> [--smart]\n");
        return 1;
    }

    /* Resolve to absolute path before sending to daemon
     * (daemon may have a different CWD) */
    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) {
        fprintf(stderr, "Path not found: %s\n", path);
        return 1;
    }

    /* Payload: flags(1) + path */
    char payload[1 + PATH_MAX];
    payload[0] = (char)smart_defaults; /* 1 = apply smart defaults */
    size_t plen = strlen(resolved) + 1;
    memcpy(payload + 1, resolved, plen);

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_VAULT_ADD,
                               payload, (uint32_t)(1 + plen),
                               response, &resp_len);

    if (rc == ONVAULT_ERR_AUTH) {
        fprintf(stderr, "Unlock required first. Run: onvault unlock\n");
        return 1;
    }
    if (rc != ONVAULT_OK) {
        response[resp_len] = '\0';
        fprintf(stderr, "%s", response);
        return 1;
    }

    response[resp_len] = '\0';
    printf("%s", response);
    return 0;
}

static int cmd_vault_remove(const char *vault_id)
{
    if (!vault_id) {
        fprintf(stderr, "Usage: onvault vault remove <vault_id>\n");
        return 1;
    }

    /* Require passphrase — vault removal decrypts files back to disk */
    uint8_t proof[ONVAULT_HASH_SIZE];
    if (auth_challenge_response("Passphrase (required to remove vault): ", proof) != 0)
        return 1;

    /* Pack: proof(32) + vault_id */
    size_t vid_len = strlen(vault_id) + 1;
    char payload[ONVAULT_HASH_SIZE + PATH_MAX];
    memcpy(payload, proof, ONVAULT_HASH_SIZE);
    memcpy(payload + ONVAULT_HASH_SIZE, vault_id, vid_len);
    onvault_memzero(proof, sizeof(proof));

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_VAULT_REMOVE,
                               payload, (uint32_t)(ONVAULT_HASH_SIZE + vid_len),
                               response, &resp_len);

    if (rc == ONVAULT_ERR_AUTH) {
        fprintf(stderr, "Wrong passphrase.\n");
        return 1;
    }
    if (rc != ONVAULT_OK) {
        response[resp_len] = '\0';
        fprintf(stderr, "%s", response);
        return 1;
    }

    response[resp_len] = '\0';
    printf("%s", response);
    return 0;
}

static int cmd_vault_list(void)
{
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_VAULT_LIST, NULL, 0, response, &resp_len);

    if (rc != ONVAULT_OK) {
        fprintf(stderr, "Daemon not running.\n");
        return 1;
    }

    response[resp_len] = '\0';
    if (resp_len == 0)
        printf("No vaults configured.\n");
    else
        printf("%s", response);
    return 0;
}

static int cmd_allow(const char *process, const char *vault_id)
{
    if (!process || !vault_id) {
        fprintf(stderr, "Usage: onvault allow <process_path> <vault_id>\n");
        return 1;
    }

    /* Pack: "process_path\0vault_id" */
    size_t plen = strlen(process);
    size_t vlen = strlen(vault_id);
    char payload[PATH_MAX + 64];
    memcpy(payload, process, plen + 1); /* includes \0 */
    memcpy(payload + plen + 1, vault_id, vlen + 1);

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_ALLOW,
                               payload, (uint32_t)(plen + 1 + vlen + 1),
                               response, &resp_len);

    response[resp_len] = '\0';
    if (rc != ONVAULT_OK)
        fprintf(stderr, "%s", response);
    else
        printf("%s", response);

    return (rc == ONVAULT_OK) ? 0 : 1;
}

static int cmd_deny(const char *process, const char *vault_id)
{
    if (!process || !vault_id) {
        fprintf(stderr, "Usage: onvault deny <process_path> <vault_id>\n");
        return 1;
    }

    /* Pack: "process_path\0vault_id" */
    size_t plen = strlen(process);
    size_t vlen = strlen(vault_id);
    char payload[PATH_MAX + 64];
    memcpy(payload, process, plen + 1);
    memcpy(payload + plen + 1, vault_id, vlen + 1);

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_DENY,
                               payload, (uint32_t)(plen + 1 + vlen + 1),
                               response, &resp_len);

    response[resp_len] = '\0';
    if (rc != ONVAULT_OK)
        fprintf(stderr, "%s", response);
    else
        printf("%s", response);

    return (rc == ONVAULT_OK) ? 0 : 1;
}

static int cmd_rules(const char *vault_id)
{
    if (!vault_id) {
        fprintf(stderr, "Usage: onvault rules <vault_id>\n");
        return 1;
    }

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_RULES,
                               vault_id, (uint32_t)strlen(vault_id) + 1,
                               response, &resp_len);

    if (rc != ONVAULT_OK) {
        fprintf(stderr, "Failed to get rules (daemon not running?)\n");
        return 1;
    }

    response[resp_len] = '\0';
    printf("%s", response);
    return 0;
}

static int cmd_log(int denied_only)
{
    char payload[4] = {0};
    payload[0] = (char)denied_only;

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_LOG,
                               payload, 1,
                               response, &resp_len);

    if (rc != ONVAULT_OK) {
        fprintf(stderr, "Failed to read logs (daemon not running?)\n");
        return 1;
    }

    response[resp_len] = '\0';
    if (resp_len == 0)
        printf("No log entries.\n");
    else
        printf("%s", response);
    return 0;
}

static int cmd_vault_watch(const char *path)
{
    if (!path) {
        fprintf(stderr, "Usage: onvault vault watch <path>\n");
        return 1;
    }

    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) {
        fprintf(stderr, "Path not found: %s\n", path);
        return 1;
    }

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_WATCH_START,
                               resolved, (uint32_t)strlen(resolved) + 1,
                               response, &resp_len);

    if (rc != ONVAULT_OK) {
        fprintf(stderr, "Failed to start watch (daemon not running?)\n");
        return 1;
    }

    response[resp_len] = '\0';
    printf("%s", response);
    return 0;
}

static int cmd_vault_suggest(const char *vault_id)
{
    if (!vault_id) {
        fprintf(stderr, "Usage: onvault vault suggest <vault_id>\n");
        return 1;
    }

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_WATCH_SUGGEST,
                               vault_id, (uint32_t)strlen(vault_id) + 1,
                               response, &resp_len);

    if (rc != ONVAULT_OK) {
        fprintf(stderr, "Failed to get suggestions (daemon not running?)\n");
        return 1;
    }

    response[resp_len] = '\0';
    if (resp_len == 0)
        printf("No watch data found for vault: %s\n", vault_id);
    else
        printf("%s", response);
    return 0;
}

static int cmd_policy_show(void)
{
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_POLICY_SHOW, NULL, 0, response, &resp_len);

    if (rc != ONVAULT_OK) {
        fprintf(stderr, "Failed to show policy (daemon not running?)\n");
        return 1;
    }

    response[resp_len] = '\0';
    printf("%s", response);
    return 0;
}

/* --- Interactive configuration --- */

static int read_choice(const char *prompt, int max)
{
    printf("%s", prompt);
    fflush(stdout);

    char buf[16];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return -1;

    int choice = atoi(buf);
    if (choice < 1 || choice > max)
        return -1;
    return choice;
}

static int configure_manage_vaults(void)
{
    /* Show vault list */
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_STATUS, NULL, 0, response, &resp_len);
    if (rc != ONVAULT_OK) {
        fprintf(stderr, "Daemon not running.\n");
        return 1;
    }
    response[resp_len] = '\0';
    printf("\nCurrent vaults:\n%s\n", response);

    printf("[1] Add a vault\n");
    printf("[2] Remove a vault\n");
    printf("[3] Back\n");

    int choice = read_choice("\nChoice: ", 3);
    if (choice == 1) {
        printf("Path to protect: ");
        fflush(stdout);
        char path[PATH_MAX];
        if (fgets(path, sizeof(path), stdin) == NULL)
            return 0;
        size_t plen = strlen(path);
        if (plen > 0 && path[plen - 1] == '\n')
            path[plen - 1] = '\0';

        printf("Apply smart defaults? [y/N]: ");
        fflush(stdout);
        char yn[8];
        if (fgets(yn, sizeof(yn), stdin) == NULL)
            return 0;
        int smart = (yn[0] == 'y' || yn[0] == 'Y') ? 1 : 0;

        return cmd_vault_add(path, smart);
    } else if (choice == 2) {
        printf("Vault ID to remove: ");
        fflush(stdout);
        char vid[64];
        if (fgets(vid, sizeof(vid), stdin) == NULL)
            return 0;
        size_t vlen = strlen(vid);
        if (vlen > 0 && vid[vlen - 1] == '\n')
            vid[vlen - 1] = '\0';

        return cmd_vault_remove(vid);
    }
    return 0;
}

static int configure_manage_rules(void)
{
    /* Show all policies */
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_POLICY_SHOW, NULL, 0, response, &resp_len);
    if (rc == ONVAULT_OK) {
        response[resp_len] = '\0';
        printf("\n%s", response);
    }

    printf("[1] Allow a process\n");
    printf("[2] Deny a process\n");
    printf("[3] View rules for a vault\n");
    printf("[4] Back\n");

    int choice = read_choice("\nChoice: ", 4);
    if (choice == 1 || choice == 2) {
        printf("Process path (e.g., /usr/bin/vim): ");
        fflush(stdout);
        char proc[PATH_MAX];
        if (fgets(proc, sizeof(proc), stdin) == NULL)
            return 0;
        size_t plen = strlen(proc);
        if (plen > 0 && proc[plen - 1] == '\n')
            proc[plen - 1] = '\0';

        printf("Vault ID (e.g., ssh): ");
        fflush(stdout);
        char vid[64];
        if (fgets(vid, sizeof(vid), stdin) == NULL)
            return 0;
        size_t vlen = strlen(vid);
        if (vlen > 0 && vid[vlen - 1] == '\n')
            vid[vlen - 1] = '\0';

        if (choice == 1)
            return cmd_allow(proc, vid);
        else
            return cmd_deny(proc, vid);
    } else if (choice == 3) {
        printf("Vault ID: ");
        fflush(stdout);
        char vid[64];
        if (fgets(vid, sizeof(vid), stdin) == NULL)
            return 0;
        size_t vlen = strlen(vid);
        if (vlen > 0 && vid[vlen - 1] == '\n')
            vid[vlen - 1] = '\0';
        return cmd_rules(vid);
    }
    return 0;
}

static int cmd_configure(void)
{
    /* Require passphrase to enter configuration */
    char pass[256];
    read_passphrase("Passphrase (required for configuration): ", pass, sizeof(pass));

    onvault_crypto_init();
    int auth_rc = onvault_auth_verify_passphrase(pass);
    onvault_memzero(pass, sizeof(pass));

    if (auth_rc != ONVAULT_OK) {
        fprintf(stderr, "Wrong passphrase.\n");
        return 1;
    }

    printf("\nonvault configuration\n");
    printf("====================\n");

    int running = 1;
    while (running) {
        printf("\n[1] Manage vaults (add/remove guard points)\n");
        printf("[2] Manage access rules (allow/deny processes)\n");
        printf("[3] View audit log\n");
        printf("[4] View denied access attempts\n");
        printf("[5] Start watch mode (learning)\n");
        printf("[6] Exit\n");

        int choice = read_choice("\nChoice: ", 6);
        switch (choice) {
        case 1:
            configure_manage_vaults();
            break;
        case 2:
            configure_manage_rules();
            break;
        case 3:
            cmd_log(0);
            break;
        case 4:
            cmd_log(1);
            break;
        case 5: {
            printf("Path to watch: ");
            fflush(stdout);
            char wpath[PATH_MAX];
            if (fgets(wpath, sizeof(wpath), stdin) == NULL)
                break;
            size_t wlen = strlen(wpath);
            if (wlen > 0 && wpath[wlen - 1] == '\n')
                wpath[wlen - 1] = '\0';
            cmd_vault_watch(wpath);
            break;
        }
        case 6:
            running = 0;
            break;
        default:
            printf("Invalid choice.\n");
            break;
        }
    }

    printf("Configuration saved.\n");
    return 0;
}

static int cmd_start(int no_gui)
{
    /* Find onvaultd in the same directory as this binary */
    char self_path[PATH_MAX];
    uint32_t self_len = sizeof(self_path);
    if (_NSGetExecutablePath(self_path, &self_len) != 0) {
        fprintf(stderr, "Cannot determine binary path.\n");
        return 1;
    }

    /* Resolve symlinks */
    char resolved[PATH_MAX];
    if (!realpath(self_path, resolved)) {
        fprintf(stderr, "Cannot resolve path.\n");
        return 1;
    }

    /* Replace "onvault" with "onvaultd" in the path */
    char *last_slash = strrchr(resolved, '/');
    if (!last_slash) {
        fprintf(stderr, "Invalid path.\n");
        return 1;
    }
    snprintf(last_slash + 1, (size_t)(resolved + PATH_MAX - last_slash - 1), "onvaultd");

    struct stat st;
    if (stat(resolved, &st) != 0) {
        fprintf(stderr, "Daemon binary not found: %s\n", resolved);
        return 1;
    }

    /* Check if already running */
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) == ONVAULT_OK) {
        char pid_path[PATH_MAX];
        snprintf(pid_path, PATH_MAX, "%s/onvaultd.pid", data_dir);
        FILE *pf = fopen(pid_path, "r");
        if (pf) {
            pid_t existing = 0;
            if (fscanf(pf, "%d", &existing) == 1 && existing > 0) {
                if (kill(existing, 0) == 0) {
                    printf("onvault daemon already running (pid %d)\n", existing);

                    /* Show web UI URL */
                    char port_path[PATH_MAX];
                    snprintf(port_path, PATH_MAX, "%s/http.port", data_dir);
                    FILE *portf = fopen(port_path, "r");
                    if (portf) {
                        int port = 0;
                        if (fscanf(portf, "%d", &port) == 1)
                            printf("Web UI: http://127.0.0.1:%d/menubar\n", port);
                        fclose(portf);
                    }
                    fclose(pf);
                    return 0;
                }
            }
            fclose(pf);
        }
    }

    /* Fork and exec onvaultd */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Failed to fork.\n");
        return 1;
    }

    if (pid == 0) {
        /* Child: exec onvaultd */
        if (no_gui)
            execl(resolved, "onvaultd", "--no-gui", (char *)NULL);
        else
            execl(resolved, "onvaultd", (char *)NULL);
        _exit(1); /* exec failed */
    }

    /* Parent: wait briefly and show status */
    sleep(2);

    char port_path[PATH_MAX];
    if (onvault_get_data_dir(data_dir) == ONVAULT_OK) {
        snprintf(port_path, PATH_MAX, "%s/http.port", data_dir);
        FILE *portf = fopen(port_path, "r");
        if (portf) {
            int port = 0;
            if (fscanf(portf, "%d", &port) == 1) {
                printf("onvault started (pid %d)\n", pid);
                printf("Web UI: http://127.0.0.1:%d/menubar\n", port);
                printf("\nRun 'onvault unlock' to authenticate.\n");
            }
            fclose(portf);
        } else {
            printf("onvault started (pid %d)\n", pid);
        }
    }

    return 0;
}

static int cmd_stop(void)
{
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK) {
        fprintf(stderr, "Not initialized.\n");
        return 1;
    }

    char pid_path[PATH_MAX];
    snprintf(pid_path, PATH_MAX, "%s/onvaultd.pid", data_dir);
    FILE *pf = fopen(pid_path, "r");
    if (!pf) {
        fprintf(stderr, "Daemon not running (no PID file).\n");
        return 1;
    }

    pid_t daemon_pid = 0;
    if (fscanf(pf, "%d", &daemon_pid) != 1 || daemon_pid <= 0) {
        fclose(pf);
        fprintf(stderr, "Invalid PID file.\n");
        return 1;
    }
    fclose(pf);

    if (kill(daemon_pid, 0) != 0) {
        fprintf(stderr, "Daemon not running (stale PID %d).\n", daemon_pid);
        unlink(pid_path);
        return 1;
    }

    /* Send SIGTERM for graceful shutdown */
    kill(daemon_pid, SIGTERM);
    printf("Stopping onvault (pid %d)...\n", daemon_pid);

    /* Wait up to 5 seconds for exit */
    for (int i = 0; i < 10; i++) {
        usleep(500000);
        if (kill(daemon_pid, 0) != 0) {
            printf("Stopped.\n");
            return 0;
        }
    }

    /* Force kill */
    kill(daemon_pid, SIGKILL);
    printf("Force stopped.\n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "init") == 0)
        return cmd_init();
    if (strcmp(cmd, "start") == 0) {
        int no_gui = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--no-gui") == 0)
                no_gui = 1;
        }
        return cmd_start(no_gui);
    }
    if (strcmp(cmd, "stop") == 0)
        return cmd_stop();
    if (strcmp(cmd, "unlock") == 0)
        return cmd_unlock();
    if (strcmp(cmd, "lock") == 0)
        return cmd_lock();
    if (strcmp(cmd, "status") == 0)
        return cmd_status();

    if (strcmp(cmd, "vault") == 0 && argc >= 3) {
        const char *sub = argv[2];
        if (strcmp(sub, "add") == 0) {
            const char *path = NULL;
            int smart = 0;
            for (int i = 3; i < argc; i++) {
                if (strcmp(argv[i], "--smart") == 0)
                    smart = 1;
                else if (!path)
                    path = argv[i];
            }
            return cmd_vault_add(path, smart);
        }
        if (strcmp(sub, "remove") == 0)
            return cmd_vault_remove(argc > 3 ? argv[3] : NULL);
        if (strcmp(sub, "list") == 0)
            return cmd_vault_list();
        if (strcmp(sub, "watch") == 0)
            return cmd_vault_watch(argc > 3 ? argv[3] : NULL);
        if (strcmp(sub, "suggest") == 0)
            return cmd_vault_suggest(argc > 3 ? argv[3] : NULL);
        fprintf(stderr, "Unknown vault command: %s\n", sub);
        return 1;
    }

    if (strcmp(cmd, "allow") == 0 && argc >= 4)
        return cmd_allow(argv[2], argv[3]);

    if (strcmp(cmd, "deny") == 0 && argc >= 4)
        return cmd_deny(argv[2], argv[3]);

    if (strcmp(cmd, "rules") == 0 && argc >= 3)
        return cmd_rules(argv[2]);

    if (strcmp(cmd, "policy") == 0 && argc >= 3) {
        if (strcmp(argv[2], "show") == 0)
            return cmd_policy_show();
        fprintf(stderr, "Unknown policy command: %s\n", argv[2]);
        return 1;
    }

    if (strcmp(cmd, "log") == 0) {
        int denied_only = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--denied") == 0)
                denied_only = 1;
        }
        return cmd_log(denied_only);
    }

    if (strcmp(cmd, "configure") == 0 || strcmp(cmd, "config") == 0)
        return cmd_configure();

    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0 || strcmp(cmd, "-v") == 0) {
        printf("onvault %s\n", ONVAULT_VERSION);
        return 0;
    }

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage();
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    usage();
    return 1;
}

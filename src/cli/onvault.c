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

static void usage(void)
{
    fprintf(stderr,
        "onvault — Seamless File Encryption & Access Control for macOS\n"
        "\n"
        "Usage: onvault <command> [args]\n"
        "\n"
        "Setup:\n"
        "  init                          First-time setup\n"
        "  unlock                        Authenticate and mount vaults\n"
        "  lock                          Unmount vaults, wipe keys\n"
        "\n"
        "Vault management:\n"
        "  vault add <path>              Encrypt and protect a directory\n"
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
    printf("Unlocked. Vaults are now accessible.\n");
    return 0;
}

static int cmd_lock(void)
{
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response);
    int rc = onvault_ipc_send(IPC_CMD_LOCK, NULL, 0, response, &resp_len);

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

static int cmd_vault_add(const char *path)
{
    if (!path) {
        fprintf(stderr, "Usage: onvault vault add <path>\n");
        return 1;
    }

    /* Resolve to absolute path before sending to daemon
     * (daemon may have a different CWD) */
    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) {
        fprintf(stderr, "Path not found: %s\n", path);
        return 1;
    }

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_VAULT_ADD,
                               resolved, (uint32_t)strlen(resolved) + 1,
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

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_VAULT_REMOVE,
                               vault_id, (uint32_t)strlen(vault_id) + 1,
                               response, &resp_len);

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

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "init") == 0)
        return cmd_init();
    if (strcmp(cmd, "unlock") == 0)
        return cmd_unlock();
    if (strcmp(cmd, "lock") == 0)
        return cmd_lock();
    if (strcmp(cmd, "status") == 0)
        return cmd_status();

    if (strcmp(cmd, "vault") == 0 && argc >= 3) {
        const char *sub = argv[2];
        if (strcmp(sub, "add") == 0)
            return cmd_vault_add(argc > 3 ? argv[3] : NULL);
        if (strcmp(sub, "remove") == 0)
            return cmd_vault_remove(argc > 3 ? argv[3] : NULL);
        if (strcmp(sub, "list") == 0)
            return cmd_vault_list();
        fprintf(stderr, "Unknown vault command: %s\n", sub);
        return 1;
    }

    if (strcmp(cmd, "allow") == 0 && argc >= 4)
        return cmd_allow(argv[2], argv[3]);

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

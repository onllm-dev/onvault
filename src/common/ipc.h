/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * ipc.h — Unix domain socket IPC (CLI ↔ daemon)
 */

#ifndef ONVAULT_IPC_H
#define ONVAULT_IPC_H

#include "types.h"

/* Socket in user's data dir (not /tmp) to avoid TOCTOU and permission issues */
#define ONVAULT_SOCKET_DIR_FMT "%s/.onvault"
#define ONVAULT_SOCKET_NAME "onvault.sock"
#define ONVAULT_IPC_MAX_MSG 4096

/* IPC command types */
typedef enum {
    IPC_CMD_STATUS = 1,
    IPC_CMD_UNLOCK,
    IPC_CMD_LOCK,
    IPC_CMD_VAULT_ADD,
    IPC_CMD_VAULT_REMOVE,
    IPC_CMD_VAULT_LIST,
    IPC_CMD_ALLOW,
    IPC_CMD_DENY,
    IPC_CMD_POLICY_SHOW,
    IPC_CMD_RULES,
    IPC_CMD_WATCH_START,
    IPC_CMD_WATCH_SUGGEST,
    IPC_CMD_ROTATE_KEYS,
    IPC_CMD_LOG,
} onvault_ipc_cmd_t;

/* IPC message header */
typedef struct {
    onvault_ipc_cmd_t cmd;
    uint32_t          payload_len;
} onvault_ipc_header_t;

/* IPC response status */
typedef enum {
    IPC_RESP_OK = 0,
    IPC_RESP_ERROR = 1,
    IPC_RESP_AUTH_REQUIRED = 2,
} onvault_ipc_resp_status_t;

typedef struct {
    onvault_ipc_resp_status_t status;
    uint32_t                  payload_len;
} onvault_ipc_resp_header_t;

/* Server (daemon) side */
int onvault_ipc_server_start(void);
void onvault_ipc_server_stop(void);

/* Get the server socket fd (for select/poll in daemon) */
int onvault_ipc_server_fd(void);

/* Client (CLI) side */
int onvault_ipc_send(onvault_ipc_cmd_t cmd,
                      const void *payload, uint32_t payload_len,
                      void *response, uint32_t *response_len);

#endif /* ONVAULT_IPC_H */

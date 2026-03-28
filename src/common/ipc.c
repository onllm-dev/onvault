/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * ipc.c — Unix domain socket IPC
 */

#include "ipc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>

/* Resolve socket path: ~/.onvault/onvault.sock */
static void get_socket_path(char *out, size_t len)
{
    const char *home = getenv("HOME");
    if (home)
        snprintf(out, len, "%s/.onvault/%s", home, ONVAULT_SOCKET_NAME);
    else
        snprintf(out, len, "/tmp/%s", ONVAULT_SOCKET_NAME);
}

/* --- Client side (CLI → daemon) --- */

int onvault_ipc_send(onvault_ipc_cmd_t cmd,
                      const void *payload, uint32_t payload_len,
                      void *response, uint32_t *response_len)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return ONVAULT_ERR_IO;

    char sock_path[PATH_MAX];
    get_socket_path(sock_path, sizeof(sock_path));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, sock_path, sizeof(addr.sun_path));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return ONVAULT_ERR_IO;
    }

    /* Send header + payload */
    onvault_ipc_header_t header = { .cmd = cmd, .payload_len = payload_len };
    if (write(sock, &header, sizeof(header)) != sizeof(header)) {
        close(sock);
        return ONVAULT_ERR_IO;
    }

    if (payload && payload_len > 0) {
        if (write(sock, payload, payload_len) != (ssize_t)payload_len) {
            close(sock);
            return ONVAULT_ERR_IO;
        }
    }

    /* Read response header */
    onvault_ipc_resp_header_t resp_header;
    ssize_t n = read(sock, &resp_header, sizeof(resp_header));
    if (n != sizeof(resp_header)) {
        close(sock);
        return ONVAULT_ERR_IO;
    }

    /* Read response payload */
    if (response && response_len && resp_header.payload_len > 0) {
        uint32_t to_read = resp_header.payload_len;
        if (to_read > *response_len)
            to_read = *response_len;

        n = read(sock, response, to_read);
        if (n < 0) {
            close(sock);
            return ONVAULT_ERR_IO;
        }
        *response_len = (uint32_t)n;
    } else if (response_len) {
        *response_len = 0;
    }

    close(sock);

    if (resp_header.status == IPC_RESP_ERROR)
        return ONVAULT_ERR_IO;
    if (resp_header.status == IPC_RESP_AUTH_REQUIRED)
        return ONVAULT_ERR_AUTH;

    return ONVAULT_OK;
}

/* --- Server side (daemon) --- */

static int g_server_sock = -1;

static char g_socket_path[PATH_MAX] = {0};

int onvault_ipc_server_start(void)
{
    get_socket_path(g_socket_path, sizeof(g_socket_path));
    unlink(g_socket_path);

    g_server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_server_sock < 0)
        return ONVAULT_ERR_IO;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, g_socket_path, sizeof(addr.sun_path));

    /* Set restrictive umask before bind to avoid TOCTOU window */
    mode_t old_mask = umask(0177);
    int bind_rc = bind(g_server_sock, (struct sockaddr *)&addr, sizeof(addr));
    umask(old_mask);

    if (bind_rc != 0) {
        close(g_server_sock);
        g_server_sock = -1;
        return ONVAULT_ERR_IO;
    }

    if (listen(g_server_sock, 5) != 0) {
        close(g_server_sock);
        g_server_sock = -1;
        return ONVAULT_ERR_IO;
    }

    return ONVAULT_OK;
}

int onvault_ipc_server_fd(void)
{
    return g_server_sock;
}

void onvault_ipc_server_stop(void)
{
    if (g_server_sock >= 0) {
        close(g_server_sock);
        g_server_sock = -1;
    }
    if (g_socket_path[0] != '\0')
        unlink(g_socket_path);
}

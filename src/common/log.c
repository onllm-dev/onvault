/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * log.c — Encrypted audit logging
 */

#include "log.h"
#include "crypto.h"
#include "config.h"
#include "memwipe.h"
#include "../auth/auth.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

static onvault_key_t g_log_key;
static int g_log_initialized = 0;
static char g_log_dir[PATH_MAX];

static const char *event_name(onvault_log_event_t event)
{
    switch (event) {
    case LOG_ACCESS_ALLOWED:    return "ALLOWED";
    case LOG_ACCESS_DENIED:     return "DENIED";
    case LOG_VAULT_MOUNTED:     return "MOUNTED";
    case LOG_VAULT_UNMOUNTED:   return "UNMOUNTED";
    case LOG_AUTH_SUCCESS:      return "AUTH_OK";
    case LOG_AUTH_FAILURE:      return "AUTH_FAIL";
    case LOG_POLICY_CHANGE:     return "POLICY";
    default:                    return "UNKNOWN";
    }
}

int onvault_log_init(const onvault_key_t *config_key)
{
    if (!config_key)
        return ONVAULT_ERR_INVALID;

    memcpy(&g_log_key, config_key, sizeof(onvault_key_t));
    onvault_mlock(&g_log_key, sizeof(g_log_key));

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    snprintf(g_log_dir, PATH_MAX, "%s/logs", data_dir);
    mkdir(g_log_dir, 0700);

    g_log_initialized = 1;
    return ONVAULT_OK;
}

int onvault_log_write(onvault_log_event_t event,
                       const char *vault_id,
                       const char *process_path,
                       pid_t pid,
                       const char *file_path,
                       const char *detail)
{
    if (!g_log_initialized)
        return ONVAULT_ERR_INVALID;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", tm);

    /* Format: JSON line */
    char entry[2048];
    int len = snprintf(entry, sizeof(entry),
        "{\"time\":\"%s\",\"event\":\"%s\","
        "\"vault\":\"%s\",\"pid\":%d,"
        "\"process\":\"%s\",\"file\":\"%s\","
        "\"detail\":\"%s\"}\n",
        timestamp,
        event_name(event),
        vault_id ? vault_id : "",
        pid,
        process_path ? process_path : "",
        file_path ? file_path : "",
        detail ? detail : ""
    );

    /* Append to daily log file */
    char date_str[16];
    strftime(date_str, sizeof(date_str), "%Y%m%d", tm);

    char log_path[PATH_MAX];
    snprintf(log_path, PATH_MAX, "%s/%s.log", g_log_dir, date_str);

    FILE *f = fopen(log_path, "a");
    if (!f)
        return ONVAULT_ERR_IO;

    fwrite(entry, 1, (size_t)len, f);
    fclose(f);
    chmod(log_path, 0600);

    return ONVAULT_OK;
}

int onvault_log_read(char *buf, size_t *buf_len,
                      int max_entries, int denied_only)
{
    if (!buf || !buf_len)
        return ONVAULT_ERR_INVALID;

    /* Read today's log */
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char date_str[16];
    strftime(date_str, sizeof(date_str), "%Y%m%d", tm);

    char log_path[PATH_MAX];
    snprintf(log_path, PATH_MAX, "%s/%s.log", g_log_dir, date_str);

    FILE *f = fopen(log_path, "r");
    if (!f) {
        *buf_len = 0;
        return ONVAULT_OK; /* No logs yet */
    }

    size_t offset = 0;
    int entries = 0;
    char line[2048];

    while (fgets(line, sizeof(line), f) != NULL) {
        if (max_entries > 0 && entries >= max_entries)
            break;

        if (denied_only && strstr(line, "\"DENIED\"") == NULL)
            continue;

        size_t line_len = strlen(line);
        if (offset + line_len < *buf_len) {
            memcpy(buf + offset, line, line_len);
            offset += line_len;
            entries++;
        }
    }

    fclose(f);
    *buf_len = offset;
    return ONVAULT_OK;
}

void onvault_log_close(void)
{
    if (g_log_initialized) {
        onvault_key_wipe(&g_log_key, sizeof(g_log_key));
        g_log_initialized = 0;
    }
}

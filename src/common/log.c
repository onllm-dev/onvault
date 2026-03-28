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
#include <stdlib.h>
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

    /* Encrypt and append to daily log file */
    char date_str[16];
    strftime(date_str, sizeof(date_str), "%Y%m%d", tm);

    char log_path[PATH_MAX];
    snprintf(log_path, PATH_MAX, "%s/%s.log.enc", g_log_dir, date_str);

    /* Encrypt the log entry with the log key (AES-256-GCM) */
    uint8_t *ciphertext = malloc((size_t)len);
    if (!ciphertext)
        return ONVAULT_ERR_MEMORY;

    uint8_t iv[ONVAULT_GCM_IV_SIZE];
    uint8_t tag[ONVAULT_GCM_TAG_SIZE];

    int enc_rc = onvault_aes_gcm_encrypt(&g_log_key, NULL, NULL, 0,
                                          (const uint8_t *)entry, (size_t)len,
                                          ciphertext, tag, iv);
    if (enc_rc != ONVAULT_OK) {
        free(ciphertext);
        return enc_rc;
    }

    /* Write encrypted entry: [entry_len(4)] [iv(12)] [tag(16)] [ciphertext(N)] */
    FILE *f = fopen(log_path, "ab");
    if (!f) {
        free(ciphertext);
        return ONVAULT_ERR_IO;
    }

    uint32_t entry_len = (uint32_t)len;
    fwrite(&entry_len, sizeof(entry_len), 1, f);
    fwrite(iv, 1, ONVAULT_GCM_IV_SIZE, f);
    fwrite(tag, 1, ONVAULT_GCM_TAG_SIZE, f);
    fwrite(ciphertext, 1, (size_t)len, f);
    fclose(f);
    chmod(log_path, 0600);

    onvault_memzero(ciphertext, (size_t)len);
    free(ciphertext);

    return ONVAULT_OK;
}

int onvault_log_read(char *buf, size_t *buf_len,
                      int max_entries, int denied_only)
{
    if (!buf || !buf_len)
        return ONVAULT_ERR_INVALID;

    /* Read today's encrypted log */
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char date_str[16];
    strftime(date_str, sizeof(date_str), "%Y%m%d", tm);

    char log_path[PATH_MAX];
    snprintf(log_path, PATH_MAX, "%s/%s.log.enc", g_log_dir, date_str);

    FILE *f = fopen(log_path, "rb");
    if (!f) {
        *buf_len = 0;
        return ONVAULT_OK; /* No logs yet */
    }

    size_t offset = 0;
    int entries = 0;

    while (!feof(f)) {
        if (max_entries > 0 && entries >= max_entries)
            break;

        /* Read entry header: [entry_len(4)] [iv(12)] [tag(16)] [ciphertext(N)] */
        uint32_t entry_len;
        if (fread(&entry_len, sizeof(entry_len), 1, f) != 1)
            break;

        if (entry_len > 4096) /* Sanity check */
            break;

        uint8_t iv[ONVAULT_GCM_IV_SIZE];
        uint8_t tag[ONVAULT_GCM_TAG_SIZE];

        if (fread(iv, 1, ONVAULT_GCM_IV_SIZE, f) != ONVAULT_GCM_IV_SIZE)
            break;
        if (fread(tag, 1, ONVAULT_GCM_TAG_SIZE, f) != ONVAULT_GCM_TAG_SIZE)
            break;

        uint8_t *ciphertext = malloc(entry_len);
        if (!ciphertext)
            break;

        if (fread(ciphertext, 1, entry_len, f) != entry_len) {
            free(ciphertext);
            break;
        }

        /* Decrypt */
        char *plaintext = malloc(entry_len + 1);
        if (!plaintext) {
            free(ciphertext);
            break;
        }

        int rc = onvault_aes_gcm_decrypt(&g_log_key, iv, NULL, 0,
                                           ciphertext, entry_len,
                                           (uint8_t *)plaintext, tag);
        free(ciphertext);

        if (rc != ONVAULT_OK) {
            free(plaintext);
            break;
        }

        plaintext[entry_len] = '\0';

        if (denied_only && strstr(plaintext, "\"DENIED\"") == NULL) {
            free(plaintext);
            continue;
        }

        if (offset + entry_len < *buf_len) {
            memcpy(buf + offset, plaintext, entry_len);
            offset += entry_len;
            entries++;
        }

        free(plaintext);
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

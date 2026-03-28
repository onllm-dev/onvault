/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * log.h — Encrypted audit logging
 */

#ifndef ONVAULT_LOG_H
#define ONVAULT_LOG_H

#include "types.h"

typedef enum {
    LOG_ACCESS_ALLOWED,
    LOG_ACCESS_DENIED,
    LOG_VAULT_MOUNTED,
    LOG_VAULT_UNMOUNTED,
    LOG_AUTH_SUCCESS,
    LOG_AUTH_FAILURE,
    LOG_POLICY_CHANGE,
} onvault_log_event_t;

/*
 * Initialize the audit log.
 * config_key: for encrypting log entries
 */
int onvault_log_init(const onvault_key_t *config_key);

/*
 * Write an audit log entry.
 */
int onvault_log_write(onvault_log_event_t event,
                       const char *vault_id,
                       const char *process_path,
                       pid_t pid,
                       const char *file_path,
                       const char *detail);

/*
 * Read and decrypt recent log entries.
 * buf: output buffer
 * buf_len: in/out buffer length
 * max_entries: max entries to return (0 = all)
 * denied_only: if 1, only return denied entries
 */
int onvault_log_read(char *buf, size_t *buf_len,
                      int max_entries, int denied_only);

/*
 * Close the audit log.
 */
void onvault_log_close(void);

#endif /* ONVAULT_LOG_H */

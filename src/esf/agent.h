/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * agent.h — Endpoint Security Framework client (Layer 2)
 *
 * Subscribes to comprehensive AUTH events to control which
 * processes can access vault mount points.
 */

#ifndef ONVAULT_ESF_AGENT_H
#define ONVAULT_ESF_AGENT_H

#include "../common/types.h"

/* Callback invoked when an access is denied */
typedef void (*onvault_deny_callback_fn)(const onvault_process_t *process,
                                          const char *file_path,
                                          const char *vault_id);

/*
 * Initialize the ESF client.
 * Subscribes to AUTH_OPEN, AUTH_RENAME, AUTH_LINK, AUTH_UNLINK,
 * AUTH_TRUNCATE, AUTH_EXEC, AUTH_CHOWN, AUTH_CHMOD.
 * Returns 0 on success.
 */
int onvault_esf_init(void);

/*
 * Start processing ESF events (blocks on the event loop).
 * Call from a dedicated thread.
 */
int onvault_esf_start(void);

/*
 * Stop ESF client and release resources.
 */
void onvault_esf_stop(void);

/*
 * Register a path prefix to monitor (vault mount point).
 * Only events within monitored paths are checked against policy.
 */
int onvault_esf_add_monitored_path(const char *path);

/*
 * Remove a monitored path.
 */
int onvault_esf_remove_monitored_path(const char *path);

/*
 * Set the callback for denied access notifications.
 */
void onvault_esf_set_deny_callback(onvault_deny_callback_fn fn);

/*
 * Extract process identity from ESF event.
 * Used internally but exposed for testing.
 */
int onvault_esf_extract_process(pid_t pid, onvault_process_t *proc);

#endif /* ONVAULT_ESF_AGENT_H */

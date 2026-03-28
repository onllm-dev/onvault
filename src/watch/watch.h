/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * watch.h — Learning/discovery mode using ESF NOTIFY events
 */

#ifndef ONVAULT_WATCH_H
#define ONVAULT_WATCH_H

#include "../common/types.h"

/* Discovered process entry */
typedef struct {
    char          path[PATH_MAX];
    char          signing_id[256];
    char          team_id[32];
    int           is_signed;
    int           access_count;
    onvault_hash_t binary_hash;
} onvault_watch_entry_t;

#define ONVAULT_MAX_WATCH_ENTRIES 256

/*
 * Start watching a path for process access.
 * Records which processes access files under the path.
 * duration_seconds: how long to watch (0 = until stop)
 */
int onvault_watch_start(const char *path, int duration_seconds);

/*
 * Stop watching.
 */
void onvault_watch_stop(void);

/*
 * Get discovered processes from the last watch session.
 * entries: output array
 * max_entries: array size
 * Returns number of entries found.
 */
int onvault_watch_get_results(onvault_watch_entry_t *entries, int max_entries);

/*
 * Save watch results to encrypted storage.
 */
int onvault_watch_save(const char *vault_id, const onvault_key_t *config_key);

/*
 * Load saved watch results.
 */
int onvault_watch_load(const char *vault_id, const onvault_key_t *config_key,
                        onvault_watch_entry_t *entries, int *count);

#endif /* ONVAULT_WATCH_H */

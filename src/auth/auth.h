/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * auth.h — Authentication: passphrase, sessions, recovery key
 */

#ifndef ONVAULT_AUTH_H
#define ONVAULT_AUTH_H

#include "../common/types.h"

/*
 * Initialize onvault for the first time.
 * Creates salt, derives master key from passphrase, stores in SE,
 * generates recovery key.
 * passphrase: user-chosen passphrase
 * recovery_key_out: buffer for 24-char recovery key (must be >= 25 bytes)
 * Returns 0 on success.
 */
int onvault_auth_init(const char *passphrase, char *recovery_key_out);

/*
 * Authenticate with passphrase.
 * Derives master key from passphrase + stored salt, unwraps from SE,
 * verifies match.
 * On success, stores session token in ~/.onvault/session.
 * master_key_out: output master key (caller must wipe after use)
 * Returns 0 on success.
 */
int onvault_auth_unlock(const char *passphrase, onvault_key_t *master_key_out);

/*
 * Check if a valid session exists (not expired).
 * If valid, loads the master key from SE.
 * master_key_out: output master key
 * Returns 0 if session is valid.
 */
int onvault_auth_check_session(onvault_key_t *master_key_out);

/*
 * Invalidate the current session.
 * Returns 0 on success.
 */
int onvault_auth_lock(void);

/*
 * Check if onvault has been initialized (salt + wrapped key exist).
 * Returns 1 if initialized, 0 if not.
 */
int onvault_auth_is_initialized(void);

/*
 * Get the onvault data directory path (~/.onvault/).
 * Creates it if it doesn't exist.
 * buf: output buffer (must be PATH_MAX)
 * Returns 0 on success.
 */
int onvault_get_data_dir(char *buf);

#endif /* ONVAULT_AUTH_H */

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
 * Verify a passphrase without performing a full unlock.
 * Used for auth-gating destructive operations (lock, vault remove).
 * Returns ONVAULT_OK if passphrase is correct.
 */
int onvault_auth_verify_passphrase(const char *passphrase);

/*
 * Compute a challenge-response proof for IPC auth.
 * proof = SHA-256(Argon2id(passphrase, salt) || nonce)
 * The nonce must be obtained from the daemon via IPC_CMD_AUTH_CHALLENGE.
 * proof_out: 32-byte output buffer
 */
int onvault_auth_compute_proof(const char *passphrase,
                                const uint8_t *nonce, size_t nonce_len,
                                uint8_t *proof_out);

/*
 * Verify a challenge-response proof against the stored master key.
 * proof = SHA-256(master_key || nonce)
 * Returns ONVAULT_OK if valid.
 */
int onvault_auth_verify_proof(const uint8_t *proof,
                               const uint8_t *nonce, size_t nonce_len);

/*
 * Verify a challenge-response proof against an already-loaded master key.
 * This avoids unnecessary keystore unwraps while the daemon is unlocked.
 * Returns ONVAULT_OK if valid.
 */
int onvault_auth_verify_proof_with_key(const uint8_t *proof,
                                        const uint8_t *nonce, size_t nonce_len,
                                        const onvault_key_t *master_key);

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

/*
 * Refresh an active session token.
 * Validates current session, generates new token, extends TTL.
 * Returns ONVAULT_OK on success, ONVAULT_ERR_AUTH if session expired/invalid.
 */
int onvault_auth_refresh_session(const onvault_key_t *master_key);

/*
 * Unlock using Touch ID biometrics.
 * Requires prior passphrase unlock to have stored key in Keychain.
 * Returns ONVAULT_OK + master key on success.
 */
int onvault_auth_unlock_touchid(onvault_key_t *master_key_out);

/*
 * Store a hash of the recovery key, encrypted with the config key.
 * Called during init to enable later recovery.
 */
int onvault_auth_store_recovery_hash(const char *recovery_key,
                                      const onvault_key_t *config_key);

/*
 * Unlock using recovery key and set a new passphrase.
 * Verifies recovery key hash, re-wraps master key with new passphrase.
 * Returns ONVAULT_OK + master key on success.
 */
int onvault_auth_unlock_recovery(const char *recovery_key,
                                  const char *new_passphrase,
                                  onvault_key_t *master_key_out);

#endif /* ONVAULT_AUTH_H */

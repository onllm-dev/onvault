/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * keystore.h — Secure Enclave + Keychain key management
 *
 * Strategy: The Secure Enclave can only do asymmetric ops (EC).
 * We generate an EC P-256 key pair in the SE, use ECDH with an
 * ephemeral key to derive a symmetric wrapping key, and wrap/unwrap
 * the AES-256 master key with it.
 */

#ifndef ONVAULT_KEYSTORE_H
#define ONVAULT_KEYSTORE_H

#include "../common/types.h"

/*
 * Initialize the keystore. Creates a Secure Enclave key pair
 * if one doesn't exist yet (first run).
 * Returns 0 on success.
 */
int onvault_keystore_init(void);

/*
 * Store (wrap) the master key using the Secure Enclave.
 * The master key is encrypted with an ECDH-derived wrapping key
 * and stored in the Keychain.
 * Returns 0 on success.
 */
int onvault_keystore_store_master_key(const onvault_key_t *master_key);

/*
 * Load (unwrap) the master key from the Keychain using the SE.
 * The Keychain item is decrypted via ECDH with the SE private key.
 * master_key: output — caller must wipe after use.
 * Returns 0 on success.
 */
int onvault_keystore_load_master_key(onvault_key_t *master_key);

/*
 * Delete all onvault keys from Keychain and Secure Enclave.
 * Used for complete reset / uninstall.
 * Returns 0 on success.
 */
int onvault_keystore_destroy(void);

/*
 * Check if a master key exists in the keystore.
 * Returns 1 if exists, 0 if not.
 */
int onvault_keystore_has_master_key(void);

#endif /* ONVAULT_KEYSTORE_H */

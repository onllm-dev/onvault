/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * touchid.h — Touch ID biometric authentication
 */

#ifndef ONVAULT_TOUCHID_H
#define ONVAULT_TOUCHID_H

/*
 * Check if Touch ID is available on this Mac.
 * Returns 1 if available, 0 if not.
 */
int onvault_touchid_available(void);

/*
 * Authenticate with Touch ID.
 * reason: displayed to the user (e.g., "unlock onvault")
 * Returns 0 on success.
 */
int onvault_touchid_authenticate(const char *reason);

#endif /* ONVAULT_TOUCHID_H */

/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * memwipe.h — Secure memory operations
 */

#ifndef ONVAULT_MEMWIPE_H
#define ONVAULT_MEMWIPE_H

#include <stddef.h>

/*
 * Securely zero memory. Guaranteed not to be optimized away.
 * Uses explicit_bzero on macOS (available since 10.13).
 */
void onvault_memzero(void *ptr, size_t len);

/*
 * Lock memory pages to prevent swapping to disk.
 * Returns 0 on success, -1 on failure.
 */
int onvault_mlock(void *ptr, size_t len);

/*
 * Unlock previously locked memory pages.
 * Returns 0 on success, -1 on failure.
 */
int onvault_munlock(void *ptr, size_t len);

/*
 * Wipe a key and unlock its memory.
 * Convenience wrapper: memzero + munlock.
 */
void onvault_key_wipe(void *key, size_t len);

#endif /* ONVAULT_MEMWIPE_H */

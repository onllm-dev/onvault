/*
 * onvault — Touch ID stub for tests (no biometric hardware access)
 */

#include "../src/auth/touchid.h"

int onvault_touchid_available(void)
{
    return 1; /* Always available in tests */
}

int onvault_touchid_authenticate(const char *reason)
{
    (void)reason;
    return 0; /* Always succeed in tests (0 = ONVAULT_OK) */
}

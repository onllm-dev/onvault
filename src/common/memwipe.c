/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * memwipe.c — Secure memory operations
 */

#define __STDC_WANT_LIB_EXT1__ 1

#include "memwipe.h"
#include <string.h>
#include <sys/mman.h>

/*
 * Use volatile function pointer trick to prevent compiler from
 * optimizing away the memset. This is the standard C approach
 * when memset_s / explicit_bzero aren't reliably available.
 */
static void * (* const volatile memset_func)(void *, int, size_t) = memset;

void onvault_memzero(void *ptr, size_t len)
{
    if (ptr && len > 0) {
        memset_func(ptr, 0, len);
    }
}

int onvault_mlock(void *ptr, size_t len)
{
    if (!ptr || len == 0)
        return -1;
    return mlock(ptr, len);
}

int onvault_munlock(void *ptr, size_t len)
{
    if (!ptr || len == 0)
        return -1;
    return munlock(ptr, len);
}

void onvault_key_wipe(void *key, size_t len)
{
    if (!key || len == 0)
        return;
    onvault_memzero(key, len);
    munlock(key, len);
}

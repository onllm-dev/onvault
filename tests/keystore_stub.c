/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * keystore_stub.c — In-memory keystore stub for tests (no Keychain access)
 *
 * Replaces keystore.o in test binaries to avoid Keychain/iCloud popups.
 * Stores the master key in memory only — no persistence, no Secure Enclave.
 */

#include "../src/keystore/keystore.h"
#include "../src/common/memwipe.h"
#include <string.h>

static uint8_t g_stored_key[ONVAULT_KEY_SIZE];
static int g_key_stored = 0;

int onvault_keystore_init(void)
{
    return ONVAULT_OK;
}

int onvault_keystore_store_master_key(const onvault_key_t *master_key)
{
    if (!master_key)
        return ONVAULT_ERR_INVALID;
    memcpy(g_stored_key, master_key->data, ONVAULT_KEY_SIZE);
    g_key_stored = 1;
    return ONVAULT_OK;
}

int onvault_keystore_load_master_key(onvault_key_t *master_key)
{
    if (!master_key || !g_key_stored)
        return ONVAULT_ERR_NOT_FOUND;
    memcpy(master_key->data, g_stored_key, ONVAULT_KEY_SIZE);
    return ONVAULT_OK;
}

int onvault_keystore_has_master_key(void)
{
    return g_key_stored;
}

int onvault_keystore_destroy(void)
{
    onvault_memzero(g_stored_key, sizeof(g_stored_key));
    g_key_stored = 0;
    return ONVAULT_OK;
}

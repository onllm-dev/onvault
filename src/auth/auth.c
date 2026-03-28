/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * auth.c — Authentication: passphrase, sessions, recovery key
 */

#include "auth.h"
#include "../common/crypto.h"
#include "../common/argon2_kdf.h"
#include "../common/memwipe.h"
#include "../common/hash.h"
#include "../keystore/keystore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

/* Recovery key alphabet: unambiguous characters */
static const char RECOVERY_ALPHABET[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

int onvault_get_data_dir(char *buf)
{
    const char *home = getenv("HOME");
    if (!home)
        return ONVAULT_ERR_IO;

    snprintf(buf, PATH_MAX, "%s/.onvault", home);

    struct stat st;
    if (stat(buf, &st) != 0) {
        if (mkdir(buf, 0700) != 0)
            return ONVAULT_ERR_IO;
    }

    return ONVAULT_OK;
}

static int read_file(const char *path, uint8_t *buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return ONVAULT_ERR_NOT_FOUND;

    size_t n = fread(buf, 1, *len, f);
    fclose(f);

    if (n == 0)
        return ONVAULT_ERR_IO;

    *len = n;
    return ONVAULT_OK;
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return ONVAULT_ERR_IO;

    size_t written = fwrite(data, 1, len, f);
    fclose(f);

    if (written != len)
        return ONVAULT_ERR_IO;

    chmod(path, 0600);
    return ONVAULT_OK;
}

static void generate_recovery_key(char *out)
{
    uint8_t random_bytes[ONVAULT_RECOVERY_LEN];
    onvault_random_bytes(random_bytes, ONVAULT_RECOVERY_LEN);

    for (int i = 0; i < ONVAULT_RECOVERY_LEN; i++) {
        out[i] = RECOVERY_ALPHABET[random_bytes[i] % (sizeof(RECOVERY_ALPHABET) - 1)];
    }
    out[ONVAULT_RECOVERY_LEN] = '\0';

    onvault_memzero(random_bytes, sizeof(random_bytes));
}

int onvault_auth_init(const char *passphrase, char *recovery_key_out)
{
    if (!passphrase || !recovery_key_out)
        return ONVAULT_ERR_INVALID;

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    /* Generate salt */
    uint8_t salt[ONVAULT_SALT_SIZE];
    if (onvault_random_bytes(salt, ONVAULT_SALT_SIZE) != ONVAULT_OK)
        return ONVAULT_ERR_CRYPTO;

    /* Write salt to disk */
    char salt_path[PATH_MAX];
    snprintf(salt_path, PATH_MAX, "%s/salt", data_dir);
    if (write_file(salt_path, salt, ONVAULT_SALT_SIZE) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    /* Derive master key from passphrase */
    onvault_key_t master_key;
    onvault_mlock(&master_key, sizeof(master_key));

    if (onvault_argon2_derive(passphrase, salt, &master_key) != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        return ONVAULT_ERR_CRYPTO;
    }

    /* Initialize Secure Enclave keystore */
    if (onvault_keystore_init() != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        return ONVAULT_ERR_KEYCHAIN;
    }

    /* Store wrapped master key in Keychain via SE */
    if (onvault_keystore_store_master_key(&master_key) != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        return ONVAULT_ERR_KEYCHAIN;
    }

    /* Store passphrase hash for verification (encrypted with config key) */
    onvault_key_t config_key;
    onvault_mlock(&config_key, sizeof(config_key));
    onvault_derive_config_key(&master_key, &config_key);

    uint8_t pass_hash[ONVAULT_KEY_SIZE];
    onvault_argon2_hash(passphrase, salt, pass_hash, ONVAULT_KEY_SIZE);

    /* Encrypt the passphrase hash with config key */
    uint8_t encrypted_hash[ONVAULT_KEY_SIZE];
    uint8_t tag[ONVAULT_GCM_TAG_SIZE];
    uint8_t iv[ONVAULT_GCM_IV_SIZE];

    onvault_aes_gcm_encrypt(&config_key, NULL, NULL, 0,
                            pass_hash, ONVAULT_KEY_SIZE,
                            encrypted_hash, tag, iv);

    /* Write auth blob: [iv(12)] [tag(16)] [encrypted_hash(32)] */
    char auth_path[PATH_MAX];
    snprintf(auth_path, PATH_MAX, "%s/auth.enc", data_dir);

    uint8_t auth_blob[ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE + ONVAULT_KEY_SIZE];
    memcpy(auth_blob, iv, ONVAULT_GCM_IV_SIZE);
    memcpy(auth_blob + ONVAULT_GCM_IV_SIZE, tag, ONVAULT_GCM_TAG_SIZE);
    memcpy(auth_blob + ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE,
           encrypted_hash, ONVAULT_KEY_SIZE);

    write_file(auth_path, auth_blob, sizeof(auth_blob));

    /* Create vault and mount directories */
    char vaults_dir[PATH_MAX], mnt_dir[PATH_MAX];
    snprintf(vaults_dir, PATH_MAX, "%s/vaults", data_dir);
    snprintf(mnt_dir, PATH_MAX, "%s/mnt", data_dir);
    mkdir(vaults_dir, 0700);
    mkdir(mnt_dir, 0700);

    /* Generate recovery key */
    generate_recovery_key(recovery_key_out);

    /* Clean up sensitive material */
    onvault_key_wipe(&master_key, sizeof(master_key));
    onvault_key_wipe(&config_key, sizeof(config_key));
    onvault_memzero(pass_hash, sizeof(pass_hash));

    return ONVAULT_OK;
}

int onvault_auth_unlock(const char *passphrase, onvault_key_t *master_key_out)
{
    if (!passphrase || !master_key_out)
        return ONVAULT_ERR_INVALID;

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    /* Read salt */
    char salt_path[PATH_MAX];
    snprintf(salt_path, PATH_MAX, "%s/salt", data_dir);

    uint8_t salt[ONVAULT_SALT_SIZE];
    size_t salt_len = ONVAULT_SALT_SIZE;
    if (read_file(salt_path, salt, &salt_len) != ONVAULT_OK)
        return ONVAULT_ERR_NOT_FOUND;

    /* Derive key from passphrase */
    onvault_key_t derived;
    onvault_mlock(&derived, sizeof(derived));

    if (onvault_argon2_derive(passphrase, salt, &derived) != ONVAULT_OK) {
        onvault_key_wipe(&derived, sizeof(derived));
        return ONVAULT_ERR_CRYPTO;
    }

    /* Load master key from SE/Keychain */
    onvault_key_t stored_key;
    onvault_mlock(&stored_key, sizeof(stored_key));

    if (onvault_keystore_load_master_key(&stored_key) != ONVAULT_OK) {
        onvault_key_wipe(&derived, sizeof(derived));
        onvault_key_wipe(&stored_key, sizeof(stored_key));
        return ONVAULT_ERR_KEYCHAIN;
    }

    /* Verify: derived key must match stored key */
    volatile uint8_t diff = 0;
    for (int i = 0; i < ONVAULT_KEY_SIZE; i++) {
        diff |= derived.data[i] ^ stored_key.data[i];
    }

    onvault_key_wipe(&derived, sizeof(derived));

    if (diff) {
        onvault_key_wipe(&stored_key, sizeof(stored_key));
        return ONVAULT_ERR_AUTH;
    }

    /* Success — copy key to output */
    onvault_mlock(master_key_out, sizeof(*master_key_out));
    memcpy(master_key_out->data, stored_key.data, ONVAULT_KEY_SIZE);
    onvault_key_wipe(&stored_key, sizeof(stored_key));

    /* Create session token */
    uint8_t token_data[ONVAULT_TOKEN_SIZE + sizeof(time_t)];
    onvault_random_bytes(token_data, ONVAULT_TOKEN_SIZE);
    time_t expiry = time(NULL) + ONVAULT_TOKEN_TTL;
    memcpy(token_data + ONVAULT_TOKEN_SIZE, &expiry, sizeof(time_t));

    char session_path[PATH_MAX];
    snprintf(session_path, PATH_MAX, "%s/session", data_dir);
    write_file(session_path, token_data, sizeof(token_data));

    onvault_memzero(token_data, sizeof(token_data));
    return ONVAULT_OK;
}

int onvault_auth_check_session(onvault_key_t *master_key_out)
{
    if (!master_key_out)
        return ONVAULT_ERR_INVALID;

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    char session_path[PATH_MAX];
    snprintf(session_path, PATH_MAX, "%s/session", data_dir);

    uint8_t token_data[ONVAULT_TOKEN_SIZE + sizeof(time_t)];
    size_t len = sizeof(token_data);
    if (read_file(session_path, token_data, &len) != ONVAULT_OK)
        return ONVAULT_ERR_AUTH;

    if (len != sizeof(token_data)) {
        onvault_memzero(token_data, sizeof(token_data));
        return ONVAULT_ERR_AUTH;
    }

    /* Check expiry */
    time_t expiry;
    memcpy(&expiry, token_data + ONVAULT_TOKEN_SIZE, sizeof(time_t));
    onvault_memzero(token_data, sizeof(token_data));

    if (time(NULL) > expiry)
        return ONVAULT_ERR_AUTH; /* Session expired */

    /* Session valid — load master key from SE */
    return onvault_keystore_load_master_key(master_key_out);
}

int onvault_auth_lock(void)
{
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    char session_path[PATH_MAX];
    snprintf(session_path, PATH_MAX, "%s/session", data_dir);
    unlink(session_path);

    return ONVAULT_OK;
}

int onvault_auth_is_initialized(void)
{
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return 0;

    char salt_path[PATH_MAX];
    snprintf(salt_path, PATH_MAX, "%s/salt", data_dir);

    struct stat st;
    if (stat(salt_path, &st) != 0)
        return 0;

    return onvault_keystore_has_master_key();
}

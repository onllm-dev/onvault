/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * auth.c — Authentication: passphrase, sessions, recovery key
 */

#include "auth.h"
#include "touchid.h"
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
#define RECOVERY_ALPHABET_LEN ((int)(sizeof(RECOVERY_ALPHABET) - 1))
#define RECOVERY_REJECTION_LIMIT 224

#define ONVAULT_AUTH_BLOB_SIZE \
    (ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE + ONVAULT_KEY_SIZE)
#define ONVAULT_SESSION_EXPIRY_SIZE 8
#define ONVAULT_SESSION_DATA_SIZE \
    (ONVAULT_TOKEN_SIZE + ONVAULT_SESSION_EXPIRY_SIZE)
#define ONVAULT_SESSION_FILE_SIZE \
    (ONVAULT_SESSION_DATA_SIZE + ONVAULT_HASH_SIZE)

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

static int read_salt(const char *data_dir, uint8_t salt[ONVAULT_SALT_SIZE])
{
    char salt_path[PATH_MAX];
    size_t salt_len = ONVAULT_SALT_SIZE;

    snprintf(salt_path, PATH_MAX, "%s/salt", data_dir);
    if (read_file(salt_path, salt, &salt_len) != ONVAULT_OK)
        return ONVAULT_ERR_NOT_FOUND;
    if (salt_len != ONVAULT_SALT_SIZE)
        return ONVAULT_ERR_INVALID;

    return ONVAULT_OK;
}

static int read_auth_blob(const char *data_dir, uint8_t auth_blob[ONVAULT_AUTH_BLOB_SIZE])
{
    char auth_path[PATH_MAX];
    size_t auth_len = ONVAULT_AUTH_BLOB_SIZE;

    snprintf(auth_path, PATH_MAX, "%s/auth.enc", data_dir);
    if (read_file(auth_path, auth_blob, &auth_len) != ONVAULT_OK)
        return ONVAULT_ERR_NOT_FOUND;
    if (auth_len != ONVAULT_AUTH_BLOB_SIZE)
        return ONVAULT_ERR_INVALID;

    return ONVAULT_OK;
}

static int verify_master_key_candidate(const char *data_dir,
                                       const uint8_t salt[ONVAULT_SALT_SIZE],
                                       const char *passphrase,
                                       const onvault_key_t *candidate_key)
{
    uint8_t auth_blob[ONVAULT_AUTH_BLOB_SIZE];
    uint8_t expected_hash[ONVAULT_KEY_SIZE];
    uint8_t decrypted_hash[ONVAULT_KEY_SIZE];
    onvault_key_t config_key;
    int rc;

    if (!data_dir || !salt || !passphrase || !candidate_key)
        return ONVAULT_ERR_INVALID;

    rc = read_auth_blob(data_dir, auth_blob);
    if (rc != ONVAULT_OK)
        return rc;

    onvault_mlock(&config_key, sizeof(config_key));
    rc = onvault_derive_config_key(candidate_key, &config_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&config_key, sizeof(config_key));
        onvault_memzero(auth_blob, sizeof(auth_blob));
        return rc;
    }

    rc = onvault_aes_gcm_decrypt(&config_key, auth_blob, NULL, 0,
                                 auth_blob + ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE,
                                 ONVAULT_KEY_SIZE,
                                 decrypted_hash,
                                 auth_blob + ONVAULT_GCM_IV_SIZE);
    onvault_key_wipe(&config_key, sizeof(config_key));
    onvault_memzero(auth_blob, sizeof(auth_blob));
    if (rc != ONVAULT_OK) {
        onvault_memzero(decrypted_hash, sizeof(decrypted_hash));
        return ONVAULT_ERR_AUTH;
    }

    onvault_argon2_hash(passphrase, salt, expected_hash, ONVAULT_KEY_SIZE);
    rc = onvault_constant_time_eq(expected_hash, decrypted_hash, ONVAULT_KEY_SIZE)
        ? ONVAULT_OK : ONVAULT_ERR_AUTH;

    onvault_memzero(expected_hash, sizeof(expected_hash));
    onvault_memzero(decrypted_hash, sizeof(decrypted_hash));
    return rc;
}

static void generate_recovery_key(char *out)
{
    uint8_t random_bytes[ONVAULT_RECOVERY_LEN];
    onvault_random_bytes(random_bytes, ONVAULT_RECOVERY_LEN);

    for (int i = 0; i < ONVAULT_RECOVERY_LEN; i++) {
        uint8_t r = random_bytes[i];
        while (r >= RECOVERY_REJECTION_LIMIT) {
            if (onvault_random_bytes(&r, 1) != ONVAULT_OK)
                r = 0;
        }
        out[i] = RECOVERY_ALPHABET[r % RECOVERY_ALPHABET_LEN];
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

    if (onvault_aes_gcm_encrypt(&config_key, NULL, NULL, 0,
                                pass_hash, ONVAULT_KEY_SIZE,
                                encrypted_hash, tag, iv) != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&config_key, sizeof(config_key));
        onvault_memzero(pass_hash, sizeof(pass_hash));
        return ONVAULT_ERR_CRYPTO;
    }

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

    /* Store recovery key hash so we can verify it during recovery unlock */
    onvault_auth_store_recovery_hash(recovery_key_out, &config_key);

    /* Clean up sensitive material */
    onvault_key_wipe(&master_key, sizeof(master_key));
    onvault_key_wipe(&config_key, sizeof(config_key));
    onvault_memzero(pass_hash, sizeof(pass_hash));
    onvault_memzero(encrypted_hash, sizeof(encrypted_hash));
    onvault_memzero(auth_blob, sizeof(auth_blob));
    onvault_memzero(tag, sizeof(tag));
    onvault_memzero(iv, sizeof(iv));

    return ONVAULT_OK;
}

int onvault_auth_unlock(const char *passphrase, onvault_key_t *master_key_out)
{
    if (!passphrase || !master_key_out)
        return ONVAULT_ERR_INVALID;

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    uint8_t salt[ONVAULT_SALT_SIZE];
    int rc = read_salt(data_dir, salt);
    if (rc != ONVAULT_OK)
        return rc;

    /* Derive the candidate master key from the passphrase. */
    onvault_key_t derived;
    onvault_mlock(&derived, sizeof(derived));
    if (onvault_argon2_derive(passphrase, salt, &derived) != ONVAULT_OK) {
        onvault_key_wipe(&derived, sizeof(derived));
        return ONVAULT_ERR_CRYPTO;
    }

    rc = verify_master_key_candidate(data_dir, salt, passphrase, &derived);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&derived, sizeof(derived));
        return rc;
    }

    /* Success — return the verified master key to the caller. */
    onvault_mlock(master_key_out, sizeof(*master_key_out));
    memcpy(master_key_out->data, derived.data, ONVAULT_KEY_SIZE);
    onvault_key_wipe(&derived, sizeof(derived));

    /* Create a session token protected by a master-key MAC. */
    uint8_t token_data[ONVAULT_SESSION_DATA_SIZE];
    uint8_t session_blob[ONVAULT_SESSION_FILE_SIZE];
    uint64_t expiry = (uint64_t)time(NULL) + (uint64_t)ONVAULT_TOKEN_TTL;

    rc = onvault_random_bytes(token_data, ONVAULT_TOKEN_SIZE);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return rc;
    }
    memcpy(token_data + ONVAULT_TOKEN_SIZE, &expiry, sizeof(expiry));
    memcpy(session_blob, token_data, sizeof(token_data));

    rc = onvault_hmac_sha256(master_key_out->data, ONVAULT_KEY_SIZE,
                             token_data, sizeof(token_data),
                             session_blob + sizeof(token_data));
    onvault_memzero(token_data, sizeof(token_data));
    if (rc != ONVAULT_OK) {
        onvault_memzero(session_blob, sizeof(session_blob));
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return rc;
    }

    char session_path[PATH_MAX];
    snprintf(session_path, PATH_MAX, "%s/session", data_dir);
    rc = write_file(session_path, session_blob, sizeof(session_blob));
    onvault_memzero(session_blob, sizeof(session_blob));
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return rc;
    }

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
    uint8_t session_blob[ONVAULT_SESSION_FILE_SIZE];
    uint8_t expected_mac[ONVAULT_HASH_SIZE];
    size_t len = sizeof(session_blob);
    uint64_t expiry = 0;
    int rc;

    snprintf(session_path, PATH_MAX, "%s/session", data_dir);

    if (read_file(session_path, session_blob, &len) != ONVAULT_OK)
        return ONVAULT_ERR_AUTH;

    if (len != sizeof(session_blob)) {
        onvault_memzero(session_blob, sizeof(session_blob));
        return ONVAULT_ERR_AUTH;
    }

    rc = onvault_keystore_load_master_key(master_key_out);
    if (rc != ONVAULT_OK) {
        onvault_memzero(session_blob, sizeof(session_blob));
        return rc;
    }

    rc = onvault_hmac_sha256(master_key_out->data, ONVAULT_KEY_SIZE,
                             session_blob, ONVAULT_SESSION_DATA_SIZE,
                             expected_mac);
    if (rc != ONVAULT_OK) {
        onvault_memzero(expected_mac, sizeof(expected_mac));
        onvault_memzero(session_blob, sizeof(session_blob));
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return rc;
    }

    if (!onvault_constant_time_eq(expected_mac,
                                  session_blob + ONVAULT_SESSION_DATA_SIZE,
                                  ONVAULT_HASH_SIZE)) {
        onvault_memzero(expected_mac, sizeof(expected_mac));
        onvault_memzero(session_blob, sizeof(session_blob));
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return ONVAULT_ERR_AUTH;
    }

    memcpy(&expiry, session_blob + ONVAULT_TOKEN_SIZE, sizeof(expiry));
    onvault_memzero(expected_mac, sizeof(expected_mac));
    onvault_memzero(session_blob, sizeof(session_blob));

    if ((uint64_t)time(NULL) > expiry) {
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return ONVAULT_ERR_AUTH;
    }

    return ONVAULT_OK;
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

int onvault_auth_verify_passphrase(const char *passphrase)
{
    if (!passphrase)
        return ONVAULT_ERR_INVALID;

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    uint8_t salt[ONVAULT_SALT_SIZE];
    int rc = read_salt(data_dir, salt);
    if (rc != ONVAULT_OK)
        return rc;

    /* Derive and verify the candidate master key without touching the keystore. */
    onvault_key_t derived;
    onvault_mlock(&derived, sizeof(derived));
    if (onvault_argon2_derive(passphrase, salt, &derived) != ONVAULT_OK) {
        onvault_key_wipe(&derived, sizeof(derived));
        return ONVAULT_ERR_CRYPTO;
    }

    rc = verify_master_key_candidate(data_dir, salt, passphrase, &derived);
    onvault_key_wipe(&derived, sizeof(derived));
    return rc;
}

int onvault_auth_compute_proof(const char *passphrase,
                                const uint8_t *nonce, size_t nonce_len,
                                uint8_t *proof_out)
{
    if (!passphrase || !nonce || !nonce_len || !proof_out)
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

    /* Proof = SHA-256(derived_key || nonce) — nonce prevents replay */
    uint8_t preimage[ONVAULT_KEY_SIZE + ONVAULT_HASH_SIZE];
    memcpy(preimage, derived.data, ONVAULT_KEY_SIZE);
    memcpy(preimage + ONVAULT_KEY_SIZE, nonce,
           nonce_len > ONVAULT_HASH_SIZE ? ONVAULT_HASH_SIZE : nonce_len);
    size_t preimage_len = ONVAULT_KEY_SIZE +
        (nonce_len > ONVAULT_HASH_SIZE ? ONVAULT_HASH_SIZE : nonce_len);

    onvault_hash_t hash;
    onvault_sha256(preimage, preimage_len, &hash);
    memcpy(proof_out, hash.data, ONVAULT_HASH_SIZE);

    onvault_key_wipe(&derived, sizeof(derived));
    onvault_memzero(preimage, sizeof(preimage));
    onvault_memzero(&hash, sizeof(hash));
    return ONVAULT_OK;
}

int onvault_auth_verify_proof_with_key(const uint8_t *proof,
                                       const uint8_t *nonce, size_t nonce_len,
                                       const onvault_key_t *master_key)
{
    if (!proof || !nonce || !nonce_len || !master_key)
        return ONVAULT_ERR_INVALID;

    /* Compute expected = SHA-256(master_key || nonce) */
    uint8_t preimage[ONVAULT_KEY_SIZE + ONVAULT_HASH_SIZE];
    memcpy(preimage, master_key->data, ONVAULT_KEY_SIZE);
    memcpy(preimage + ONVAULT_KEY_SIZE, nonce,
           nonce_len > ONVAULT_HASH_SIZE ? ONVAULT_HASH_SIZE : nonce_len);
    size_t preimage_len = ONVAULT_KEY_SIZE +
        (nonce_len > ONVAULT_HASH_SIZE ? ONVAULT_HASH_SIZE : nonce_len);

    onvault_hash_t expected;
    onvault_sha256(preimage, preimage_len, &expected);
    onvault_memzero(preimage, sizeof(preimage));

    int ok = onvault_constant_time_eq(proof, expected.data, ONVAULT_HASH_SIZE);
    onvault_memzero(&expected, sizeof(expected));
    return ok ? ONVAULT_OK : ONVAULT_ERR_AUTH;
}

int onvault_auth_verify_proof(const uint8_t *proof,
                               const uint8_t *nonce, size_t nonce_len)
{
    onvault_key_t stored_key;
    int rc;

    if (!proof || !nonce || !nonce_len)
        return ONVAULT_ERR_INVALID;

    onvault_mlock(&stored_key, sizeof(stored_key));
    rc = onvault_keystore_load_master_key(&stored_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&stored_key, sizeof(stored_key));
        return rc;
    }

    rc = onvault_auth_verify_proof_with_key(proof, nonce, nonce_len, &stored_key);
    onvault_key_wipe(&stored_key, sizeof(stored_key));
    return rc;
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

int onvault_auth_refresh_session(const onvault_key_t *master_key)
{
    if (!master_key)
        return ONVAULT_ERR_INVALID;

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    /* Verify current session is still valid */
    char session_path[PATH_MAX];
    snprintf(session_path, PATH_MAX, "%s/session", data_dir);

    uint8_t old_blob[ONVAULT_SESSION_FILE_SIZE];
    size_t len = sizeof(old_blob);
    if (read_file(session_path, old_blob, &len) != ONVAULT_OK || len != sizeof(old_blob))
        return ONVAULT_ERR_AUTH;

    /* Verify HMAC of old session */
    uint8_t expected_mac[ONVAULT_HASH_SIZE];
    int rc = onvault_hmac_sha256(master_key->data, ONVAULT_KEY_SIZE,
                                  old_blob, ONVAULT_SESSION_DATA_SIZE,
                                  expected_mac);
    if (rc != ONVAULT_OK) {
        onvault_memzero(old_blob, sizeof(old_blob));
        onvault_memzero(expected_mac, sizeof(expected_mac));
        return rc;
    }
    if (!onvault_constant_time_eq(expected_mac, old_blob + ONVAULT_SESSION_DATA_SIZE,
                                   ONVAULT_HASH_SIZE)) {
        onvault_memzero(old_blob, sizeof(old_blob));
        onvault_memzero(expected_mac, sizeof(expected_mac));
        return ONVAULT_ERR_AUTH;
    }
    onvault_memzero(expected_mac, sizeof(expected_mac));

    /* Check not expired */
    uint64_t old_expiry;
    memcpy(&old_expiry, old_blob + ONVAULT_TOKEN_SIZE, sizeof(old_expiry));
    onvault_memzero(old_blob, sizeof(old_blob));
    if ((uint64_t)time(NULL) > old_expiry)
        return ONVAULT_ERR_AUTH;

    /* Generate fresh session token */
    uint8_t token_data[ONVAULT_SESSION_DATA_SIZE];
    uint8_t session_blob[ONVAULT_SESSION_FILE_SIZE];
    uint64_t new_expiry = (uint64_t)time(NULL) + (uint64_t)ONVAULT_TOKEN_TTL;

    rc = onvault_random_bytes(token_data, ONVAULT_TOKEN_SIZE);
    if (rc != ONVAULT_OK)
        return rc;
    memcpy(token_data + ONVAULT_TOKEN_SIZE, &new_expiry, sizeof(new_expiry));
    memcpy(session_blob, token_data, sizeof(token_data));

    rc = onvault_hmac_sha256(master_key->data, ONVAULT_KEY_SIZE,
                              token_data, sizeof(token_data),
                              session_blob + sizeof(token_data));
    onvault_memzero(token_data, sizeof(token_data));
    if (rc != ONVAULT_OK) {
        onvault_memzero(session_blob, sizeof(session_blob));
        return rc;
    }

    rc = write_file(session_path, session_blob, sizeof(session_blob));
    onvault_memzero(session_blob, sizeof(session_blob));
    return rc;
}

int onvault_auth_unlock_touchid(onvault_key_t *master_key_out)
{
    if (!master_key_out)
        return ONVAULT_ERR_INVALID;

    if (!onvault_touchid_available())
        return ONVAULT_ERR_NOT_FOUND;

    if (onvault_touchid_authenticate("Unlock onvault") != 0)
        return ONVAULT_ERR_AUTH;

    /* Touch ID success grants Keychain access — load master key */
    onvault_mlock(master_key_out, sizeof(*master_key_out));
    int rc = onvault_keystore_load_master_key(master_key_out);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return rc;
    }

    /* Create session token */
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK) {
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return ONVAULT_ERR_IO;
    }

    uint8_t token_data[ONVAULT_SESSION_DATA_SIZE];
    uint8_t session_blob[ONVAULT_SESSION_FILE_SIZE];
    uint64_t expiry = (uint64_t)time(NULL) + (uint64_t)ONVAULT_TOKEN_TTL;

    rc = onvault_random_bytes(token_data, ONVAULT_TOKEN_SIZE);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return rc;
    }
    memcpy(token_data + ONVAULT_TOKEN_SIZE, &expiry, sizeof(expiry));
    memcpy(session_blob, token_data, sizeof(token_data));

    rc = onvault_hmac_sha256(master_key_out->data, ONVAULT_KEY_SIZE,
                              token_data, sizeof(token_data),
                              session_blob + sizeof(token_data));
    onvault_memzero(token_data, sizeof(token_data));
    if (rc != ONVAULT_OK) {
        onvault_memzero(session_blob, sizeof(session_blob));
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return rc;
    }

    char session_path[PATH_MAX];
    snprintf(session_path, PATH_MAX, "%s/session", data_dir);
    rc = write_file(session_path, session_blob, sizeof(session_blob));
    onvault_memzero(session_blob, sizeof(session_blob));
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(master_key_out, sizeof(*master_key_out));
        return rc;
    }

    return ONVAULT_OK;
}

int onvault_auth_store_recovery_hash(const char *recovery_key,
                                      const onvault_key_t *config_key)
{
    if (!recovery_key || !config_key)
        return ONVAULT_ERR_INVALID;

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    /* Compute SHA-256 of the recovery key string */
    onvault_hash_t rec_hash;
    onvault_sha256((const uint8_t *)recovery_key, strlen(recovery_key), &rec_hash);

    /* Encrypt hash with config key: [iv(12)][tag(16)][ciphertext(32)] */
    uint8_t encrypted[ONVAULT_KEY_SIZE];
    uint8_t tag[ONVAULT_GCM_TAG_SIZE];
    uint8_t iv[ONVAULT_GCM_IV_SIZE];

    int rc = onvault_aes_gcm_encrypt(config_key, NULL, NULL, 0,
                                      rec_hash.data, ONVAULT_HASH_SIZE,
                                      encrypted, tag, iv);
    onvault_memzero(&rec_hash, sizeof(rec_hash));
    if (rc != ONVAULT_OK) {
        onvault_memzero(encrypted, sizeof(encrypted));
        onvault_memzero(tag, sizeof(tag));
        onvault_memzero(iv, sizeof(iv));
        return rc;
    }

    uint8_t blob[ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE + ONVAULT_HASH_SIZE];
    memcpy(blob, iv, ONVAULT_GCM_IV_SIZE);
    memcpy(blob + ONVAULT_GCM_IV_SIZE, tag, ONVAULT_GCM_TAG_SIZE);
    memcpy(blob + ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE, encrypted, ONVAULT_KEY_SIZE);

    onvault_memzero(encrypted, sizeof(encrypted));
    onvault_memzero(tag, sizeof(tag));
    onvault_memzero(iv, sizeof(iv));

    char recovery_path[PATH_MAX];
    snprintf(recovery_path, PATH_MAX, "%s/recovery.enc", data_dir);
    rc = write_file(recovery_path, blob, sizeof(blob));
    onvault_memzero(blob, sizeof(blob));
    return rc;
}

int onvault_auth_unlock_recovery(const char *recovery_key,
                                  const char *new_passphrase,
                                  onvault_key_t *master_key_out)
{
    if (!recovery_key || !new_passphrase || !master_key_out)
        return ONVAULT_ERR_INVALID;

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    /* Load master key from keystore (requires Keychain to be accessible) */
    onvault_key_t master_key;
    onvault_mlock(&master_key, sizeof(master_key));
    int rc = onvault_keystore_load_master_key(&master_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        return rc;
    }

    /* Derive config key from master key to decrypt recovery.enc */
    onvault_key_t config_key;
    onvault_mlock(&config_key, sizeof(config_key));
    rc = onvault_derive_config_key(&master_key, &config_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&config_key, sizeof(config_key));
        return rc;
    }

    /* Read recovery.enc */
    char recovery_path[PATH_MAX];
    snprintf(recovery_path, PATH_MAX, "%s/recovery.enc", data_dir);

    uint8_t blob[ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE + ONVAULT_HASH_SIZE];
    size_t blob_len = sizeof(blob);
    rc = read_file(recovery_path, blob, &blob_len);
    if (rc != ONVAULT_OK || blob_len != sizeof(blob)) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&config_key, sizeof(config_key));
        onvault_memzero(blob, sizeof(blob));
        return ONVAULT_ERR_NOT_FOUND;
    }

    /* Decrypt stored recovery hash */
    uint8_t stored_hash[ONVAULT_HASH_SIZE];
    rc = onvault_aes_gcm_decrypt(&config_key, blob,
                                  NULL, 0,
                                  blob + ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE,
                                  ONVAULT_HASH_SIZE,
                                  stored_hash,
                                  blob + ONVAULT_GCM_IV_SIZE);
    onvault_key_wipe(&config_key, sizeof(config_key));
    onvault_memzero(blob, sizeof(blob));
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_memzero(stored_hash, sizeof(stored_hash));
        return ONVAULT_ERR_AUTH;
    }

    /* Compute SHA-256 of supplied recovery key and compare */
    onvault_hash_t input_hash;
    onvault_sha256((const uint8_t *)recovery_key, strlen(recovery_key), &input_hash);

    int match = onvault_constant_time_eq(stored_hash, input_hash.data, ONVAULT_HASH_SIZE);
    onvault_memzero(stored_hash, sizeof(stored_hash));
    onvault_memzero(&input_hash, sizeof(input_hash));

    if (!match) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        return ONVAULT_ERR_AUTH;
    }

    /* Recovery key verified — re-initialize auth with new passphrase */

    /* Generate new salt */
    uint8_t new_salt[ONVAULT_SALT_SIZE];
    rc = onvault_random_bytes(new_salt, ONVAULT_SALT_SIZE);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        return rc;
    }

    char salt_path[PATH_MAX];
    snprintf(salt_path, PATH_MAX, "%s/salt", data_dir);
    rc = write_file(salt_path, new_salt, ONVAULT_SALT_SIZE);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_memzero(new_salt, sizeof(new_salt));
        return rc;
    }

    /* Derive new master key from new passphrase (master_key identity stays,
     * but we re-wrap under the new passphrase-derived key and update auth.enc) */
    onvault_key_t new_master_key;
    onvault_mlock(&new_master_key, sizeof(new_master_key));
    rc = onvault_argon2_derive(new_passphrase, new_salt, &new_master_key);
    onvault_memzero(new_salt, sizeof(new_salt));
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&new_master_key, sizeof(new_master_key));
        return ONVAULT_ERR_CRYPTO;
    }

    /* Store new master key in keystore */
    rc = onvault_keystore_store_master_key(&new_master_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&new_master_key, sizeof(new_master_key));
        return rc;
    }

    /* Derive new config key and write new auth.enc */
    onvault_key_t new_config_key;
    onvault_mlock(&new_config_key, sizeof(new_config_key));
    rc = onvault_derive_config_key(&new_master_key, &new_config_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&new_master_key, sizeof(new_master_key));
        onvault_key_wipe(&new_config_key, sizeof(new_config_key));
        return rc;
    }

    /* Read the new salt back for hash computation */
    uint8_t salt_verify[ONVAULT_SALT_SIZE];
    size_t salt_verify_len = ONVAULT_SALT_SIZE;
    rc = read_file(salt_path, salt_verify, &salt_verify_len);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&new_master_key, sizeof(new_master_key));
        onvault_key_wipe(&new_config_key, sizeof(new_config_key));
        return rc;
    }

    uint8_t pass_hash[ONVAULT_KEY_SIZE];
    onvault_argon2_hash(new_passphrase, salt_verify, pass_hash, ONVAULT_KEY_SIZE);
    onvault_memzero(salt_verify, sizeof(salt_verify));

    uint8_t enc_hash[ONVAULT_KEY_SIZE];
    uint8_t auth_tag[ONVAULT_GCM_TAG_SIZE];
    uint8_t auth_iv[ONVAULT_GCM_IV_SIZE];

    rc = onvault_aes_gcm_encrypt(&new_config_key, NULL, NULL, 0,
                                  pass_hash, ONVAULT_KEY_SIZE,
                                  enc_hash, auth_tag, auth_iv);
    onvault_memzero(pass_hash, sizeof(pass_hash));
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&new_master_key, sizeof(new_master_key));
        onvault_key_wipe(&new_config_key, sizeof(new_config_key));
        onvault_memzero(enc_hash, sizeof(enc_hash));
        return rc;
    }

    uint8_t auth_blob[ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE + ONVAULT_KEY_SIZE];
    memcpy(auth_blob, auth_iv, ONVAULT_GCM_IV_SIZE);
    memcpy(auth_blob + ONVAULT_GCM_IV_SIZE, auth_tag, ONVAULT_GCM_TAG_SIZE);
    memcpy(auth_blob + ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE, enc_hash, ONVAULT_KEY_SIZE);
    onvault_memzero(enc_hash, sizeof(enc_hash));
    onvault_memzero(auth_tag, sizeof(auth_tag));
    onvault_memzero(auth_iv, sizeof(auth_iv));

    char auth_path[PATH_MAX];
    snprintf(auth_path, PATH_MAX, "%s/auth.enc", data_dir);
    rc = write_file(auth_path, auth_blob, sizeof(auth_blob));
    onvault_memzero(auth_blob, sizeof(auth_blob));
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&new_master_key, sizeof(new_master_key));
        onvault_key_wipe(&new_config_key, sizeof(new_config_key));
        return rc;
    }

    /* Update recovery.enc with the same recovery key under the new config key */
    onvault_auth_store_recovery_hash(recovery_key, &new_config_key);
    onvault_key_wipe(&new_config_key, sizeof(new_config_key));

    /* Create session token for the new master key */
    uint8_t token_data[ONVAULT_SESSION_DATA_SIZE];
    uint8_t session_blob[ONVAULT_SESSION_FILE_SIZE];
    uint64_t expiry = (uint64_t)time(NULL) + (uint64_t)ONVAULT_TOKEN_TTL;

    rc = onvault_random_bytes(token_data, ONVAULT_TOKEN_SIZE);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&new_master_key, sizeof(new_master_key));
        return rc;
    }
    memcpy(token_data + ONVAULT_TOKEN_SIZE, &expiry, sizeof(expiry));
    memcpy(session_blob, token_data, sizeof(token_data));

    rc = onvault_hmac_sha256(new_master_key.data, ONVAULT_KEY_SIZE,
                              token_data, sizeof(token_data),
                              session_blob + sizeof(token_data));
    onvault_memzero(token_data, sizeof(token_data));
    if (rc != ONVAULT_OK) {
        onvault_memzero(session_blob, sizeof(session_blob));
        onvault_key_wipe(&master_key, sizeof(master_key));
        onvault_key_wipe(&new_master_key, sizeof(new_master_key));
        return rc;
    }

    char session_path[PATH_MAX];
    snprintf(session_path, PATH_MAX, "%s/session", data_dir);
    rc = write_file(session_path, session_blob, sizeof(session_blob));
    onvault_memzero(session_blob, sizeof(session_blob));
    onvault_key_wipe(&master_key, sizeof(master_key));
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&new_master_key, sizeof(new_master_key));
        return rc;
    }

    /* Return new master key to caller */
    memcpy(master_key_out->data, new_master_key.data, ONVAULT_KEY_SIZE);
    onvault_key_wipe(&new_master_key, sizeof(new_master_key));
    return ONVAULT_OK;
}

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

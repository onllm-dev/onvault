/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * types.h — Core type definitions
 */

#ifndef ONVAULT_TYPES_H
#define ONVAULT_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <limits.h>

/* Key sizes */
#define ONVAULT_KEY_SIZE        32   /* AES-256: 32 bytes */
#define ONVAULT_XTS_KEY_SIZE    64   /* AES-256-XTS: 2x32 bytes */
#define ONVAULT_NONCE_SIZE      16   /* Per-file nonce for HKDF */
#define ONVAULT_SALT_SIZE       16   /* Argon2id salt */
#define ONVAULT_GCM_IV_SIZE     12   /* AES-GCM IV */
#define ONVAULT_GCM_TAG_SIZE    16   /* AES-GCM auth tag */
#define ONVAULT_HASH_SIZE       32   /* SHA-256 output */
#define ONVAULT_RECOVERY_LEN    24   /* Recovery key characters */

/* Block sizes for FUSE read/write encryption */
#define ONVAULT_BLOCK_SIZE      4096

/* Session token */
#define ONVAULT_TOKEN_SIZE      32
#define ONVAULT_TOKEN_TTL       900  /* 15 minutes in seconds */

/* A sensitive key that must be wiped after use */
typedef struct {
    uint8_t data[ONVAULT_KEY_SIZE];
} onvault_key_t;

/* XTS key (double-width for AES-XTS) */
typedef struct {
    uint8_t data[ONVAULT_XTS_KEY_SIZE];
} onvault_xts_key_t;

/* SHA-256 hash */
typedef struct {
    uint8_t data[ONVAULT_HASH_SIZE];
} onvault_hash_t;

/* Per-file nonce stored in xattr */
typedef struct {
    uint8_t data[ONVAULT_NONCE_SIZE];
} onvault_nonce_t;

/* GCM encrypted blob: IV + ciphertext + tag */
typedef struct {
    uint8_t  iv[ONVAULT_GCM_IV_SIZE];
    uint8_t  tag[ONVAULT_GCM_TAG_SIZE];
    uint8_t *ciphertext;
    size_t   ciphertext_len;
} onvault_gcm_blob_t;

/* Vault status */
typedef enum {
    VAULT_LOCKED,
    VAULT_UNLOCKED,
    VAULT_ERROR
} onvault_vault_status_t;

/* Vault definition */
typedef struct {
    char                   id[64];           /* Short identifier (e.g., "ssh") */
    char                   source_path[PATH_MAX]; /* Original path (e.g., ~/.ssh) */
    char                   vault_path[PATH_MAX];  /* Ciphertext path */
    char                   mount_path[PATH_MAX];  /* FUSE mount point */
    onvault_vault_status_t status;
} onvault_vault_t;

/* Process verification mode */
typedef enum {
    VERIFY_CODESIGN_PREFERRED,   /* cdHash + Team ID for signed, SHA-256 for unsigned */
    VERIFY_HASH_ONLY,            /* Always SHA-256, ignore code signing */
    VERIFY_CODESIGN_REQUIRED     /* Only code-signed binaries allowed */
} onvault_verify_mode_t;

/* Process identity (extracted from ESF es_process_t) */
typedef struct {
    pid_t  pid;
    uid_t  ruid;              /* Real UID (original user) */
    uid_t  euid;              /* Effective UID (current privilege) */
    char   path[PATH_MAX];    /* Binary path */
    char   signing_id[256];   /* Code signing identifier */
    char   team_id[32];       /* Developer Team ID */
    uint8_t cdhash[ONVAULT_HASH_SIZE]; /* Apple's content directory hash */
    onvault_hash_t binary_hash;        /* SHA-256 of binary file */
    int    is_signed;         /* Whether binary is code-signed */
} onvault_process_t;

/* Policy rule action */
typedef enum {
    RULE_ALLOW,
    RULE_DENY
} onvault_rule_action_t;

/* Policy rule */
typedef struct {
    char                   process_path[PATH_MAX];
    char                   team_id[32];
    char                   signing_id[256];
    onvault_hash_t         binary_hash;
    int                    allow_escalated; /* Allow su/sudo access */
    onvault_rule_action_t  action;
    int                    use_hash;        /* Whether binary_hash is set */
    int                    use_team_id;     /* Whether team_id is set */
} onvault_rule_t;

/* Return codes */
typedef enum {
    ONVAULT_OK = 0,
    ONVAULT_ERR_CRYPTO = -1,
    ONVAULT_ERR_IO = -2,
    ONVAULT_ERR_AUTH = -3,
    ONVAULT_ERR_DENIED = -4,
    ONVAULT_ERR_NOT_FOUND = -5,
    ONVAULT_ERR_ALREADY_EXISTS = -6,
    ONVAULT_ERR_KEYCHAIN = -7,
    ONVAULT_ERR_MEMORY = -8,
    ONVAULT_ERR_INVALID = -9
} onvault_error_t;

#endif /* ONVAULT_TYPES_H */

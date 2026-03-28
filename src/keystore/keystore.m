/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * keystore.c — Secure Enclave + Keychain key management
 *
 * Architecture:
 *   1. Generate EC P-256 key pair in Secure Enclave (non-exportable)
 *   2. Generate ephemeral EC key pair in software
 *   3. ECDH(SE private, ephemeral public) → wrapping key
 *   4. AES-256-GCM(wrapping key, master key) → wrapped blob
 *   5. Store wrapped blob + ephemeral public key in Keychain
 *   6. To unwrap: ECDH(SE private, stored ephemeral public) → wrapping key → decrypt
 */

#include "keystore.h"
#include "../common/crypto.h"
#include "../common/memwipe.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <string.h>
#include <stdio.h>

/* Keychain labels and tags */
static const char *kSEKeyLabel    = "com.onvault.se-key";
static const char *kSWKeyLabel    = "com.onvault.sw-key";
static const char *kWrappedLabel  = "com.onvault.master-key-wrapped";
static int g_using_software_key   = 0;

/* --- EC key management (Secure Enclave with software fallback) --- */

static SecKeyRef find_existing_key(void)
{
    /* Try SE key first */
    NSDictionary *seQuery = @{
        (__bridge id)kSecClass:               (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyType:         (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits:   @256,
        (__bridge id)kSecAttrLabel:           @(kSEKeyLabel),
        (__bridge id)kSecReturnRef:           @YES,
        (__bridge id)kSecAttrTokenID:         (__bridge id)kSecAttrTokenIDSecureEnclave,
    };
    SecKeyRef key = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)seQuery, (CFTypeRef *)&key) == errSecSuccess && key)
        return key;

    /* Try software key */
    NSDictionary *swQuery = @{
        (__bridge id)kSecClass:               (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyType:         (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits:   @256,
        (__bridge id)kSecAttrLabel:           @(kSWKeyLabel),
        (__bridge id)kSecReturnRef:           @YES,
    };
    if (SecItemCopyMatching((__bridge CFDictionaryRef)swQuery, (CFTypeRef *)&key) == errSecSuccess && key) {
        g_using_software_key = 1;
        return key;
    }

    return NULL;
}

static SecKeyRef get_or_create_se_key(void)
{
    /* Check for existing key (SE or software) */
    SecKeyRef key = find_existing_key();
    if (key) return key;

    /* Try creating SE key first */
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        NULL
    );

    if (access) {
        NSDictionary *seAttrs = @{
            (__bridge id)kSecAttrKeyType:         (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrKeySizeInBits:   @256,
            (__bridge id)kSecAttrTokenID:         (__bridge id)kSecAttrTokenIDSecureEnclave,
            (__bridge id)kSecPrivateKeyAttrs: @{
                (__bridge id)kSecAttrIsPermanent:    @YES,
                (__bridge id)kSecAttrLabel:          @(kSEKeyLabel),
                (__bridge id)kSecAttrAccessControl:  (__bridge id)access,
            },
        };

        CFErrorRef error = NULL;
        key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)seAttrs, &error);
        CFRelease(access);

        if (key && !error) {
            fprintf(stderr, "onvault: using Secure Enclave for key protection\n");
            return key;
        }
        if (key) CFRelease(key);
        if (error) CFRelease(error);
    }

    /* SE unavailable — fall back to software EC key in Keychain */
    fprintf(stderr, "onvault: Secure Enclave unavailable, using software key "
                    "(less secure — sign with Apple Developer ID for SE support)\n");

    NSDictionary *swAttrs = @{
        (__bridge id)kSecAttrKeyType:         (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits:   @256,
        (__bridge id)kSecPrivateKeyAttrs: @{
            (__bridge id)kSecAttrIsPermanent:    @YES,
            (__bridge id)kSecAttrLabel:          @(kSWKeyLabel),
            (__bridge id)kSecAttrAccessible:     (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        },
    };

    CFErrorRef swError = NULL;
    key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)swAttrs, &swError);

    if (swError) {
        if (key) CFRelease(key);
        NSError *nsErr = (__bridge NSError *)swError;
        fprintf(stderr, "onvault: software key creation failed: %s\n",
                [[nsErr localizedDescription] UTF8String]);
        CFRelease(swError);
        return NULL;
    }

    g_using_software_key = 1;
    return key;
}

/* --- ECDH key agreement --- */

static int ecdh_derive_wrapping_key(SecKeyRef se_private_key,
                                     SecKeyRef peer_public_key,
                                     onvault_key_t *wrapping_key)
{
    NSDictionary *params = @{
        (__bridge id)kSecKeyKeyExchangeParameterRequestedSize: @32,
        (__bridge id)kSecKeyKeyExchangeParameterSharedInfo:
            [@"onvault-key-wrap" dataUsingEncoding:NSUTF8StringEncoding],
    };

    CFErrorRef error = NULL;
    CFDataRef shared = SecKeyCopyKeyExchangeResult(
        se_private_key,
        kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256,
        peer_public_key,
        (__bridge CFDictionaryRef)params,
        &error
    );

    if (!shared || error) {
        if (shared) CFRelease(shared);
        if (error) CFRelease(error);
        return ONVAULT_ERR_KEYCHAIN;
    }

    if (CFDataGetLength(shared) < ONVAULT_KEY_SIZE) {
        CFRelease(shared);
        return ONVAULT_ERR_KEYCHAIN;
    }

    memcpy(wrapping_key->data, CFDataGetBytePtr(shared), ONVAULT_KEY_SIZE);
    CFRelease(shared);
    return ONVAULT_OK;
}

/* --- Keychain storage for wrapped master key + ephemeral public --- */

static int store_wrapped_blob(const uint8_t *data, size_t len)
{
    /* Delete any existing entry */
    NSDictionary *delQuery = @{
        (__bridge id)kSecClass:      (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrLabel:  @(kWrappedLabel),
        (__bridge id)kSecAttrService: @"com.onvault",
    };
    SecItemDelete((__bridge CFDictionaryRef)delQuery);

    NSDictionary *attrs = @{
        (__bridge id)kSecClass:           (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrLabel:       @(kWrappedLabel),
        (__bridge id)kSecAttrService:     @"com.onvault",
        (__bridge id)kSecAttrAccount:     @"master-key",
        (__bridge id)kSecValueData:       [NSData dataWithBytes:data length:len],
        (__bridge id)kSecAttrAccessible:  (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    };

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
    return (status == errSecSuccess) ? ONVAULT_OK : ONVAULT_ERR_KEYCHAIN;
}

static int load_wrapped_blob(uint8_t *data, size_t *len)
{
    NSDictionary *query = @{
        (__bridge id)kSecClass:            (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrLabel:        @(kWrappedLabel),
        (__bridge id)kSecAttrService:      @"com.onvault",
        (__bridge id)kSecAttrAccount:      @"master-key",
        (__bridge id)kSecReturnData:       @YES,
        (__bridge id)kSecMatchLimit:       (__bridge id)kSecMatchLimitOne,
    };

    CFDataRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query,
                                          (CFTypeRef *)&result);

    if (status != errSecSuccess || !result)
        return ONVAULT_ERR_NOT_FOUND;

    size_t data_len = (size_t)CFDataGetLength(result);
    if (data_len > *len) {
        CFRelease(result);
        return ONVAULT_ERR_MEMORY;
    }

    memcpy(data, CFDataGetBytePtr(result), data_len);
    *len = data_len;
    CFRelease(result);
    return ONVAULT_OK;
}

/* --- Public API --- */

int onvault_keystore_init(void)
{
    SecKeyRef se_key = get_or_create_se_key();
    if (!se_key)
        return ONVAULT_ERR_KEYCHAIN;
    CFRelease(se_key);
    return ONVAULT_OK;
}

int onvault_keystore_store_master_key(const onvault_key_t *master_key)
{
    if (!master_key)
        return ONVAULT_ERR_INVALID;

    /* Get SE private key */
    SecKeyRef se_key = get_or_create_se_key();
    if (!se_key)
        return ONVAULT_ERR_KEYCHAIN;

    /* Generate ephemeral EC key pair */
    NSDictionary *ephAttrs = @{
        (__bridge id)kSecAttrKeyType:       (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits: @256,
    };

    CFErrorRef error = NULL;
    SecKeyRef eph_private = SecKeyCreateRandomKey((__bridge CFDictionaryRef)ephAttrs, &error);
    if (!eph_private || error) {
        CFRelease(se_key);
        if (eph_private) CFRelease(eph_private);
        if (error) CFRelease(error);
        return ONVAULT_ERR_CRYPTO;
    }

    SecKeyRef eph_public = SecKeyCopyPublicKey(eph_private);

    /* ECDH: SE private + ephemeral public → wrapping key */
    onvault_key_t wrapping_key;
    onvault_mlock(&wrapping_key, sizeof(wrapping_key));

    int rc = ecdh_derive_wrapping_key(se_key, eph_public, &wrapping_key);
    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&wrapping_key, sizeof(wrapping_key));
        CFRelease(se_key);
        CFRelease(eph_private);
        CFRelease(eph_public);
        return rc;
    }

    /* AES-GCM wrap the master key */
    uint8_t ciphertext[ONVAULT_KEY_SIZE];
    uint8_t tag[ONVAULT_GCM_TAG_SIZE];
    uint8_t iv[ONVAULT_GCM_IV_SIZE];

    rc = onvault_aes_gcm_encrypt(&wrapping_key, NULL, NULL, 0,
                                  master_key->data, ONVAULT_KEY_SIZE,
                                  ciphertext, tag, iv);
    onvault_key_wipe(&wrapping_key, sizeof(wrapping_key));

    if (rc != ONVAULT_OK) {
        CFRelease(se_key);
        CFRelease(eph_private);
        CFRelease(eph_public);
        return rc;
    }

    /* Export ephemeral public key */
    CFDataRef eph_pub_data = SecKeyCopyExternalRepresentation(eph_public, &error);
    CFRelease(eph_private);
    CFRelease(eph_public);
    CFRelease(se_key);

    if (!eph_pub_data || error) {
        if (eph_pub_data) CFRelease(eph_pub_data);
        if (error) CFRelease(error);
        return ONVAULT_ERR_CRYPTO;
    }

    /* Pack: [iv(12)] [tag(16)] [ciphertext(32)] [eph_pub_len(4)] [eph_pub_data] */
    size_t eph_len = (size_t)CFDataGetLength(eph_pub_data);
    size_t blob_len = ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE +
                      ONVAULT_KEY_SIZE + 4 + eph_len;
    uint8_t *blob = malloc(blob_len);
    if (!blob) {
        CFRelease(eph_pub_data);
        return ONVAULT_ERR_MEMORY;
    }

    size_t off = 0;
    memcpy(blob + off, iv, ONVAULT_GCM_IV_SIZE); off += ONVAULT_GCM_IV_SIZE;
    memcpy(blob + off, tag, ONVAULT_GCM_TAG_SIZE); off += ONVAULT_GCM_TAG_SIZE;
    memcpy(blob + off, ciphertext, ONVAULT_KEY_SIZE); off += ONVAULT_KEY_SIZE;
    uint32_t eph_len32 = (uint32_t)eph_len;
    memcpy(blob + off, &eph_len32, 4); off += 4;
    memcpy(blob + off, CFDataGetBytePtr(eph_pub_data), eph_len);

    CFRelease(eph_pub_data);

    rc = store_wrapped_blob(blob, blob_len);
    onvault_memzero(blob, blob_len);
    free(blob);
    return rc;
}

int onvault_keystore_load_master_key(onvault_key_t *master_key)
{
    if (!master_key)
        return ONVAULT_ERR_INVALID;

    /* Load wrapped blob from Keychain */
    uint8_t blob[512];
    size_t blob_len = sizeof(blob);
    int rc = load_wrapped_blob(blob, &blob_len);
    if (rc != ONVAULT_OK)
        return rc;

    /* Unpack */
    size_t min_len = ONVAULT_GCM_IV_SIZE + ONVAULT_GCM_TAG_SIZE + ONVAULT_KEY_SIZE + 4;
    if (blob_len < min_len) {
        onvault_memzero(blob, blob_len);
        return ONVAULT_ERR_INVALID;
    }

    size_t off = 0;
    uint8_t iv[ONVAULT_GCM_IV_SIZE];
    uint8_t tag[ONVAULT_GCM_TAG_SIZE];
    uint8_t ciphertext[ONVAULT_KEY_SIZE];

    memcpy(iv, blob + off, ONVAULT_GCM_IV_SIZE); off += ONVAULT_GCM_IV_SIZE;
    memcpy(tag, blob + off, ONVAULT_GCM_TAG_SIZE); off += ONVAULT_GCM_TAG_SIZE;
    memcpy(ciphertext, blob + off, ONVAULT_KEY_SIZE); off += ONVAULT_KEY_SIZE;

    uint32_t eph_len32;
    memcpy(&eph_len32, blob + off, 4); off += 4;
    size_t eph_len = (size_t)eph_len32;

    if (off + eph_len > blob_len) {
        onvault_memzero(blob, blob_len);
        return ONVAULT_ERR_INVALID;
    }

    /* Reconstruct ephemeral public key */
    CFDataRef eph_pub_data = CFDataCreate(kCFAllocatorDefault, blob + off, (CFIndex)eph_len);
    onvault_memzero(blob, blob_len);

    if (!eph_pub_data)
        return ONVAULT_ERR_MEMORY;

    NSDictionary *keyAttrs = @{
        (__bridge id)kSecAttrKeyType:       (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeyClass:      (__bridge id)kSecAttrKeyClassPublic,
        (__bridge id)kSecAttrKeySizeInBits: @256,
    };

    CFErrorRef error = NULL;
    SecKeyRef eph_public = SecKeyCreateWithData(eph_pub_data,
                                                 (__bridge CFDictionaryRef)keyAttrs,
                                                 &error);
    CFRelease(eph_pub_data);

    if (!eph_public || error) {
        if (eph_public) CFRelease(eph_public);
        if (error) CFRelease(error);
        return ONVAULT_ERR_CRYPTO;
    }

    /* Get SE private key */
    SecKeyRef se_key = get_or_create_se_key();
    if (!se_key) {
        CFRelease(eph_public);
        return ONVAULT_ERR_KEYCHAIN;
    }

    /* ECDH: SE private + ephemeral public → wrapping key */
    onvault_key_t wrapping_key;
    onvault_mlock(&wrapping_key, sizeof(wrapping_key));

    rc = ecdh_derive_wrapping_key(se_key, eph_public, &wrapping_key);
    CFRelease(se_key);
    CFRelease(eph_public);

    if (rc != ONVAULT_OK) {
        onvault_key_wipe(&wrapping_key, sizeof(wrapping_key));
        return rc;
    }

    /* AES-GCM unwrap the master key */
    onvault_mlock(master_key, sizeof(*master_key));

    rc = onvault_aes_gcm_decrypt(&wrapping_key, iv, NULL, 0,
                                  ciphertext, ONVAULT_KEY_SIZE,
                                  master_key->data, tag);
    onvault_key_wipe(&wrapping_key, sizeof(wrapping_key));

    if (rc != ONVAULT_OK) {
        onvault_key_wipe(master_key, sizeof(*master_key));
    }

    return rc;
}

int onvault_keystore_has_master_key(void)
{
    uint8_t blob[512];
    size_t blob_len = sizeof(blob);
    int rc = load_wrapped_blob(blob, &blob_len);
    onvault_memzero(blob, blob_len);
    return (rc == ONVAULT_OK) ? 1 : 0;
}

int onvault_keystore_destroy(void)
{
    /* Delete wrapped master key from Keychain */
    NSDictionary *delWrapped = @{
        (__bridge id)kSecClass:      (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrLabel:  @(kWrappedLabel),
        (__bridge id)kSecAttrService: @"com.onvault",
    };
    SecItemDelete((__bridge CFDictionaryRef)delWrapped);

    /* Delete SE key */
    NSDictionary *delSE = @{
        (__bridge id)kSecClass:      (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrLabel:  @(kSEKeyLabel),
        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
    };
    SecItemDelete((__bridge CFDictionaryRef)delSE);

    /* Delete software key */
    NSDictionary *delSW = @{
        (__bridge id)kSecClass:      (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrLabel:  @(kSWKeyLabel),
    };
    SecItemDelete((__bridge CFDictionaryRef)delSW);

    return ONVAULT_OK;
}

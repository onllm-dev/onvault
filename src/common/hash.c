/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * hash.c — SHA-256 hashing (CommonCrypto)
 */

#include "hash.h"
#include <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <string.h>

void onvault_sha256(const uint8_t *data, size_t len, onvault_hash_t *hash)
{
    CC_SHA256(data, (CC_LONG)len, hash->data);
}

int onvault_sha256_file(const char *path, onvault_hash_t *hash)
{
    if (!path || !hash)
        return -1;

    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    uint8_t buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        CC_SHA256_Update(&ctx, buf, (CC_LONG)n);
    }

    int err = ferror(f);
    fclose(f);

    if (err) {
        memset(buf, 0, sizeof(buf));
        return -1;
    }

    CC_SHA256_Final(hash->data, &ctx);
    memset(buf, 0, sizeof(buf));
    return 0;
}

int onvault_hash_compare(const onvault_hash_t *a, const onvault_hash_t *b)
{
    if (!a || !b)
        return -1;

    /* Constant-time comparison */
    volatile uint8_t diff = 0;
    for (int i = 0; i < ONVAULT_HASH_SIZE; i++) {
        diff |= a->data[i] ^ b->data[i];
    }
    return diff ? -1 : 0;
}

void onvault_hash_to_hex(const onvault_hash_t *hash, char *buf)
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < ONVAULT_HASH_SIZE; i++) {
        buf[i * 2]     = hex[(hash->data[i] >> 4) & 0x0f];
        buf[i * 2 + 1] = hex[hash->data[i] & 0x0f];
    }
    buf[ONVAULT_HASH_SIZE * 2] = '\0';
}

/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * watch.c — Learning/discovery mode
 *
 * Uses ESF NOTIFY_OPEN events (non-blocking observation) to discover
 * which processes access files under a watched path.
 */

#include "watch.h"
#include "../common/crypto.h"
#include "../common/hash.h"
#include "../common/config.h"
#include "../common/memwipe.h"
#include "../auth/auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libproc.h>
#include <Security/Security.h>

/* Extract code signing info from a binary path */
static void extract_codesign_info(const char *path, onvault_watch_entry_t *entry)
{
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (!url) return;

    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (status != errSecSuccess || !code) return;

    /* Verify the signature (don't reject unsigned — just note it) */
    status = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
    if (status == errSecSuccess) {
        entry->is_signed = 1;

        /* Extract signing information */
        CFDictionaryRef info = NULL;
        status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
        if (status == errSecSuccess && info) {
            /* Team ID */
            CFStringRef teamId = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
            if (teamId && CFGetTypeID(teamId) == CFStringGetTypeID()) {
                CFStringGetCString(teamId, entry->team_id,
                                    sizeof(entry->team_id), kCFStringEncodingUTF8);
            }

            /* Signing identifier */
            CFStringRef signId = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
            if (signId && CFGetTypeID(signId) == CFStringGetTypeID()) {
                CFStringGetCString(signId, entry->signing_id,
                                    sizeof(entry->signing_id), kCFStringEncodingUTF8);
            }

            CFRelease(info);
        }
    }

    CFRelease(code);
}

/* In-memory watch results */
static onvault_watch_entry_t g_entries[ONVAULT_MAX_WATCH_ENTRIES];
static int g_entry_count = 0;
static char g_watch_path[PATH_MAX] = {0};
static volatile int g_watching = 0;
static pthread_mutex_t g_watch_lock = PTHREAD_MUTEX_INITIALIZER;

/* Record a process access — called from ESF NOTIFY handler */
void onvault_watch_record_access(pid_t pid)
{
    char proc_path[PROC_PIDPATHINFO_MAXSIZE];
    int ret = proc_pidpath(pid, proc_path, sizeof(proc_path));
    if (ret <= 0)
        return;

    pthread_mutex_lock(&g_watch_lock);

    /* Check if already recorded */
    for (int i = 0; i < g_entry_count; i++) {
        if (strcmp(g_entries[i].path, proc_path) == 0) {
            g_entries[i].access_count++;
            pthread_mutex_unlock(&g_watch_lock);
            return;
        }
    }

    /* New entry */
    if (g_entry_count < ONVAULT_MAX_WATCH_ENTRIES) {
        onvault_watch_entry_t *e = &g_entries[g_entry_count];
        memset(e, 0, sizeof(*e));
        strlcpy(e->path, proc_path, PATH_MAX);
        e->access_count = 1;
        onvault_sha256_file(proc_path, &e->binary_hash);
        extract_codesign_info(proc_path, e);
        g_entry_count++;
    }

    pthread_mutex_unlock(&g_watch_lock);
}

/* Watch thread: polls /dev/fsevents or uses ESF NOTIFY */
static void *watch_thread(void *arg)
{
    int duration = *(int *)arg;
    free(arg);

    int elapsed = 0;
    while (g_watching && (duration == 0 || elapsed < duration)) {
        sleep(1);
        elapsed++;
        /* In a real implementation, ESF NOTIFY events would call
         * record_access() asynchronously. This is a polling placeholder. */
    }

    g_watching = 0;
    return NULL;
}

int onvault_watch_start(const char *path, int duration_seconds)
{
    if (!path || g_watching)
        return ONVAULT_ERR_INVALID;

    strlcpy(g_watch_path, path, PATH_MAX);
    g_entry_count = 0;
    g_watching = 1;

    int *dur = malloc(sizeof(int));
    if (!dur)
        return ONVAULT_ERR_MEMORY;
    *dur = duration_seconds;

    pthread_t tid;
    pthread_create(&tid, NULL, watch_thread, dur);
    pthread_detach(tid);

    return ONVAULT_OK;
}

void onvault_watch_stop(void)
{
    g_watching = 0;
}

int onvault_watch_get_results(onvault_watch_entry_t *entries, int max_entries)
{
    pthread_mutex_lock(&g_watch_lock);

    int count = g_entry_count;
    if (count > max_entries)
        count = max_entries;

    memcpy(entries, g_entries, (size_t)count * sizeof(onvault_watch_entry_t));

    pthread_mutex_unlock(&g_watch_lock);
    return count;
}

int onvault_watch_save(const char *vault_id, const onvault_key_t *config_key)
{
    if (!vault_id || !config_key)
        return ONVAULT_ERR_INVALID;

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    char watch_dir[PATH_MAX];
    snprintf(watch_dir, PATH_MAX, "%s/watch", data_dir);
    mkdir(watch_dir, 0700);

    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "%s/%s.enc", watch_dir, vault_id);

    pthread_mutex_lock(&g_watch_lock);

    int rc = onvault_config_write(path, config_key,
                                   (const uint8_t *)g_entries,
                                   (size_t)g_entry_count * sizeof(onvault_watch_entry_t));

    pthread_mutex_unlock(&g_watch_lock);
    return rc;
}

int onvault_watch_load(const char *vault_id, const onvault_key_t *config_key,
                        onvault_watch_entry_t *entries, int *count)
{
    if (!vault_id || !config_key || !entries || !count)
        return ONVAULT_ERR_INVALID;

    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) != ONVAULT_OK)
        return ONVAULT_ERR_IO;

    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "%s/watch/%s.enc", data_dir, vault_id);

    size_t buf_len = (size_t)ONVAULT_MAX_WATCH_ENTRIES * sizeof(onvault_watch_entry_t);
    uint8_t *buf = malloc(buf_len);
    if (!buf)
        return ONVAULT_ERR_MEMORY;

    int rc = onvault_config_read(path, config_key, buf, &buf_len);
    if (rc != ONVAULT_OK) {
        free(buf);
        return rc;
    }

    *count = (int)(buf_len / sizeof(onvault_watch_entry_t));
    if (*count > ONVAULT_MAX_WATCH_ENTRIES)
        *count = ONVAULT_MAX_WATCH_ENTRIES;

    memcpy(entries, buf, (size_t)*count * sizeof(onvault_watch_entry_t));
    free(buf);
    return ONVAULT_OK;
}

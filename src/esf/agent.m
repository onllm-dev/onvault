/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * agent.m — Endpoint Security Framework client (Layer 2)
 *
 * Requires: com.apple.developer.endpoint-security.client entitlement
 * Requires: Full Disk Access TCC permission
 * Requires: macOS 15 Sequoia+
 * Requires: Full Xcode SDK (not just Command Line Tools)
 */

#import <Foundation/Foundation.h>
#include "agent.h"
#include "policy.h"
#include "../common/hash.h"
#include "../common/memwipe.h"

#include <stdio.h>
#include <string.h>
#include <libproc.h>
#include <pthread.h>

/* Monitored paths (vault mount points) */
#define MAX_MONITORED_PATHS 64
static char g_monitored_paths[MAX_MONITORED_PATHS][PATH_MAX];
static int  g_monitored_count = 0;
static pthread_rwlock_t g_path_lock = PTHREAD_RWLOCK_INITIALIZER;

/* Deny callback */
static onvault_deny_callback_fn g_deny_callback = NULL;

void onvault_esf_set_deny_callback(onvault_deny_callback_fn fn)
{
    g_deny_callback = fn;
}

int onvault_esf_add_monitored_path(const char *path)
{
    if (!path)
        return ONVAULT_ERR_INVALID;

    pthread_rwlock_wrlock(&g_path_lock);
    if (g_monitored_count >= MAX_MONITORED_PATHS) {
        pthread_rwlock_unlock(&g_path_lock);
        return ONVAULT_ERR_INVALID;
    }
    strlcpy(g_monitored_paths[g_monitored_count], path, PATH_MAX);
    g_monitored_count++;
    pthread_rwlock_unlock(&g_path_lock);
    return ONVAULT_OK;
}

int onvault_esf_remove_monitored_path(const char *path)
{
    pthread_rwlock_wrlock(&g_path_lock);
    for (int i = 0; i < g_monitored_count; i++) {
        if (strcmp(g_monitored_paths[i], path) == 0) {
            for (int j = i; j < g_monitored_count - 1; j++) {
                memcpy(g_monitored_paths[j], g_monitored_paths[j + 1], PATH_MAX);
            }
            g_monitored_count--;
            pthread_rwlock_unlock(&g_path_lock);
            return ONVAULT_OK;
        }
    }
    pthread_rwlock_unlock(&g_path_lock);
    return ONVAULT_ERR_NOT_FOUND;
}

int onvault_esf_extract_process(pid_t pid, onvault_process_t *proc)
{
    if (!proc)
        return ONVAULT_ERR_INVALID;

    memset(proc, 0, sizeof(*proc));
    proc->pid = pid;

    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
    if (ret > 0) {
        strlcpy(proc->path, pathbuf, PATH_MAX);
        onvault_sha256_file(proc->path, &proc->binary_hash);
    }

    return ONVAULT_OK;
}

#ifdef HAVE_ESF

/* ============================================================
 * Full ESF implementation (requires Xcode SDK + entitlements)
 * ============================================================ */

#import <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

static es_client_t *g_esf_client = NULL;

static int path_in_monitored_vault(const char *file_path,
                                   char *vault_path,
                                   size_t vault_path_len)
{
    int found = 0;

    if (!file_path || !vault_path || vault_path_len == 0)
        return 0;
    vault_path[0] = '\0';

    pthread_rwlock_rdlock(&g_path_lock);
    for (int i = 0; i < g_monitored_count; i++) {
        size_t len = strlen(g_monitored_paths[i]);
        if (strncmp(file_path, g_monitored_paths[i], len) == 0 &&
            (file_path[len] == '/' || file_path[len] == '\0')) {
            strlcpy(vault_path, g_monitored_paths[i], vault_path_len);
            found = 1;
            break;
        }
    }
    pthread_rwlock_unlock(&g_path_lock);
    return found;
}

static void extract_process_info(const es_process_t *es_proc,
                                  onvault_process_t *proc)
{
    memset(proc, 0, sizeof(*proc));
    proc->pid = audit_token_to_pid(es_proc->audit_token);
    proc->ruid = audit_token_to_ruid(es_proc->audit_token);
    proc->euid = audit_token_to_euid(es_proc->audit_token);

    if (es_proc->executable && es_proc->executable->path.data)
        strlcpy(proc->path, es_proc->executable->path.data, PATH_MAX);

    if (es_proc->signing_id.data && es_proc->signing_id.length > 0) {
        strlcpy(proc->signing_id, es_proc->signing_id.data, sizeof(proc->signing_id));
        proc->is_signed = 1;
    }

    if (es_proc->team_id.data && es_proc->team_id.length > 0)
        strlcpy(proc->team_id, es_proc->team_id.data, sizeof(proc->team_id));

    memcpy(proc->cdhash, es_proc->cdhash, 20);
}

static void esf_handler(es_client_t *client, const es_message_t *msg)
{
    const char *file_path = NULL;

    switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_OPEN:
        if (msg->event.open.file) file_path = msg->event.open.file->path.data;
        break;
    case ES_EVENT_TYPE_AUTH_RENAME:
        if (msg->event.rename.source) file_path = msg->event.rename.source->path.data;
        break;
    case ES_EVENT_TYPE_AUTH_LINK:
        if (msg->event.link.source) file_path = msg->event.link.source->path.data;
        break;
    case ES_EVENT_TYPE_AUTH_UNLINK:
        if (msg->event.unlink.target) file_path = msg->event.unlink.target->path.data;
        break;
    case ES_EVENT_TYPE_AUTH_TRUNCATE:
        if (msg->event.truncate.target) file_path = msg->event.truncate.target->path.data;
        break;
    case ES_EVENT_TYPE_AUTH_EXEC:
        if (msg->event.exec.target && msg->event.exec.target->executable)
            file_path = msg->event.exec.target->executable->path.data;
        break;
    default:
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    if (!file_path) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    char vault_path[PATH_MAX];
    if (!path_in_monitored_vault(file_path, vault_path, sizeof(vault_path))) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    onvault_process_t proc;
    extract_process_info(msg->process, &proc);

    int allowed = onvault_policy_evaluate(&proc, file_path, vault_path);

    if (allowed) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
    } else {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY, false);
        onvault_deny_callback_fn cb = g_deny_callback;
        __sync_synchronize();
        if (cb) {
            const char *id = strrchr(vault_path, '/');
            id = id ? id + 1 : vault_path;
            cb(&proc, file_path, id);
        }
    }
}

int onvault_esf_init(void)
{
    if (g_esf_client) return ONVAULT_OK;

    es_new_client_result_t result = es_new_client(&g_esf_client,
        ^(es_client_t *client, const es_message_t *msg) {
            esf_handler(client, msg);
        });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "onvault: ESF client creation failed (result=%d)\n", result);
        g_esf_client = NULL;
        return ONVAULT_ERR_DENIED;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_AUTH_LINK, ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_EXEC,
    };

    if (es_subscribe(g_esf_client, events, sizeof(events)/sizeof(events[0])) != ES_RETURN_SUCCESS) {
        es_delete_client(g_esf_client);
        g_esf_client = NULL;
        return ONVAULT_ERR_IO;
    }

    return ONVAULT_OK;
}

int onvault_esf_start(void)
{
    if (!g_esf_client) return ONVAULT_ERR_INVALID;
    dispatch_main();
    return ONVAULT_OK;
}

void onvault_esf_stop(void)
{
    if (g_esf_client) {
        es_unsubscribe_all(g_esf_client);
        es_delete_client(g_esf_client);
        g_esf_client = NULL;
    }
    pthread_rwlock_wrlock(&g_path_lock);
    g_monitored_count = 0;
    pthread_rwlock_unlock(&g_path_lock);
}

#else /* !HAVE_ESF */

/* ============================================================
 * Stub implementation when ESF SDK is not available
 * ============================================================ */

int onvault_esf_init(void)
{
    fprintf(stderr, "onvault: ESF not available (compile with Xcode SDK)\n");
    return ONVAULT_ERR_DENIED;
}

int onvault_esf_start(void)
{
    return ONVAULT_ERR_INVALID;
}

void onvault_esf_stop(void)
{
    pthread_rwlock_wrlock(&g_path_lock);
    g_monitored_count = 0;
    pthread_rwlock_unlock(&g_path_lock);
}

#endif /* HAVE_ESF */

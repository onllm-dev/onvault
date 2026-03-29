/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * menubar.m — Menu bar status item, per-vault management, and notifications
 *
 * Uses Objective-C for NSStatusItem, NSMenu, and UNUserNotificationCenter.
 */

#import <Cocoa/Cocoa.h>
#import <UserNotifications/UserNotifications.h>
#import <WebKit/WebKit.h>
#include "menubar.h"
#include "../common/ipc.h"
#include "../common/crypto.h"
#include "../common/memwipe.h"
#include "../auth/auth.h"
#include <pthread.h>
#include <time.h>

/* --- Recent denial tracking --- */

#define MAX_RECENT_DENIALS 10

typedef struct {
    char process_name[256];
    char process_path[PATH_MAX];
    char file_path[PATH_MAX];
    char vault_id[64];
    time_t timestamp;
} recent_denial_t;

static recent_denial_t g_recent_denials[MAX_RECENT_DENIALS];
static int g_denial_count = 0;
static pthread_mutex_t g_denial_lock = PTHREAD_MUTEX_INITIALIZER;

/* --- Vault info for menu --- */

#define MAX_MENU_VAULTS 32

typedef struct {
    char vault_id[64];
    char source_path[PATH_MAX];
    int  is_mounted;
} menu_vault_info_t;

static menu_vault_info_t g_menu_vaults[MAX_MENU_VAULTS];
static int g_menu_vault_count = 0;

/* --- Menu bar delegate --- */

@interface OnVaultMenuBarDelegate : NSObject <NSApplicationDelegate, UNUserNotificationCenterDelegate, WKNavigationDelegate, WKScriptMessageHandler>
@property (strong, nonatomic) NSStatusItem *statusItem;
@property (strong, nonatomic) NSPopover *popover;
@property (strong, nonatomic) WKWebView *webView;
@property (strong, nonatomic) id eventMonitor;
@property (assign, nonatomic) int vaultCount;
@property (assign, nonatomic) int httpPort;
@property (assign, nonatomic) BOOL isLocked;
@end

@implementation OnVaultMenuBarDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;

    /* Create status item */
    self.statusItem = [[NSStatusBar systemStatusBar]
                        statusItemWithLength:NSVariableStatusItemLength];
    self.statusItem.button.title = @"🔒";

    /* Read HTTP port from file */
    self.httpPort = 0;
    char data_dir[PATH_MAX];
    if (onvault_get_data_dir(data_dir) == ONVAULT_OK) {
        char port_path[PATH_MAX];
        snprintf(port_path, PATH_MAX, "%s/http.port", data_dir);
        FILE *pf = fopen(port_path, "r");
        if (pf) {
            int port = 0;
            if (fscanf(pf, "%d", &port) == 1)
                self.httpPort = port;
            fclose(pf);
        }
    }

    /* Create WKWebView for popover with dynamic sizing */
    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
    WKUserContentController *ucc = [[WKUserContentController alloc] init];
    [ucc addScriptMessageHandler:self name:@"resize"];
    config.userContentController = ucc;
    self.webView = [[WKWebView alloc] initWithFrame:NSMakeRect(0, 0, 300, 100) configuration:config];
    self.webView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    self.webView.navigationDelegate = self;
    /* Transparent background so it blends with popover */
    [self.webView setValue:@NO forKey:@"drawsBackground"];

    NSViewController *vc = [[NSViewController alloc] init];
    vc.view = self.webView;
    vc.preferredContentSize = NSMakeSize(300, 100);

    self.popover = [[NSPopover alloc] init];
    self.popover.contentSize = NSMakeSize(300, 100);
    self.popover.behavior = NSPopoverBehaviorTransient;
    self.popover.animates = YES;
    self.popover.contentViewController = vc;

    /* Handle click: use button action + target.
     * Critical: do NOT set statusItem.menu — it overrides the action. */
    self.statusItem.button.action = @selector(togglePopover:);
    self.statusItem.button.target = self;

    /* Load the web UI now so it's ready when user clicks */
    [self loadWebUI];

    /* Start periodic refresh of vault status */
    [NSTimer scheduledTimerWithTimeInterval:5.0
                                     target:self
                                   selector:@selector(refreshVaultStatus)
                                   userInfo:nil
                                    repeats:YES];

    /* Request notification permission (only when running as bundled app) */
    if ([[NSBundle mainBundle] bundleIdentifier] != nil) {
        UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
        center.delegate = self;
        [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionSound)
                              completionHandler:^(BOOL granted, NSError *error) {
            if (!granted)
                NSLog(@"onvault: notification permission denied");
            if (error)
                NSLog(@"onvault: notification error: %@", error);
        }];

        /* Register notification actions */
        UNNotificationAction *allowOnce = [UNNotificationAction
            actionWithIdentifier:@"ALLOW_ONCE"
            title:@"Allow Once"
            options:UNNotificationActionOptionNone];

        UNNotificationAction *allowAlways = [UNNotificationAction
            actionWithIdentifier:@"ALLOW_ALWAYS"
            title:@"Allow Always"
            options:UNNotificationActionOptionNone];

        UNNotificationCategory *denyCategory = [UNNotificationCategory
            categoryWithIdentifier:@"DENY"
            actions:@[allowOnce, allowAlways]
            intentIdentifiers:@[]
            options:UNNotificationCategoryOptionNone];

        [center setNotificationCategories:[NSSet setWithObject:denyCategory]];
    }
}

- (void)togglePopover:(id)sender {
    (void)sender;
    if (self.popover.isShown) {
        [self.popover performClose:nil];
        if (self.eventMonitor) {
            [NSEvent removeMonitor:self.eventMonitor];
            self.eventMonitor = nil;
        }
    } else {
        /* Reload the web UI each time popover opens */
        [self loadWebUI];

        [self.popover showRelativeToRect:self.statusItem.button.bounds
                                  ofView:self.statusItem.button
                           preferredEdge:NSMinYEdge];

        /* Close popover when clicking outside */
        self.eventMonitor = [NSEvent addGlobalMonitorForEventsMatchingMask:
            (NSEventMaskLeftMouseDown | NSEventMaskRightMouseDown)
            handler:^(NSEvent *event) {
                (void)event;
                if (self.popover.isShown) {
                    [self.popover performClose:nil];
                    if (self.eventMonitor) {
                        [NSEvent removeMonitor:self.eventMonitor];
                        self.eventMonitor = nil;
                    }
                }
            }];
    }
}

- (void)loadWebUI {
    if (self.httpPort > 0) {
        NSString *urlStr = [NSString stringWithFormat:@"http://127.0.0.1:%d/menubar", self.httpPort];
        NSURL *url = [NSURL URLWithString:urlStr];
        [self.webView loadRequest:[NSURLRequest requestWithURL:url]];
    } else {
        /* Fallback: show a message if HTTP server isn't ready */
        [self.webView loadHTMLString:@"<html><body style='background:#0d0d0d;color:#fff;font-family:system-ui;padding:40px;text-align:center'>"
            "<h3>onvault</h3><p style='color:#888'>Starting...</p></body></html>"
            baseURL:nil];
        /* Retry reading the port file */
        char data_dir[PATH_MAX];
        if (onvault_get_data_dir(data_dir) == ONVAULT_OK) {
            char port_path[PATH_MAX];
            snprintf(port_path, PATH_MAX, "%s/http.port", data_dir);
            FILE *pf = fopen(port_path, "r");
            if (pf) {
                int port = 0;
                if (fscanf(pf, "%d", &port) == 1)
                    self.httpPort = port;
                fclose(pf);
            }
        }
    }
}

/* WKScriptMessageHandler — receive resize messages from JS */
- (void)userContentController:(WKUserContentController *)ucc
       didReceiveScriptMessage:(WKScriptMessage *)message {
    (void)ucc;
    if ([message.name isEqualToString:@"resize"]) {
        CGFloat height = [message.body doubleValue];
        if (height < 150) height = 150;
        if (height > 600) height = 600;
        self.popover.contentSize = NSMakeSize(300, height);
        self.popover.contentViewController.preferredContentSize = NSMakeSize(300, height);
    }
}

/* WKNavigationDelegate — resize popover based on content height */
- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    (void)navigation;
    /* Query the actual content height from the DOM */
    [webView evaluateJavaScript:@"document.body.scrollHeight"
              completionHandler:^(id result, NSError *error) {
        if (error || !result) return;
        CGFloat contentHeight = [result doubleValue];
        if (contentHeight < 150) contentHeight = 150;
        if (contentHeight > 600) contentHeight = 600;

        dispatch_async(dispatch_get_main_queue(), ^{
            self.popover.contentSize = NSMakeSize(300, contentHeight);
            self.popover.contentViewController.preferredContentSize = NSMakeSize(300, contentHeight);
        });
    }];
}

- (void)refreshVaultStatus {
    /* Query daemon for current vault list + status */
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_STATUS, NULL, 0, response, &resp_len);
    if (rc != ONVAULT_OK)
        return;
    response[resp_len] = '\0';

    /* Parse vault status from response lines:
     * "onvaultd running, N vault(s)\n"
     * "  <id> (<source>) [mounted|locked]\n" */
    g_menu_vault_count = 0;
    char *line = strtok(response, "\n");
    while (line != NULL && g_menu_vault_count < MAX_MENU_VAULTS) {
        /* Skip header line */
        if (strstr(line, "vault(s)") != NULL) {
            line = strtok(NULL, "\n");
            continue;
        }
        /* Parse vault lines: "  ssh (/Users/x/.ssh) [mounted]" */
        char vid[64], source[PATH_MAX], status_str[32];
        if (sscanf(line, "  %63s (%[^)]) [%31[^]]", vid, source, status_str) == 3) {
            menu_vault_info_t *v = &g_menu_vaults[g_menu_vault_count];
            strlcpy(v->vault_id, vid, sizeof(v->vault_id));
            strlcpy(v->source_path, source, sizeof(v->source_path));
            v->is_mounted = (strcmp(status_str, "mounted") == 0) ? 1 : 0;
            g_menu_vault_count++;
        }
        line = strtok(NULL, "\n");
    }

    /* Detect lock state: if daemon responds to STATUS, it's running.
     * If any vault exists, the daemon has been unlocked at some point. */
    int daemon_unlocked = (g_menu_vault_count > 0) ? 1 : 0;
    /* Also check: if the response starts with "onvaultd running", we're connected */
    if (rc == ONVAULT_OK)
        daemon_unlocked = 1;

    dispatch_async(dispatch_get_main_queue(), ^{
        self.vaultCount = g_menu_vault_count;
        /* Update lock state based on daemon connectivity */
        if (daemon_unlocked && self.isLocked) {
            self.isLocked = NO;
            self.statusItem.button.title = @"\U0001F513";
        }
        [self rebuildMenu];
    });
}

- (void)rebuildMenu {
    NSMenu *menu = [[NSMenu alloc] init];

    /* ── Status header ── */
    NSString *status = self.isLocked
        ? @"● Locked"
        : [NSString stringWithFormat:@"● %d vault(s) active", self.vaultCount];
    NSMenuItem *statusItem = [menu addItemWithTitle:status action:nil keyEquivalent:@""];
    [statusItem setEnabled:NO];
    [menu addItem:[NSMenuItem separatorItem]];

    /* ── Per-vault section ── */
    if (g_menu_vault_count > 0) {
        NSMenuItem *vaultHeader = [menu addItemWithTitle:@"Vaults" action:nil keyEquivalent:@""];
        [vaultHeader setEnabled:NO];

        for (int i = 0; i < g_menu_vault_count; i++) {
            menu_vault_info_t *v = &g_menu_vaults[i];
            NSString *icon = v->is_mounted ? @"\U0001F513" : @"\U0001F512";
            NSString *label = [NSString stringWithFormat:@"  %@ %s  (%s)",
                               icon, v->vault_id, v->source_path];
            NSMenuItem *item = [[NSMenuItem alloc]
                initWithTitle:label action:nil keyEquivalent:@""];

            /* Per-vault submenu */
            NSMenu *subMenu = [[NSMenu alloc] init];
            NSString *vid = [NSString stringWithUTF8String:v->vault_id];

            /* Info */
            NSString *statusLine = [NSString stringWithFormat:@"Status: %s",
                                    v->is_mounted ? "Mounted (accessible)" : "Locked (encrypted)"];
            NSMenuItem *si = [subMenu addItemWithTitle:statusLine action:nil keyEquivalent:@""];
            [si setEnabled:NO];
            [subMenu addItem:[NSMenuItem separatorItem]];

            /* View Rules */
            NSMenuItem *rulesItem = [[NSMenuItem alloc]
                initWithTitle:@"View Access Rules"
                action:@selector(viewRulesForVault:) keyEquivalent:@""];
            rulesItem.target = self;
            rulesItem.representedObject = vid;
            [subMenu addItem:rulesItem];

            /* Allow Process... */
            NSMenuItem *allowItem = [[NSMenuItem alloc]
                initWithTitle:@"Allow Process..."
                action:@selector(allowProcessForVault:) keyEquivalent:@""];
            allowItem.target = self;
            allowItem.representedObject = vid;
            [subMenu addItem:allowItem];

            /* Deny Process... */
            NSMenuItem *denyItem = [[NSMenuItem alloc]
                initWithTitle:@"Deny Process..."
                action:@selector(denyProcessForVault:) keyEquivalent:@""];
            denyItem.target = self;
            denyItem.representedObject = vid;
            [subMenu addItem:denyItem];

            [subMenu addItem:[NSMenuItem separatorItem]];

            /* Remove Vault */
            NSMenuItem *removeItem = [[NSMenuItem alloc]
                initWithTitle:@"Remove Vault..."
                action:@selector(removeVault:) keyEquivalent:@""];
            removeItem.target = self;
            removeItem.representedObject = vid;
            [subMenu addItem:removeItem];

            [item setSubmenu:subMenu];
            [menu addItem:item];
        }
        [menu addItem:[NSMenuItem separatorItem]];
    } else if (!self.isLocked) {
        NSMenuItem *noVaults = [menu addItemWithTitle:@"No vaults configured" action:nil keyEquivalent:@""];
        [noVaults setEnabled:NO];
        [menu addItem:[NSMenuItem separatorItem]];
    }

    /* ── Vault management ── */
    NSMenuItem *addVaultItem = [[NSMenuItem alloc]
        initWithTitle:@"Add Vault..." action:@selector(addVaultAction:) keyEquivalent:@"a"];
    addVaultItem.target = self;
    [menu addItem:addVaultItem];

    [menu addItem:[NSMenuItem separatorItem]];

    /* ── Recent denials section ── */
    pthread_mutex_lock(&g_denial_lock);
    int denial_snapshot = g_denial_count;
    if (denial_snapshot > 0) {
        NSString *denialTitle = [NSString stringWithFormat:@"Recent Denials (%d)", denial_snapshot];
        NSMenuItem *denialHeader = [menu addItemWithTitle:denialTitle action:nil keyEquivalent:@""];
        [denialHeader setEnabled:NO];

        int show_count = denial_snapshot < 5 ? denial_snapshot : 5;
        for (int i = denial_snapshot - 1; i >= denial_snapshot - show_count; i--) {
            recent_denial_t *d = &g_recent_denials[i];

            time_t now = time(NULL);
            int secs = (int)(now - d->timestamp);
            NSString *timeAgo;
            if (secs < 60) timeAgo = [NSString stringWithFormat:@"%ds ago", secs];
            else if (secs < 3600) timeAgo = [NSString stringWithFormat:@"%dm ago", secs / 60];
            else timeAgo = [NSString stringWithFormat:@"%dh ago", secs / 3600];

            NSString *label = [NSString stringWithFormat:@"  %s → %s  %@",
                               d->process_name, d->vault_id, timeAgo];
            NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:label action:nil keyEquivalent:@""];

            NSMenu *subMenu = [[NSMenu alloc] init];

            NSString *procLine = [NSString stringWithFormat:@"Process: %s", d->process_path];
            NSMenuItem *pi = [subMenu addItemWithTitle:procLine action:nil keyEquivalent:@""];
            [pi setEnabled:NO];

            NSString *fileLine = [NSString stringWithFormat:@"File: %s", d->file_path];
            NSMenuItem *fi = [subMenu addItemWithTitle:fileLine action:nil keyEquivalent:@""];
            [fi setEnabled:NO];

            [subMenu addItem:[NSMenuItem separatorItem]];

            NSMenuItem *allowBtn = [[NSMenuItem alloc]
                initWithTitle:@"Allow Always" action:@selector(allowFromDenial:) keyEquivalent:@""];
            allowBtn.target = self;
            allowBtn.representedObject = @{
                @"process_path": [NSString stringWithUTF8String:d->process_path],
                @"vault_id": [NSString stringWithUTF8String:d->vault_id]
            };
            [subMenu addItem:allowBtn];

            [item setSubmenu:subMenu];
            [menu addItem:item];
        }
        [menu addItem:[NSMenuItem separatorItem]];
    }
    pthread_mutex_unlock(&g_denial_lock);

    /* ── View Logs ── */
    NSMenuItem *logsItem = [[NSMenuItem alloc]
        initWithTitle:@"View Audit Log" action:@selector(viewLogsAction:) keyEquivalent:@""];
    logsItem.target = self;
    [menu addItem:logsItem];

    NSMenuItem *deniedLogsItem = [[NSMenuItem alloc]
        initWithTitle:@"View Denied Access Log" action:@selector(viewDeniedLogsAction:) keyEquivalent:@""];
    deniedLogsItem.target = self;
    [menu addItem:deniedLogsItem];

    /* ── View All Policies ── */
    NSMenuItem *policyItem = [[NSMenuItem alloc]
        initWithTitle:@"View All Policies" action:@selector(viewPoliciesAction:) keyEquivalent:@""];
    policyItem.target = self;
    [menu addItem:policyItem];

    [menu addItem:[NSMenuItem separatorItem]];

    /* ── Lock / Unlock ── */
    if (self.isLocked) {
        NSMenuItem *unlockItem = [[NSMenuItem alloc]
            initWithTitle:@"Unlock All" action:@selector(unlockAction:) keyEquivalent:@"u"];
        unlockItem.target = self;
        [menu addItem:unlockItem];
    } else {
        NSMenuItem *lockItem = [[NSMenuItem alloc]
            initWithTitle:@"Lock All" action:@selector(lockAction:) keyEquivalent:@"l"];
        lockItem.target = self;
        [menu addItem:lockItem];
    }

    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *quitItem = [[NSMenuItem alloc]
        initWithTitle:@"Quit onvault" action:@selector(quitAction:) keyEquivalent:@"q"];
    quitItem.target = self;
    [menu addItem:quitItem];

    /* Don't assign menu to statusItem — we use the popover on click instead.
     * The NSMenu is kept as a fallback if popover isn't available. */
    (void)menu;
}

/* --- Actions --- */

- (NSString *)promptForPassphrase:(NSString *)message {
    [NSApp activateIgnoringOtherApps:YES];
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = message;
    alert.informativeText = @"Enter your onvault passphrase to continue.";
    [alert addButtonWithTitle:@"OK"];
    [alert addButtonWithTitle:@"Cancel"];

    NSSecureTextField *input = [[NSSecureTextField alloc]
        initWithFrame:NSMakeRect(0, 0, 300, 24)];
    alert.accessoryView = input;
    [alert.window setInitialFirstResponder:input];

    if ([alert runModal] != NSAlertFirstButtonReturn)
        return nil;
    return input.stringValue;
}

/* Helper: request challenge nonce from daemon and compute proof */
- (BOOL)computeProofForPassphrase:(NSString *)passphrase proof:(uint8_t *)proof_out {
    /* Step 1: Get challenge nonce */
    uint8_t nonce[ONVAULT_HASH_SIZE];
    uint32_t nonce_len = sizeof(nonce);
    int rc = onvault_ipc_send(IPC_CMD_AUTH_CHALLENGE, NULL, 0,
                               nonce, &nonce_len);
    if (rc != ONVAULT_OK || nonce_len != ONVAULT_HASH_SIZE)
        return NO;

    /* Step 2: Compute proof = SHA-256(derived_key || nonce) */
    const char *pass = [passphrase UTF8String];
    onvault_crypto_init();
    int auth_rc = onvault_auth_compute_proof(pass, nonce, nonce_len, proof_out);
    onvault_memzero(nonce, sizeof(nonce));
    return (auth_rc == ONVAULT_OK) ? YES : NO;
}

- (void)lockAction:(id)sender {
    (void)sender;

    NSString *passphrase = [self promptForPassphrase:@"Lock All Vaults"];
    if (!passphrase) return;

    uint8_t proof[ONVAULT_HASH_SIZE];
    if (![self computeProofForPassphrase:passphrase proof:proof]) {
        NSAlert *err = [[NSAlert alloc] init];
        err.messageText = @"Authentication Failed";
        err.informativeText = @"Could not verify passphrase.";
        err.alertStyle = NSAlertStyleWarning;
        [err addButtonWithTitle:@"OK"];
        [err runModal];
        return;
    }

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_LOCK, proof, ONVAULT_HASH_SIZE,
                               response, &resp_len);
    onvault_memzero(proof, sizeof(proof));

    if (rc != ONVAULT_OK) {
        NSAlert *err = [[NSAlert alloc] init];
        err.messageText = @"Lock Failed";
        err.informativeText = @"Wrong passphrase or daemon error.";
        err.alertStyle = NSAlertStyleWarning;
        [err addButtonWithTitle:@"OK"];
        [err runModal];
        return;
    }

    self.isLocked = YES;
    self.statusItem.button.title = @"\U0001F512";
    [self rebuildMenu];
}

- (void)unlockAction:(id)sender {
    (void)sender;

    /* Require passphrase for unlock */
    NSString *passphrase = [self promptForPassphrase:@"Unlock All Vaults"];
    if (!passphrase) return;

    /* Verify passphrase locally, then unlock via CLI path
     * (passphrase → Argon2id → verify against stored key → create session → notify daemon) */
    const char *pass = [passphrase UTF8String];
    onvault_crypto_init();
    onvault_key_t master_key;
    int auth_rc = onvault_auth_unlock(pass, &master_key);
    onvault_key_wipe(&master_key, sizeof(master_key));

    if (auth_rc != ONVAULT_OK) {
        NSAlert *err = [[NSAlert alloc] init];
        err.messageText = @"Unlock Failed";
        err.informativeText = (auth_rc == ONVAULT_ERR_AUTH)
            ? @"Wrong passphrase."
            : @"Authentication error.";
        err.alertStyle = NSAlertStyleWarning;
        [err addButtonWithTitle:@"OK"];
        [err runModal];
        return;
    }

    /* Notify daemon to load master key from session */
    onvault_ipc_send(IPC_CMD_UNLOCK, NULL, 0, NULL, NULL);
    self.isLocked = NO;
    self.statusItem.button.title = @"\U0001F513";
    [self rebuildMenu];
}

- (void)quitAction:(id)sender {
    (void)sender;
    [[NSApplication sharedApplication] terminate:nil];
}

- (void)addVaultAction:(id)sender {
    (void)sender;

    /* Require passphrase for adding vaults */
    NSString *passphrase = [self promptForPassphrase:@"Add Vault"];
    if (!passphrase) return;

    int verify_rc = onvault_auth_verify_passphrase([passphrase UTF8String]);
    if (verify_rc != ONVAULT_OK) {
        NSAlert *err = [[NSAlert alloc] init];
        err.messageText = @"Authentication Failed";
        err.informativeText = @"Wrong passphrase.";
        err.alertStyle = NSAlertStyleWarning;
        [err addButtonWithTitle:@"OK"];
        [err runModal];
        return;
    }

    /* Bring app to front for the file dialog */
    [NSApp activateIgnoringOtherApps:YES];

    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.canChooseFiles = NO;
    panel.canChooseDirectories = YES;
    panel.allowsMultipleSelection = NO;
    panel.message = @"Select a directory to protect with onvault";
    panel.prompt = @"Protect";

    if ([panel runModal] == NSModalResponseOK) {
        NSURL *url = panel.URL;
        if (url) {
            const char *path = [url.path UTF8String];
            /* Payload: flags(1) + path — menu bar adds with smart defaults */
            size_t pathlen = strlen(path) + 1;
            char add_payload[1 + PATH_MAX];
            add_payload[0] = 1; /* smart defaults on from GUI */
            memcpy(add_payload + 1, path, pathlen);

            char response[ONVAULT_IPC_MAX_MSG];
            uint32_t resp_len = sizeof(response) - 1;
            int rc = onvault_ipc_send(IPC_CMD_VAULT_ADD,
                                       add_payload, (uint32_t)(1 + pathlen),
                                       response, &resp_len);
            response[resp_len] = '\0';

            NSAlert *alert = [[NSAlert alloc] init];
            if (rc == ONVAULT_OK) {
                alert.messageText = @"Vault Added";
                alert.informativeText = [NSString stringWithUTF8String:response];
            } else {
                alert.messageText = @"Failed to Add Vault";
                alert.informativeText = resp_len > 0
                    ? [NSString stringWithUTF8String:response]
                    : @"Unknown error. Make sure the daemon is unlocked.";
                alert.alertStyle = NSAlertStyleWarning;
            }
            [alert addButtonWithTitle:@"OK"];
            [alert runModal];

            /* Refresh vault list */
            [self refreshVaultStatus];
        }
    }
}

- (void)removeVault:(NSMenuItem *)sender {
    NSString *vaultId = sender.representedObject;

    /* Require passphrase for vault removal */
    NSString *passphrase = [self promptForPassphrase:
        [NSString stringWithFormat:@"Remove vault \"%@\"?", vaultId]];
    if (!passphrase) return;

    uint8_t proof[ONVAULT_HASH_SIZE];
    if (![self computeProofForPassphrase:passphrase proof:proof]) {
        NSAlert *err = [[NSAlert alloc] init];
        err.messageText = @"Authentication Failed";
        err.alertStyle = NSAlertStyleWarning;
        [err addButtonWithTitle:@"OK"];
        [err runModal];
        return;
    }

    const char *vid = [vaultId UTF8String];
    size_t vid_len = strlen(vid) + 1;
    char payload[ONVAULT_HASH_SIZE + PATH_MAX];
    memcpy(payload, proof, ONVAULT_HASH_SIZE);
    memcpy(payload + ONVAULT_HASH_SIZE, vid, vid_len);
    onvault_memzero(proof, sizeof(proof));

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_VAULT_REMOVE,
                               payload, (uint32_t)(ONVAULT_HASH_SIZE + vid_len),
                               response, &resp_len);
    response[resp_len] = '\0';

    NSAlert *alert = [[NSAlert alloc] init];
    if (rc == ONVAULT_OK) {
        alert.messageText = @"Vault Removed";
        alert.informativeText = [NSString stringWithUTF8String:response];
    } else {
        alert.messageText = @"Failed to Remove Vault";
        alert.informativeText = resp_len > 0
            ? [NSString stringWithUTF8String:response]
            : @"Unknown error.";
        alert.alertStyle = NSAlertStyleWarning;
    }
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];

    /* Refresh vault list */
    [self refreshVaultStatus];
}

/* Prompt for a process path using an input dialog */
- (NSString *)promptForInput:(NSString *)title message:(NSString *)message placeholder:(NSString *)placeholder {
    [NSApp activateIgnoringOtherApps:YES];
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = title;
    alert.informativeText = message;
    [alert addButtonWithTitle:@"OK"];
    [alert addButtonWithTitle:@"Cancel"];

    NSTextField *input = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 400, 24)];
    input.placeholderString = placeholder;
    alert.accessoryView = input;
    [alert.window setInitialFirstResponder:input];

    if ([alert runModal] != NSAlertFirstButtonReturn)
        return nil;
    NSString *val = input.stringValue;
    return (val.length > 0) ? val : nil;
}

- (void)allowProcessForVault:(NSMenuItem *)sender {
    NSString *vaultId = sender.representedObject;

    NSString *passphrase = [self promptForPassphrase:@"Allow Process"];
    if (!passphrase) return;
    uint8_t proof[ONVAULT_HASH_SIZE];
    if (![self computeProofForPassphrase:passphrase proof:proof]) {
        NSAlert *err = [[NSAlert alloc] init];
        err.messageText = @"Authentication Failed";
        err.alertStyle = NSAlertStyleWarning;
        [err addButtonWithTitle:@"OK"];
        [err runModal];
        return;
    }

    NSString *procPath = [self promptForInput:@"Allow Process"
        message:[NSString stringWithFormat:@"Enter the full path of the process to allow for vault \"%@\":", vaultId]
        placeholder:@"/usr/bin/vim"];
    if (!procPath) return;

    const char *proc = [procPath UTF8String];
    const char *vid = [vaultId UTF8String];
    size_t plen = strlen(proc);
    size_t vlen = strlen(vid);
    char payload[ONVAULT_HASH_SIZE + PATH_MAX + 64];
    size_t payload_len = ONVAULT_HASH_SIZE + plen + 1 + vlen + 1;
    if (payload_len > sizeof(payload)) {
        onvault_memzero(proof, sizeof(proof));
        NSAlert *err = [[NSAlert alloc] init];
        err.messageText = @"Path too long";
        err.alertStyle = NSAlertStyleWarning;
        [err addButtonWithTitle:@"OK"];
        [err runModal];
        return;
    }
    memcpy(payload, proof, ONVAULT_HASH_SIZE);
    memcpy(payload + ONVAULT_HASH_SIZE, proc, plen + 1);
    memcpy(payload + ONVAULT_HASH_SIZE + plen + 1, vid, vlen + 1);

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_ALLOW, payload, (uint32_t)payload_len,
                               response, &resp_len);
    onvault_memzero(proof, sizeof(proof));
    response[resp_len] = '\0';

    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = (rc == ONVAULT_OK) ? @"Process Allowed" : @"Failed";
    alert.informativeText = resp_len > 0 ? [NSString stringWithUTF8String:response] : @"";
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
}

- (void)denyProcessForVault:(NSMenuItem *)sender {
    NSString *vaultId = sender.representedObject;

    NSString *passphrase = [self promptForPassphrase:@"Deny Process"];
    if (!passphrase) return;
    uint8_t proof[ONVAULT_HASH_SIZE];
    if (![self computeProofForPassphrase:passphrase proof:proof]) {
        NSAlert *err = [[NSAlert alloc] init];
        err.messageText = @"Authentication Failed";
        err.alertStyle = NSAlertStyleWarning;
        [err addButtonWithTitle:@"OK"];
        [err runModal];
        return;
    }

    NSString *procPath = [self promptForInput:@"Deny Process"
        message:[NSString stringWithFormat:@"Enter the full path of the process to deny for vault \"%@\":", vaultId]
        placeholder:@"/usr/bin/python3"];
    if (!procPath) return;

    const char *proc = [procPath UTF8String];
    const char *vid = [vaultId UTF8String];
    size_t plen = strlen(proc);
    size_t vlen = strlen(vid);
    char payload[ONVAULT_HASH_SIZE + PATH_MAX + 64];
    size_t payload_len = ONVAULT_HASH_SIZE + plen + 1 + vlen + 1;
    if (payload_len > sizeof(payload)) {
        onvault_memzero(proof, sizeof(proof));
        NSAlert *err = [[NSAlert alloc] init];
        err.messageText = @"Path too long";
        err.alertStyle = NSAlertStyleWarning;
        [err addButtonWithTitle:@"OK"];
        [err runModal];
        return;
    }
    memcpy(payload, proof, ONVAULT_HASH_SIZE);
    memcpy(payload + ONVAULT_HASH_SIZE, proc, plen + 1);
    memcpy(payload + ONVAULT_HASH_SIZE + plen + 1, vid, vlen + 1);

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_DENY, payload, (uint32_t)payload_len,
                               response, &resp_len);
    onvault_memzero(proof, sizeof(proof));
    response[resp_len] = '\0';

    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = (rc == ONVAULT_OK) ? @"Process Denied" : @"Failed";
    alert.informativeText = resp_len > 0 ? [NSString stringWithUTF8String:response] : @"";
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
}

- (void)viewLogsAction:(id)sender {
    (void)sender;
    char payload[1] = {0}; /* denied_only = false */
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_LOG, payload, 1, response, &resp_len);
    response[resp_len] = '\0';

    [NSApp activateIgnoringOtherApps:YES];
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Audit Log";
    if (rc != ONVAULT_OK || resp_len == 0)
        alert.informativeText = @"No log entries (or daemon not unlocked).";
    else
        alert.informativeText = [NSString stringWithUTF8String:response];
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
}

- (void)viewDeniedLogsAction:(id)sender {
    (void)sender;
    char payload[1] = {1}; /* denied_only = true */
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_LOG, payload, 1, response, &resp_len);
    response[resp_len] = '\0';

    [NSApp activateIgnoringOtherApps:YES];
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Denied Access Log";
    if (rc != ONVAULT_OK || resp_len == 0)
        alert.informativeText = @"No denied access entries.";
    else
        alert.informativeText = [NSString stringWithUTF8String:response];
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
}

- (void)viewPoliciesAction:(id)sender {
    (void)sender;
    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_POLICY_SHOW, NULL, 0, response, &resp_len);
    response[resp_len] = '\0';

    [NSApp activateIgnoringOtherApps:YES];
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"All Policies";
    if (rc != ONVAULT_OK || resp_len == 0)
        alert.informativeText = @"No policies configured (or daemon not unlocked).";
    else
        alert.informativeText = [NSString stringWithUTF8String:response];
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
}

- (void)viewRulesForVault:(NSMenuItem *)sender {
    NSString *vaultId = sender.representedObject;
    const char *vid = [vaultId UTF8String];

    char response[ONVAULT_IPC_MAX_MSG];
    uint32_t resp_len = sizeof(response) - 1;
    int rc = onvault_ipc_send(IPC_CMD_RULES, vid, (uint32_t)strlen(vid) + 1,
                               response, &resp_len);
    if (rc != ONVAULT_OK) {
        response[0] = '\0';
        resp_len = 0;
    }
    response[resp_len] = '\0';

    /* Show in an alert */
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = [NSString stringWithFormat:@"Rules for %@", vaultId];
    alert.informativeText = resp_len > 0
        ? [NSString stringWithUTF8String:response]
        : @"No rules configured (all access denied by default)";
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
}

- (void)allowFromDenial:(NSMenuItem *)sender {
    NSDictionary *info = sender.representedObject;
    NSString *processPath = info[@"process_path"];
    NSString *vaultId = info[@"vault_id"];
    NSString *passphrase = [self promptForPassphrase:@"Allow Process"];
    if (!passphrase) return;
    uint8_t proof[ONVAULT_HASH_SIZE];
    if (![self computeProofForPassphrase:passphrase proof:proof])
        return;

    const char *proc = [processPath UTF8String];
    const char *vid = [vaultId UTF8String];
    size_t plen = strlen(proc);
    size_t vlen = strlen(vid);
    char payload[ONVAULT_HASH_SIZE + PATH_MAX + 64];
    size_t payload_len = ONVAULT_HASH_SIZE + plen + 1 + vlen + 1;
    if (payload_len > sizeof(payload)) {
        onvault_memzero(proof, sizeof(proof));
        return;
    }
    memcpy(payload, proof, ONVAULT_HASH_SIZE);
    memcpy(payload + ONVAULT_HASH_SIZE, proc, plen + 1);
    memcpy(payload + ONVAULT_HASH_SIZE + plen + 1, vid, vlen + 1);
    onvault_ipc_send(IPC_CMD_ALLOW,
                      payload, (uint32_t)payload_len,
                      NULL, NULL);
    onvault_memzero(proof, sizeof(proof));

    /* Remove this denial from the list */
    pthread_mutex_lock(&g_denial_lock);
    for (int i = 0; i < g_denial_count; i++) {
        if (strcmp(g_recent_denials[i].process_path, proc) == 0 &&
            strcmp(g_recent_denials[i].vault_id, vid) == 0) {
            for (int j = i; j < g_denial_count - 1; j++)
                g_recent_denials[j] = g_recent_denials[j + 1];
            g_denial_count--;
            break;
        }
    }
    pthread_mutex_unlock(&g_denial_lock);

    [self rebuildMenu];
}

/* Handle notification actions (Allow Once / Allow Always) */
- (void)userNotificationCenter:(UNUserNotificationCenter *)center
didReceiveNotificationResponse:(UNNotificationResponse *)response
         withCompletionHandler:(void (^)(void))completionHandler
{
    (void)center;
    NSDictionary *userInfo = response.notification.request.content.userInfo;
    NSString *processPath = userInfo[@"process_path"];
    NSString *vaultId = userInfo[@"vault_id"];

    if ([response.actionIdentifier isEqualToString:@"ALLOW_ONCE"]) {
        NSLog(@"onvault: allow once %@ for %@", processPath, vaultId);
        /* Allow Once: temporarily allow (logged but no persistent rule) */
    } else if ([response.actionIdentifier isEqualToString:@"ALLOW_ALWAYS"]) {
        NSLog(@"onvault: allow always %@ for %@", processPath, vaultId);
        /* Allow Always: add persistent allow rule via IPC */
        NSString *passphrase = [self promptForPassphrase:@"Allow Process"];
        if (!passphrase) {
            completionHandler();
            return;
        }
        uint8_t proof[ONVAULT_HASH_SIZE];
        if (![self computeProofForPassphrase:passphrase proof:proof]) {
            completionHandler();
            return;
        }
        const char *proc = [processPath UTF8String];
        const char *vid = [vaultId UTF8String];
        size_t plen = strlen(proc);
        size_t vlen = strlen(vid);
        char payload[ONVAULT_HASH_SIZE + PATH_MAX + 64];
        size_t payload_len = ONVAULT_HASH_SIZE + plen + 1 + vlen + 1;
        if (payload_len > sizeof(payload)) {
            onvault_memzero(proof, sizeof(proof));
            completionHandler();
            return;
        }
        memcpy(payload, proof, ONVAULT_HASH_SIZE);
        memcpy(payload + ONVAULT_HASH_SIZE, proc, plen + 1);
        memcpy(payload + ONVAULT_HASH_SIZE + plen + 1, vid, vlen + 1);
        onvault_ipc_send(IPC_CMD_ALLOW,
                          payload, (uint32_t)payload_len,
                          NULL, NULL);
        onvault_memzero(proof, sizeof(proof));
    }

    completionHandler();
}

/* Show notifications when app is in foreground */
- (void)userNotificationCenter:(UNUserNotificationCenter *)center
       willPresentNotification:(UNNotification *)notification
         withCompletionHandler:(void (^)(UNNotificationPresentationOptions))completionHandler
{
    (void)center;
    (void)notification;
    completionHandler(UNNotificationPresentationOptionBanner |
                      UNNotificationPresentationOptionSound);
}

@end

/* --- Global state --- */

static OnVaultMenuBarDelegate *g_delegate = nil;

/* --- Public C API --- */

int onvault_menubar_init(void)
{
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

        g_delegate = [[OnVaultMenuBarDelegate alloc] init];
        g_delegate.isLocked = YES;
        g_delegate.vaultCount = 0;

        [NSApp setDelegate:g_delegate];
        [NSApp run]; /* This blocks — runs the event loop */
    }
    return 0;
}

void onvault_menubar_set_locked(int locked)
{
    if (!g_delegate) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        g_delegate.isLocked = locked ? YES : NO;
        g_delegate.statusItem.button.title = locked ? @"🔒" : @"🔓";
        [g_delegate rebuildMenu];
    });
}

void onvault_menubar_set_vault_count(int count)
{
    if (!g_delegate) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        g_delegate.vaultCount = count;
        [g_delegate rebuildMenu];
    });
}

void onvault_menubar_notify_deny(const char *process_name,
                                   const char *process_path,
                                   const char *file_path,
                                   const char *vault_id)
{
    /* Track denial in recent list */
    pthread_mutex_lock(&g_denial_lock);
    if (g_denial_count >= MAX_RECENT_DENIALS) {
        /* Shift out oldest */
        memmove(&g_recent_denials[0], &g_recent_denials[1],
                (MAX_RECENT_DENIALS - 1) * sizeof(recent_denial_t));
        g_denial_count = MAX_RECENT_DENIALS - 1;
    }
    recent_denial_t *d = &g_recent_denials[g_denial_count];
    memset(d, 0, sizeof(*d));
    strlcpy(d->process_name, process_name ?: "unknown", sizeof(d->process_name));
    strlcpy(d->process_path, process_path ?: process_name ?: "unknown", sizeof(d->process_path));
    strlcpy(d->file_path, file_path ?: "unknown", sizeof(d->file_path));
    strlcpy(d->vault_id, vault_id ?: "unknown", sizeof(d->vault_id));
    d->timestamp = time(NULL);
    g_denial_count++;
    pthread_mutex_unlock(&g_denial_lock);

    /* Rebuild menu to show new denial */
    if (g_delegate) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [g_delegate rebuildMenu];
        });
    }

    /* Notifications require a bundled app; skip if not available */
    if ([[NSBundle mainBundle] bundleIdentifier] == nil)
        return;

    NSString *proc = [NSString stringWithUTF8String:process_name ?: "unknown"];
    NSString *procFullPath = [NSString stringWithUTF8String:process_path ?: process_name ?: "unknown"];
    NSString *fpath = [NSString stringWithUTF8String:file_path ?: "unknown"];
    NSString *vid = [NSString stringWithUTF8String:vault_id ?: "unknown"];

    UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
    content.title = @"onvault: Access Denied";
    content.body = [NSString stringWithFormat:@"%@ tried to access %@", proc, fpath];
    content.sound = [UNNotificationSound defaultSound];
    content.categoryIdentifier = @"DENY";
    content.userInfo = @{
        @"process_path": procFullPath,
        @"file_path": fpath,
        @"vault_id": vid,
    };

    UNNotificationRequest *request = [UNNotificationRequest
        requestWithIdentifier:[[NSUUID UUID] UUIDString]
        content:content
        trigger:nil];

    [[UNUserNotificationCenter currentNotificationCenter]
        addNotificationRequest:request
        withCompletionHandler:^(NSError *error) {
            if (error)
                NSLog(@"onvault: notification error: %@", error);
        }];
}

void onvault_menubar_stop(void)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_delegate.statusItem) {
            [[NSStatusBar systemStatusBar] removeStatusItem:g_delegate.statusItem];
            g_delegate.statusItem = nil;
        }
        [[NSApplication sharedApplication] terminate:nil];
    });
}

/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * menubar.m — Menu bar status item and notifications
 *
 * Uses Objective-C for NSStatusItem, NSMenu, and UNUserNotificationCenter.
 */

#import <Cocoa/Cocoa.h>
#import <UserNotifications/UserNotifications.h>
#include "menubar.h"

/* --- Menu bar delegate --- */

@interface OnVaultMenuBarDelegate : NSObject <NSApplicationDelegate, UNUserNotificationCenterDelegate>
@property (strong, nonatomic) NSStatusItem *statusItem;
@property (assign, nonatomic) int vaultCount;
@property (assign, nonatomic) BOOL isLocked;
@end

@implementation OnVaultMenuBarDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;

    /* Create status item */
    self.statusItem = [[NSStatusBar systemStatusBar]
                        statusItemWithLength:NSVariableStatusItemLength];
    self.statusItem.button.title = @"🔒";

    /* Build menu */
    [self rebuildMenu];

    /* Request notification permission */
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

- (void)rebuildMenu {
    NSMenu *menu = [[NSMenu alloc] init];

    NSString *status = self.isLocked
        ? @"● Locked"
        : [NSString stringWithFormat:@"● %d vault(s) unlocked", self.vaultCount];

    [menu addItemWithTitle:status action:nil keyEquivalent:@""];
    [menu addItem:[NSMenuItem separatorItem]];

    if (self.isLocked) {
        [menu addItemWithTitle:@"Unlock All"
                        action:@selector(unlockAction:)
                 keyEquivalent:@"u"];
    } else {
        [menu addItemWithTitle:@"Lock All"
                        action:@selector(lockAction:)
                 keyEquivalent:@"l"];
    }

    [menu addItem:[NSMenuItem separatorItem]];
    [menu addItemWithTitle:@"Quit onvault"
                    action:@selector(quitAction:)
             keyEquivalent:@"q"];

    for (NSMenuItem *item in menu.itemArray)
        item.target = self;

    self.statusItem.menu = menu;
}

- (void)lockAction:(id)sender {
    (void)sender;
    /* TODO: Send IPC_CMD_LOCK to daemon */
    NSLog(@"onvault: lock requested");
}

- (void)unlockAction:(id)sender {
    (void)sender;
    /* TODO: Trigger unlock flow */
    NSLog(@"onvault: unlock requested");
}

- (void)quitAction:(id)sender {
    (void)sender;
    [[NSApplication sharedApplication] terminate:nil];
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
        /* TODO: Send temporary allow via IPC */
    } else if ([response.actionIdentifier isEqualToString:@"ALLOW_ALWAYS"]) {
        NSLog(@"onvault: allow always %@ for %@", processPath, vaultId);
        /* TODO: Send permanent allow via IPC */
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
                                   const char *file_path,
                                   const char *vault_id)
{
    NSString *proc = [NSString stringWithUTF8String:process_name ?: "unknown"];
    NSString *fpath = [NSString stringWithUTF8String:file_path ?: "unknown"];
    NSString *vid = [NSString stringWithUTF8String:vault_id ?: "unknown"];

    UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
    content.title = @"onvault: Access Denied";
    content.body = [NSString stringWithFormat:@"%@ tried to access %@", proc, fpath];
    content.sound = [UNNotificationSound defaultSound];
    content.categoryIdentifier = @"DENY";
    content.userInfo = @{
        @"process_path": proc,
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

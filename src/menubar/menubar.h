/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * menubar.h — Menu bar status item (C + Obj-C runtime)
 */

#ifndef ONVAULT_MENUBAR_H
#define ONVAULT_MENUBAR_H

/*
 * Initialize and show the menu bar status item.
 * Must be called from the main thread.
 * This starts the NSApplication run loop.
 */
int onvault_menubar_init(void);

/*
 * Update the menu bar icon state.
 * locked: 1 = locked (red), 0 = unlocked (green)
 */
void onvault_menubar_set_locked(int locked);

/*
 * Update vault count in the menu bar.
 */
void onvault_menubar_set_vault_count(int count);

/*
 * Show a denial notification.
 */
void onvault_menubar_notify_deny(const char *process_name,
                                   const char *file_path,
                                   const char *vault_id);

/*
 * Stop the menu bar.
 */
void onvault_menubar_stop(void);

#endif /* ONVAULT_MENUBAR_H */

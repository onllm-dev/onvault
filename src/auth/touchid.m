/*
 * onvault — Seamless File Encryption & Access Control for macOS
 * touchid.m — Touch ID biometric authentication
 */

#import <LocalAuthentication/LocalAuthentication.h>
#include "touchid.h"
#include "../common/types.h"

int onvault_touchid_available(void)
{
    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;
    BOOL available = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                          error:&error];
    return available ? 1 : 0;
}

int onvault_touchid_authenticate(const char *reason)
{
    if (!reason)
        reason = "authenticate with onvault";

    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;

    if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                              error:&error]) {
        return ONVAULT_ERR_DENIED;
    }

    __block int result = ONVAULT_ERR_AUTH;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    NSString *reasonStr = [NSString stringWithUTF8String:reason];

    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:reasonStr
                      reply:^(BOOL success, NSError *evalError) {
        if (success) {
            result = ONVAULT_OK;
        } else {
            (void)evalError;
            result = ONVAULT_ERR_AUTH;
        }
        dispatch_semaphore_signal(sema);
    }];

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    return result;
}

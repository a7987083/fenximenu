#import <Foundation/Foundation.h>
#import "ZONUI.h"
#import "ZONActivation.h"
#import "ZONVerify.h"

static NSString * const kZONUDIDKey = @"zonoe.auth.udid";

static void ZONShowAuthorized(NSString *udid) {
    [ZONActivation fetchLegacyStatusForUDID:udid completion:^(NSDictionary *legacy) {
        [ZONVerify runWithUDID:udid completion:^(NSDictionary *verify) {
            NSMutableDictionary *all = [NSMutableDictionary dictionary];
            all[@"udid"] = udid ?: @"";
            all[@"legacy"] = legacy ?: @{};
            all[@"verify"] = verify ?: @{};
            all[@"notification_key"] = @"20260926";
            [[ZONUI shared] showInfo:all title:@"授权信息"];
        }];
    }];
}

__attribute__((constructor)) static void ZONStart(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        ZONUI *ui = [ZONUI shared];
        [ui installFloatingButton];
        ui.tapHandler = ^{
            NSString *saved = [NSUserDefaults.standardUserDefaults stringForKey:kZONUDIDKey];
            [ui requestUDID:saved completion:^(NSString *udid) {
                if (!udid) return;
                [NSUserDefaults.standardUserDefaults setObject:udid forKey:kZONUDIDKey];

                [ZONActivation fetchLegacyStatusForUDID:udid completion:^(NSDictionary *legacy) {
                    NSDictionary *dylibStatus = [legacy[@"legacy_dylib"] isKindOfClass:NSDictionary.class] ? legacy[@"legacy_dylib"] : nil;
                    NSInteger code = [dylibStatus[@"code"] integerValue];
                    if (code == 1) {
                        ZONShowAuthorized(udid);
                        return;
                    }

                    [ui requestCardWithCompletion:^(NSString *card) {
                        if (!card) return;
                        [ZONActivation activateUDID:udid card:card completion:^(BOOL ok, NSString *message, NSDictionary *raw) {
                            if (!ok) {
                                [ui showInfo:@{
                                    @"success": @NO,
                                    @"message": message ?: @"激活失败",
                                    @"raw": raw ?: @{}
                                } title:@"激活结果"];
                                return;
                            }
                            [ZONActivation fetchLegacyStatusForUDID:udid completion:^(__unused NSDictionary *status) {
                                ZONShowAuthorized(udid);
                            }];
                        }];
                    }];
                }];
            }];
        };
    });
}

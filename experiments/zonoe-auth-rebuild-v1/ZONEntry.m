#import <Foundation/Foundation.h>
#import "ZONUI.h"
#import "ZONActivation.h"
#import "ZONVerify.h"

static NSString * const kZONUDIDKey = @"zonoe.auth.udid";

static void ZONShowVerifyResult(NSString *udid, NSDictionary *verify) {
    NSMutableDictionary *display = [NSMutableDictionary dictionaryWithDictionary:verify ?: @{}];
    display[@"udid"] = udid ?: @"";
    display[@"notification_key"] = @"20260926";
    [[ZONUI shared] showInfo:display title:@"授权信息"];
}

static void ZONVerifyThenRoute(ZONUI *ui, NSString *udid) {
    [ZONVerify runWithUDID:udid completion:^(NSDictionary *verify) {
        BOOL allowed = [verify[@"allowed"] boolValue];
        if (allowed) {
            ZONShowVerifyResult(udid, verify);
            return;
        }

        if (![ZONActivation isConfigured]) {
            NSMutableDictionary *display = [NSMutableDictionary dictionaryWithDictionary:verify ?: @{}];
            display[@"udid"] = udid ?: @"";
            display[@"activation_api"] = @{
                @"configured": @NO,
                @"message": @"当前 API 包未定义卡密激活接口"
            };
            [ui showInfo:display title:@"验证结果"];
            return;
        }

        [ui requestCardWithCompletion:^(NSString *card) {
            if (!card.length) return;
            [ZONActivation activateUDID:udid card:card completion:^(BOOL ok, NSString *message, NSDictionary *raw) {
                if (!ok) {
                    NSMutableDictionary *display = [NSMutableDictionary dictionaryWithDictionary:raw ?: @{}];
                    if (!display[@"message"] && message.length) display[@"message"] = message;
                    [ui showInfo:display title:@"卡密激活"];
                    return;
                }
                [ZONVerify runWithUDID:udid completion:^(NSDictionary *verifyAfterActivation) {
                    ZONShowVerifyResult(udid, verifyAfterActivation);
                }];
            }];
        }];
    }];
}

__attribute__((constructor)) static void ZONStart(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        ZONUI *ui = [ZONUI shared];
        [ui installFloatingButton];
        __weak ZONUI *weakUI = ui;
        ui.tapHandler = ^{
            ZONUI *strongUI = weakUI;
            if (!strongUI) return;
            NSString *saved = [NSUserDefaults.standardUserDefaults stringForKey:kZONUDIDKey];
            if (saved.length > 0) {
                ZONVerifyThenRoute(strongUI, saved);
                return;
            }
            [strongUI requestUDID:nil completion:^(NSString *udid) {
                if (!udid.length) return;
                [NSUserDefaults.standardUserDefaults setObject:udid forKey:kZONUDIDKey];
                ZONVerifyThenRoute(strongUI, udid);
            }];
        };
    });
}

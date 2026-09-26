#import "ZONDylibConfig.h"
#import "ZONUDIDPrompt.m"

@interface H5GGCardAuthController : NSObject
@property(nonatomic,assign) BOOL busy;
- (NSString *)autoUDID;
- (UIViewController *)presenter;
- (void)checkLegacyAuthorizationForUDID:(NSString *)udid activationSuccessMessage:(NSString *)message;
@end

@interface H5GGCardAuthController (ZONV6UDID)
@end

@implementation H5GGCardAuthController (ZONV6UDID)

- (void)floatTapped:(id)sender
{
    (void)sender;
    if (self.busy) return;

    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSString *saved = [defaults stringForKey:@"ZONUDID"];
    if (saved.length > 8) {
        [self checkLegacyAuthorizationForUDID:saved activationSuccessMessage:nil];
        return;
    }

    NSString *prefill = [self autoUDID];
    __weak typeof(self) weakSelf = self;
    [ZONUDIDPrompt presentFrom:[self presenter] prefilled:prefill completion:^(NSString *udid) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self || udid.length <= 8) return;
        [defaults setObject:udid forKey:@"ZONUDID"];
        [self checkLegacyAuthorizationForUDID:udid activationSuccessMessage:nil];
    }];
}

@end

@implementation ZONDylibConfig

+ (ZONDylibVerifyConfiguration *)configurationWithUDIDProvider:(ZONDylibUDIDProvider)udidProvider
{
    ZONDylibVerifyConfiguration *cfg = [ZONDylibVerifyConfiguration new];
    cfg.bootstrapURLs = @[
        [NSURL URLWithString:@"https://raw.githubusercontent.com/a7987083/zonoemenu-config/main/bootstrap/zonoe.main.json"],
        [NSURL URLWithString:@"https://app3.zonoeios.xyz/index/dylib_verify/config?dylib_key=zonoe.main"]
    ];
    cfg.endpointURL = [NSURL URLWithString:@"https://app3.zonoeios.xyz/index/dylib_verify/verify"];
    cfg.dylibKey = @"zonoe.main";
    cfg.dylibVersion = @"1";
    cfg.dylibBuild = @"";
    cfg.verifySecret = @"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
    cfg.requestTimeout = 10.0;
    cfg.udidProvider = udidProvider;
    return cfg;
}

+ (NSDictionary<NSString *, id> *)metadata
{
    return @{
        @"dylib_id": @(5),
        @"dylib_key": @"zonoe.main",
        @"version_id": @(2),
        @"version_state": @"testing",
        @"runtime_config_version": @(3),
        @"default_fail_action": @"disable_feature",
        @"default_offline_grace": @(900)
    };
}

@end

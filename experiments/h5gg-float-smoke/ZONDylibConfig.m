#import "ZONDylibConfig.h"

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
    // Public branch intentionally keeps a fixed-length placeholder. The real
    // verification secret is injected into the delivery binary outside git.
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

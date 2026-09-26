#import "ZONDylibConfig.h"
@implementation ZONDylibConfig
+ (ZONDylibVerifyConfiguration *)configurationWithUDIDProvider:(ZONDylibUDIDProvider)udidProvider {
    ZONDylibVerifyConfiguration *cfg=[ZONDylibVerifyConfiguration new];
    cfg.bootstrapURLs=@[[NSURL URLWithString:@"https://raw.githubusercontent.com/a7987083/zonoemenu-config/main/bootstrap/zonoe.main.json"]];
    cfg.endpointURL=[NSURL URLWithString:@"https://app3.zonoeios.xyz/index/dylib_verify/verify"];
    cfg.dylibKey=@"zonoe.main"; cfg.dylibVersion=@"1"; cfg.dylibBuild=@"";
    cfg.verifySecret=@"ZON_VERIFY_SECRET_PLACEHOLDER_20260926_V2_______________________";
    cfg.requestTimeout=10.0; cfg.udidProvider=udidProvider; return cfg;
}
+ (NSDictionary<NSString *,id> *)metadata { return @{@"generator_version":@"2.2.0",@"dylib_id":@(5),@"dylib_key":@"zonoe.main",@"version_id":@(2),@"version_state":@"testing",@"runtime_config_version":@(3)}; }
@end

#import "ZONDylibConfig.h"
#import "ZONAPIEndpoints.h"
@implementation ZONDylibConfig
+ (NSString *)verifySecret { return @"ZON_VERIFY_SECRET_PLACEHOLDER_20260926_V2_______________________"; }
+ (ZONDylibVerifyConfiguration *)configurationWithUDIDProvider:(ZONDylibUDIDProvider)udidProvider {
    ZONDylibVerifyConfiguration *cfg=[ZONDylibVerifyConfiguration new];
    cfg.bootstrapURLs=@[[ZONAPIEndpoints runtimeConfigURLForDylibKey:@"zonoe.main"]];
    cfg.endpointURL=[ZONAPIEndpoints verifyURL];
    cfg.dylibKey=@"zonoe.main"; cfg.dylibVersion=@"1"; cfg.dylibBuild=@"";
    cfg.verifySecret=[self verifySecret];
    cfg.requestTimeout=10.0; cfg.udidProvider=udidProvider; return cfg;
}
+ (NSDictionary<NSString *,id> *)metadata { return @{@"generator_version":@"api-smoke-1",@"dylib_key":@"zonoe.main",@"protocol_version":@2,@"runtime_config_version":@3,@"api_base_url":@"https://app3.zonoeios.xyz"}; }
@end

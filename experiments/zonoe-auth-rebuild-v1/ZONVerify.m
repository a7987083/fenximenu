#import "ZONVerify.h"
#import "ZONDylibVerify.h"
#import "ZONDylibConfig.h"
@implementation ZONVerify
+ (void)runWithUDID:(NSString *)udid completion:(void (^)(NSDictionary *))completion {
    ZONDylibVerifyConfiguration *cfg=[ZONDylibConfig configurationWithUDIDProvider:^NSString *{ return udid; }];
    ZONDylibVerify *client=[[ZONDylibVerify alloc] initWithConfiguration:cfg];
    [client verifyWithCompletion:^(ZONDylibVerifyResult *r){
        NSMutableDictionary *d=[NSMutableDictionary dictionary];
        d[@"ok"]=@(r.isAllowed); d[@"code"]=r.code?:@""; d[@"action"]=r.action?:@""; d[@"message"]=r.message?:@"";
        d[@"access_level"]=r.accessLevel?:@""; d[@"permissions"]=r.permissions?:@{}; d[@"app_identity"]=r.appIdentity?:@{}; d[@"app_update"]=r.appUpdate?:@{};
        if(r.notice)d[@"notice"]=r.notice; d[@"protocol_version"]=@(r.protocolVersion); d[@"offline_grace_seconds"]=@(r.offlineGraceSeconds); d[@"server_time"]=@(r.serverTime); d[@"offline_cache"]=@(r.isOfflineCache);
        if(r.token.length)d[@"token"]=r.token;
        if(completion)completion(d.copy);
    }];
}
@end

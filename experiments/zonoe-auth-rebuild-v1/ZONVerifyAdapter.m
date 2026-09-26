#import "ZONVerifyAdapter.h"
#import "ZONDylibConfig.h"
#import "ZONDylibVerify.h"

@interface ZONVerifyAdapter ()
@property(nonatomic,strong) ZONDylibVerify *client;
@end

@implementation ZONVerifyAdapter
- (void)verifyUDID:(NSString *)udid
        completion:(void (^)(ZONDylibVerifyResult *result))completion {
    ZONDylibVerifyConfiguration *cfg = [ZONDylibConfig configurationWithUDIDProvider:^NSString *{
        return udid ?: @"";
    }];
    self.client = [[ZONDylibVerify alloc] initWithConfiguration:cfg];
    [self.client verifyWithCompletion:^(ZONDylibVerifyResult *result) {
        if (completion) completion(result);
    }];
}
@end

#import "ZONLicenseStatus.h"
#import "ZONAPIEndpoints.h"
#import "ZONNetwork.h"

@implementation ZONLicenseStatus
+ (void)fetchForUDID:(NSString *)udid completion:(void (^)(NSDictionary *, BOOL, NSError * _Nullable))completion {
    [ZONNetwork GET:[ZONAPIEndpoints apiFaceURLForUDID:udid] timeout:12 completion:^(NSDictionary *json, NSData *data, NSHTTPURLResponse *response, NSError *error) {
        NSDictionary *result=[json isKindOfClass:NSDictionary.class]?json:@{};
        if(!result.count && data.length){
            NSString *text=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]?:@"";
            result=text.length?@{@"message":text}:@{};
        }
        // API package does not define a client-side HMAC protocol for /apiface.
        // Preserve the server response exactly and do not infer validity locally.
        if(completion) completion(result,NO,error);
    }];
}
@end

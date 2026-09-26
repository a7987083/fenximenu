#import "ZONActivation.h"
#import "ZONNetwork.h"
@implementation ZONActivationResult @end
@implementation ZONActivation
+ (NSURL *)urlForUDID:(NSString *)udid card:(NSString *)card {
    NSURLComponents *c=[NSURLComponents componentsWithString:@"http://ios.zonoeios.xyz/appstore"];
    c.queryItems=@[[NSURLQueryItem queryItemWithName:@"udid" value:udid?:@""],[NSURLQueryItem queryItemWithName:@"code" value:card?:@""]];
    return c.URL;
}
+ (void)activateUDID:(NSString *)udid card:(NSString *)card completion:(void (^)(ZONActivationResult *))completion {
    [ZONNetwork GET:[self urlForUDID:udid card:card] timeout:12 completion:^(NSDictionary *json, NSData *data, NSHTTPURLResponse *response, NSError *error) {
        ZONActivationResult *r=[ZONActivationResult new];
        if(error){ r.success=NO; r.message=error.localizedDescription?:@"网络错误"; r.displayObject=@{ @"message":r.message }; if(completion)completion(r); return; }
        NSString *raw=data.length?[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]:@"";
        NSDictionary *d=[json isKindOfClass:NSDictionary.class]?json:@{};
        id msgObj=d[@"message"]?:d[@"msg"];
        NSString *msg=[msgObj isKindOfClass:NSString.class]?msgObj:(raw.length?raw:@"服务器未返回消息");
        BOOL success=NO;
        id ok=d[@"ok"];
        if([ok respondsToSelector:@selector(boolValue)]) success=[ok boolValue];
        else {
            NSString *code=[d[@"code"] isKindOfClass:NSString.class]?d[@"code"]:@"";
            if([code isEqualToString:@"ok"]||[code isEqualToString:@"success"]||[code isEqualToString:@"ok_testing"]||[code isEqualToString:@"ok_deprecated"]) success=YES;
            else if([msg containsString:@"解锁成功"]||[msg.lowercaseString isEqualToString:@"ok"]||[msg containsString:@"激活成功"]) success=YES;
        }
        r.success=success; r.message=msg?:@""; r.json=d;
        r.displayObject=d.count?d:(raw.length?raw:@{ @"message":r.message?:@"" });
        if(completion)completion(r);
    }];
}
@end

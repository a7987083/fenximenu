#import "ZONActivation.h"
#import "ZONNetwork.h"
#import "ZONStorage.h"
@implementation ZONActivation
+ (NSURL *)urlForUDID:(NSString *)udid card:(NSString *)card {
    NSURLComponents *c=[NSURLComponents componentsWithString:@"http://ios.zonoeios.xyz/appstore"];
    c.queryItems=@[
        [NSURLQueryItem queryItemWithName:@"udid" value:udid?:@""],
        [NSURLQueryItem queryItemWithName:@"code" value:card?:@""]
    ];
    return c.URL;
}
+ (void)activateUDID:(NSString *)udid card:(NSString *)card completion:(void (^)(BOOL, NSString *, NSDictionary * _Nullable))completion {
    [ZONNetwork GET:[self urlForUDID:udid card:card] timeout:12 completion:^(NSDictionary *json, NSData *data, NSHTTPURLResponse *response, NSError *error) {
        if(error){ if(completion)completion(NO,error.localizedDescription?:@"网络错误",@{@"message":error.localizedDescription?:@"网络错误"}); return; }
        NSString *rawText=data.length?[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]:@"";
        NSDictionary *d=[json isKindOfClass:NSDictionary.class]?json:@{};
        id msgObj=d[@"message"]?:d[@"msg"];
        NSString *msg=[msgObj isKindOfClass:NSString.class]?msgObj:(rawText.length?rawText:@"服务器未返回消息");
        BOOL success=NO; id ok=d[@"ok"];
        if([ok respondsToSelector:@selector(boolValue)]) success=[ok boolValue];
        else {
            NSString *code=[d[@"code"] isKindOfClass:NSString.class]?d[@"code"]:@"";
            if([code isEqualToString:@"ok"]||[code isEqualToString:@"success"]||[code isEqualToString:@"ok_testing"]||[code isEqualToString:@"ok_deprecated"]) success=YES;
            else if([msg containsString:@"解锁成功"]||[msg.lowercaseString isEqualToString:@"ok"]||[msg containsString:@"激活成功"]) success=YES;
        }
        NSDictionary *display=d.count?d:(rawText.length?@{@"message":msg?:@"",@"raw_text":rawText}:@{@"message":msg?:@""});
        if(success){
            [ZONStorage setCard:card];
            [ZONStorage setLastActivationObject:display];
            [ZONStorage setJustActivated:YES];
        }
        if(completion)completion(success,msg?:@"",display);
    }];
}
+ (void)fetchLegacyStatusForUDID:(NSString *)udid completion:(void (^)(NSDictionary *))completion {
    // Compatibility shim only: no Index::dylib / Index::apiface HTTP request is made.
    NSInteger code=[ZONStorage card].length?1:0;
    if(completion)completion(@{@"legacy_dylib":@{@"code":@(code)}});
}
@end

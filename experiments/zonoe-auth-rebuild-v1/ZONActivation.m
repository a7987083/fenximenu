#import "ZONActivation.h"
#import "ZONAPIEndpoints.h"
#import "ZONNetwork.h"
#import "ZONStorage.h"
@implementation ZONActivation
+ (BOOL)isConfigured { return YES; }
+ (void)activateUDID:(NSString *)udid card:(NSString *)card completion:(void (^)(BOOL, NSString *, NSDictionary * _Nullable))completion {
    NSURL *url=[ZONAPIEndpoints activationURLForUDID:udid card:card];
    [ZONNetwork GET:url timeout:12 completion:^(NSDictionary *json, NSData *data, NSHTTPURLResponse *response, NSError *error) {
        if(error){ NSString *m=error.localizedDescription?:@"网络错误"; if(completion)completion(NO,m,@{@"message":m}); return; }
        NSDictionary *d=[json isKindOfClass:NSDictionary.class]?json:@{};
        NSString *rawText=data.length?[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]:@"";
        id msgObj=d[@"message"]?:d[@"msg"];
        NSString *msg=[msgObj isKindOfClass:NSString.class]?msgObj:(rawText.length?rawText:@"");
        BOOL ok=NO;
        if([d[@"ok"] respondsToSelector:@selector(boolValue)]) {
            ok=[d[@"ok"] boolValue];
        } else {
            NSString *code=[d[@"code"] isKindOfClass:NSString.class]?[d[@"code"] lowercaseString]:@"";
            ok=[@[@"ok",@"success",@"activated",@"bound"] containsObject:code];
        }
        NSDictionary *display=d.count?d:(msg.length?@{@"message":msg}:@{});
        if(ok){
            [ZONStorage setUDID:udid];
            [ZONStorage setCard:card];
            [ZONStorage setLastActivationObject:display];
            [ZONStorage setJustActivated:YES];
        }
        if(completion)completion(ok,msg?:@"",display);
    }];
}
@end

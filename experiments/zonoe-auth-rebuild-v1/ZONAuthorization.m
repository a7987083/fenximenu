#import "ZONAuthorization.h"
#import "ZONAPIEndpoints.h"
#import "ZONNetwork.h"
@implementation ZONAuthorization
+ (void)queryCard:(NSString *)card udid:(NSString *)udid completion:(void (^)(NSDictionary *, NSError * _Nullable))completion {
    NSDictionary *body=@{@"code":card?:@"",@"udid":udid?:@""};
    [ZONNetwork POST:[ZONAPIEndpoints authorizationURL] formBody:body timeout:12 completion:^(NSDictionary *json, NSData *data, NSHTTPURLResponse *response, NSError *error) {
        NSDictionary *result=[json isKindOfClass:NSDictionary.class]?json:@{};
        if(!result.count && data.length){
            NSString *text=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]?:@"";
            result=@{@"message":text};
        }
        if(completion) completion(result,error);
    }];
}
+ (BOOL)resultNeedsActivation:(NSDictionary *)result {
    id activated=result[@"activated"]?:result[@"is_activated"]?:result[@"bound"]?:result[@"is_bound"];
    if([activated respondsToSelector:@selector(boolValue)]) return ![activated boolValue];
    NSString *code=[result[@"code"] isKindOfClass:NSString.class]?[result[@"code"] lowercaseString]:@"";
    if([code containsString:@"not_activated"]||[code containsString:@"unbound"]||[code containsString:@"not_bound"]||[code containsString:@"need_activation"]) return YES;
    NSString *action=[result[@"action"] isKindOfClass:NSString.class]?[result[@"action"] lowercaseString]:@"";
    if([action containsString:@"activate"]||[action containsString:@"bind"]) return YES;
    return NO;
}
@end

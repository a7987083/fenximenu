#import "ZONActivation.h"
#import "ZONAPIEndpoints.h"
#import "ZONNetwork.h"
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
        NSMutableDictionary *display=[NSMutableDictionary dictionaryWithDictionary:d?:@{}];
        if(!display.count && msg.length) display[@"message"]=msg;
        if(response) display[@"http_status"]=@(response.statusCode);
        // /appstore 旧协议的 code=0 同时出现在成功和失败结果中，不能据此判断业务成功。
        // 这里只报告请求是否成功到达服务器；真正激活结果由调用方继续查询 /apiface + Verify 确认。
        BOOL transportOK=response && response.statusCode>=200 && response.statusCode<300;
        if(completion) completion(transportOK,msg?:@"",display.copy);
    }];
}
@end

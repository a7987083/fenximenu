#import "ZONActivation.h"
#import "ZONNetwork.h"
#import "ZONDylibConfig.h"

@implementation ZONActivation

+ (NSDictionary *)activationConfig {
    NSDictionary *meta = [ZONDylibConfig metadata];
    id cfg = meta[@"activation"];
    return [cfg isKindOfClass:NSDictionary.class] ? cfg : @{};
}

+ (BOOL)isConfigured {
    NSDictionary *cfg = [self activationConfig];
    NSString *url = [cfg[@"url"] isKindOfClass:NSString.class] ? cfg[@"url"] : @"";
    return url.length > 0;
}

+ (void)activateUDID:(NSString *)udid card:(NSString *)card completion:(void (^)(BOOL, NSString *, NSDictionary * _Nullable))completion {
    NSDictionary *cfg = [self activationConfig];
    NSString *urlString = [cfg[@"url"] isKindOfClass:NSString.class] ? cfg[@"url"] : @"";
    if (urlString.length == 0) {
        NSDictionary *raw = @{
            @"ok": @NO,
            @"code": @"activation_api_unconfigured",
            @"message": @"当前 API 包未定义卡密激活接口"
        };
        if (completion) completion(NO, raw[@"message"], raw);
        return;
    }

    NSURL *url = [NSURL URLWithString:urlString];
    if (!url || ![url.scheme.lowercaseString isEqualToString:@"https"]) {
        NSDictionary *raw = @{
            @"ok": @NO,
            @"code": @"activation_api_invalid",
            @"message": @"卡密激活接口配置无效，必须使用 HTTPS"
        };
        if (completion) completion(NO, raw[@"message"], raw);
        return;
    }

    NSString *method = [cfg[@"method"] isKindOfClass:NSString.class] ? [cfg[@"method"] uppercaseString] : @"POST";
    NSString *encoding = [cfg[@"encoding"] isKindOfClass:NSString.class] ? [cfg[@"encoding"] lowercaseString] : @"json";
    NSDictionary *body = @{@"udid": udid ?: @"", @"card": card ?: @""};

    ZONNetworkCompletion done = ^(NSDictionary *json, NSData *data, NSHTTPURLResponse *response, NSError *error) {
        if (error) {
            NSString *msg = error.localizedDescription ?: @"网络错误";
            if (completion) completion(NO, msg, @{@"ok":@NO,@"code":@"network_error",@"message":msg});
            return;
        }
        NSDictionary *d = [json isKindOfClass:NSDictionary.class] ? json : @{};
        NSString *rawText = data.length ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"";
        id msgObj = d[@"message"] ?: d[@"msg"];
        NSString *msg = [msgObj isKindOfClass:NSString.class] ? msgObj : (rawText.length ? rawText : @"服务器未返回消息");
        BOOL ok = [d[@"ok"] respondsToSelector:@selector(boolValue)] ? [d[@"ok"] boolValue] : NO;
        if (completion) completion(ok, msg, d.count ? d : @{@"ok":@(ok),@"message":msg ?: @""});
    };

    if ([method isEqualToString:@"POST"]) {
        if ([encoding isEqualToString:@"form"]) [ZONNetwork POST:url formBody:body timeout:10 completion:done];
        else [ZONNetwork POST:url jsonBody:body timeout:10 completion:done];
        return;
    }

    NSDictionary *raw = @{@"ok":@NO,@"code":@"activation_method_unsupported",@"message":@"当前客户端仅支持 POST 卡密激活接口"};
    if (completion) completion(NO, raw[@"message"], raw);
}

@end

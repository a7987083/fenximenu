#import "ZONActivation.h"
#import "ZONNetwork.h"
#import "ZONDylibConfig.h"

@implementation ZONActivation

+ (NSURL *)softwareSourceURLForUDID:(NSString *)udid card:(NSString *)card {
    NSURLComponents *c = [NSURLComponents componentsWithString:@"http://ios.zonoeios.xyz/appstore"];
    c.queryItems = @[
        [NSURLQueryItem queryItemWithName:@"udid" value:udid ?: @""],
        [NSURLQueryItem queryItemWithName:@"code" value:card ?: @""]
    ];
    return c.URL;
}

+ (void)activateUDID:(NSString *)udid card:(NSString *)card completion:(void (^)(BOOL, NSString *, NSDictionary * _Nullable))completion {
    NSURL *url = [self softwareSourceURLForUDID:udid card:card];
    [ZONNetwork GET:url timeout:12 completion:^(NSDictionary *json, NSData *data, NSHTTPURLResponse *response, NSError *error) {
        if (error) {
            completion(NO, error.localizedDescription ?: @"网络错误", json);
            return;
        }
        NSString *msg = [json[@"msg"] isKindOfClass:NSString.class] ? json[@"msg"] : @"";
        BOOL success = [msg containsString:@"解锁成功"] || [msg isEqualToString:@"ok"];
        if (msg.length == 0 && data.length) {
            msg = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"服务器未返回可读消息";
        }
        completion(success, msg.length ? msg : @"未知响应", json);
    }];
}

+ (void)fetchLegacyStatusForUDID:(NSString *)udid completion:(void (^)(NSDictionary *))completion {
    NSMutableDictionary *merged = [NSMutableDictionary dictionary];
    dispatch_group_t g = dispatch_group_create();
    NSArray<NSArray<NSURL *> *> *groups = @[
        [ZONDylibConfig legacyDylibURLs] ?: @[],
        [ZONDylibConfig legacyApiFaceURLs] ?: @[]
    ];
    NSArray<NSString *> *names = @[@"legacy_dylib", @"legacy_apiface"];
    [groups enumerateObjectsUsingBlock:^(NSArray<NSURL *> *urls, NSUInteger idx, BOOL *stop) {
        NSURL *base = urls.firstObject;
        if (!base) return;
        NSURLComponents *c = [NSURLComponents componentsWithURL:base resolvingAgainstBaseURL:NO];
        c.queryItems = @[[NSURLQueryItem queryItemWithName:@"udid" value:udid ?: @""]];
        dispatch_group_enter(g);
        [ZONNetwork GET:c.URL timeout:10 completion:^(NSDictionary *json, NSData *data, NSHTTPURLResponse *response, NSError *error) {
            if (json) merged[names[idx]] = json;
            else if (error) merged[[names[idx] stringByAppendingString:@"_error"]] = error.localizedDescription ?: @"error";
            dispatch_group_leave(g);
        }];
    }];
    dispatch_group_notify(g, dispatch_get_main_queue(), ^{
        completion(merged.copy);
    });
}

@end

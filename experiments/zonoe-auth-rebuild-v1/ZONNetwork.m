#import "ZONNetwork.h"

@implementation ZONNetwork

+ (void)sendRequest:(NSMutableURLRequest *)req completion:(ZONNetworkCompletion)completion {
    [req setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    NSURLSessionDataTask *task = [NSURLSession.sharedSession dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *json = nil;
        if (data.length) {
            id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if ([obj isKindOfClass:NSDictionary.class]) json = obj;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(json, data, (NSHTTPURLResponse *)response, error);
        });
    }];
    [task resume];
}

+ (void)GET:(NSURL *)url timeout:(NSTimeInterval)timeout completion:(ZONNetworkCompletion)completion {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:timeout > 0 ? timeout : 10.0];
    req.HTTPMethod = @"GET";
    [self sendRequest:req completion:completion];
}

+ (void)POST:(NSURL *)url jsonBody:(NSDictionary *)body timeout:(NSTimeInterval)timeout completion:(ZONNetworkCompletion)completion {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:timeout > 0 ? timeout : 10.0];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body ?: @{} options:0 error:nil];
    [self sendRequest:req completion:completion];
}

+ (void)POST:(NSURL *)url formBody:(NSDictionary<NSString *,id> *)body timeout:(NSTimeInterval)timeout completion:(ZONNetworkCompletion)completion {
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    NSCharacterSet *allowed = [NSCharacterSet URLQueryAllowedCharacterSet];
    [body enumerateKeysAndObjectsUsingBlock:^(NSString *key, id obj, BOOL *stop) {
        NSString *k = [key stringByAddingPercentEncodingWithAllowedCharacters:allowed] ?: @"";
        NSString *v = [[obj description] stringByAddingPercentEncodingWithAllowedCharacters:allowed] ?: @"";
        [parts addObject:[NSString stringWithFormat:@"%@=%@", k, v]];
    }];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:timeout > 0 ? timeout : 10.0];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/x-www-form-urlencoded; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [[parts componentsJoinedByString:@"&"] dataUsingEncoding:NSUTF8StringEncoding];
    [self sendRequest:req completion:completion];
}

@end

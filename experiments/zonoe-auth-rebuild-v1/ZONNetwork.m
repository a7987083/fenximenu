#import "ZONNetwork.h"
@implementation ZONNetwork
+ (void)GET:(NSURL *)url timeout:(NSTimeInterval)timeout completion:(ZONNetworkCompletion)completion {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:timeout > 0 ? timeout : 10.0];
    req.HTTPMethod = @"GET";
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
@end

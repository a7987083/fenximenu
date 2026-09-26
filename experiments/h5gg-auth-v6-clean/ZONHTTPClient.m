#import "ZONHTTPClient.h"

@interface ZONHTTPClient ()
@property(nonatomic,strong) NSURL *baseURL;
@end

@implementation ZONHTTPClient

- (instancetype)initWithBaseURL:(NSURL *)baseURL {
    self = [super init];
    if (self) _baseURL = baseURL;
    return self;
}

- (void)getPath:(NSString *)path
          query:(NSDictionary<NSString *, NSString *> *)query
     completion:(ZONHTTPJSONCompletion)completion
{
    NSURL *url = [NSURL URLWithString:path relativeToURL:self.baseURL];
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:YES];
    NSMutableArray<NSURLQueryItem *> *items = [NSMutableArray array];
    [query enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        (void)stop;
        [items addObject:[NSURLQueryItem queryItemWithName:key value:value ?: @""]];
    }];
    components.queryItems = items;

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:components.URL cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:12.0];
    request.HTTPMethod = @"GET";
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];

    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        (void)response;
        if (error) {
            if (completion) completion(nil, error);
            return;
        }
        if (!data.length) {
            NSError *e = [NSError errorWithDomain:@"ZONHTTP" code:-1 userInfo:@{NSLocalizedDescriptionKey:@"服务器返回空数据"}];
            if (completion) completion(nil, e);
            return;
        }
        NSError *jsonError = nil;
        id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (![obj isKindOfClass:[NSDictionary class]]) {
            NSError *e = jsonError ?: [NSError errorWithDomain:@"ZONHTTP" code:-2 userInfo:@{NSLocalizedDescriptionKey:@"服务器返回格式错误"}];
            if (completion) completion(nil, e);
            return;
        }
        if (completion) completion((NSDictionary *)obj, nil);
    }] resume];
}

@end

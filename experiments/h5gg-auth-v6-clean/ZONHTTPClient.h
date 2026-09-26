#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^ZONHTTPJSONCompletion)(NSDictionary * _Nullable json, NSError * _Nullable error);

@interface ZONHTTPClient : NSObject
- (instancetype)initWithBaseURL:(NSURL *)baseURL;
- (void)getPath:(NSString *)path
          query:(NSDictionary<NSString *, NSString *> *)query
     completion:(ZONHTTPJSONCompletion)completion;
@end

NS_ASSUME_NONNULL_END

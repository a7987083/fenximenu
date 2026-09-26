#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
typedef void (^ZONNetworkCompletion)(NSDictionary * _Nullable json, NSData * _Nullable data, NSHTTPURLResponse * _Nullable response, NSError * _Nullable error);
@interface ZONNetwork : NSObject
+ (void)GET:(NSURL *)url timeout:(NSTimeInterval)timeout completion:(ZONNetworkCompletion)completion;
@end
NS_ASSUME_NONNULL_END

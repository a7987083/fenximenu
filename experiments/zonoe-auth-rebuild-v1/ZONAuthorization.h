#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONAuthorization : NSObject
+ (void)queryCard:(NSString *)card udid:(NSString *)udid completion:(void (^)(NSDictionary *result, NSError * _Nullable error))completion;
+ (BOOL)resultNeedsActivation:(NSDictionary *)result;
@end
NS_ASSUME_NONNULL_END

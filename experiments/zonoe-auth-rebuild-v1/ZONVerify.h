#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONVerify : NSObject
+ (void)runWithUDID:(NSString *)udid completion:(void (^)(NSDictionary *result))completion;
@end
NS_ASSUME_NONNULL_END

#import <Foundation/Foundation.h>

@class ZONDylibVerifyResult;

NS_ASSUME_NONNULL_BEGIN

@interface ZONVerifyAdapter : NSObject
- (void)verifyUDID:(NSString *)udid
        completion:(void (^)(ZONDylibVerifyResult *result))completion;
@end

NS_ASSUME_NONNULL_END

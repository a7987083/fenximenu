#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONLicenseStatus : NSObject
+ (void)fetchForUDID:(NSString *)udid completion:(void (^)(NSDictionary *result, BOOL signatureValid, NSError * _Nullable error))completion;
@end
NS_ASSUME_NONNULL_END

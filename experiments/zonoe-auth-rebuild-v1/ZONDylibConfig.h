#import <Foundation/Foundation.h>
#import "ZONDylibVerify.h"
NS_ASSUME_NONNULL_BEGIN
@interface ZONDylibConfig : NSObject
+ (ZONDylibVerifyConfiguration *)configurationWithUDIDProvider:(ZONDylibUDIDProvider)udidProvider;
+ (NSDictionary<NSString *, id> *)metadata;
@end
NS_ASSUME_NONNULL_END

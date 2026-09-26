#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZONUDIDStore : NSObject
+ (nullable NSString *)savedUDID;
+ (void)saveUDID:(NSString *)udid;
+ (void)clearUDID;
@end

NS_ASSUME_NONNULL_END

#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONAPIEndpoints : NSObject
+ (NSURL *)authorizationURL;
+ (NSURL *)activationURLForUDID:(NSString *)udid card:(NSString *)card;
+ (NSURL *)apiFaceURLForUDID:(NSString *)udid;
@end
NS_ASSUME_NONNULL_END

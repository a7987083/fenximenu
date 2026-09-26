#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONAPIEndpoints : NSObject
+ (NSString *)base;
+ (NSURL *)authorizationURL;
+ (NSURL *)activationURLForUDID:(NSString *)udid card:(NSString * _Nullable)card;
+ (NSURL *)apiFaceURLForUDID:(NSString *)udid;
+ (NSURL *)legacyDylibConfigURLForUDID:(NSString *)udid;
+ (NSURL *)unbindQueryURLForUDID:(NSString *)udid;
+ (NSURL *)unbindURL;
+ (NSURL *)runtimeConfigURLForDylibKey:(NSString *)dylibKey;
+ (NSURL *)verifyURL;
@end
NS_ASSUME_NONNULL_END

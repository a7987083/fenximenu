#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONActivation : NSObject
+ (BOOL)isConfigured;
+ (void)activateUDID:(NSString *)udid
                card:(NSString *)card
          completion:(void (^)(BOOL ok, NSString *message, NSDictionary * _Nullable raw))completion;
@end
NS_ASSUME_NONNULL_END

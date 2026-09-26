#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONActivation : NSObject
+ (void)activateUDID:(NSString *)udid
                card:(NSString *)card
          completion:(void (^)(BOOL ok, NSString *message, NSDictionary * _Nullable raw))completion;
+ (void)fetchLegacyStatusForUDID:(NSString *)udid completion:(void (^)(NSDictionary *status))completion;
@end
NS_ASSUME_NONNULL_END

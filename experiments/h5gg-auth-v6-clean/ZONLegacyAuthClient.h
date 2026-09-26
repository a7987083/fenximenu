#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^ZONLegacyJSONCompletion)(NSDictionary * _Nullable json, NSError * _Nullable error);

@interface ZONLegacyAuthClient : NSObject
- (void)checkUDID:(NSString *)udid completion:(ZONLegacyJSONCompletion)completion;
- (void)activateCard:(NSString *)card udid:(NSString *)udid completion:(ZONLegacyJSONCompletion)completion;
@end

NS_ASSUME_NONNULL_END

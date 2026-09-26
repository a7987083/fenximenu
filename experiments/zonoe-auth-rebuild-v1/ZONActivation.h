#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONActivationResult : NSObject
@property(nonatomic,assign) BOOL success;
@property(nonatomic,copy) NSString *message;
@property(nonatomic,strong) id displayObject;
@property(nonatomic,copy) NSDictionary *json;
@end
@interface ZONActivation : NSObject
+ (void)activateUDID:(NSString *)udid card:(NSString *)card completion:(void (^)(ZONActivationResult *result))completion;
@end
NS_ASSUME_NONNULL_END

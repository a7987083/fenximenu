#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, ZONAuthPhase) {
    ZONAuthPhaseIdle = 0,
    ZONAuthPhaseNeedsUDID,
    ZONAuthPhaseCheckingLegacyAuthorization,
    ZONAuthPhaseNeedsCard,
    ZONAuthPhaseActivatingCard,
    ZONAuthPhaseRunningDylibVerify,
    ZONAuthPhaseAuthorized,
    ZONAuthPhaseFailed,
};

@interface ZONAuthSnapshot : NSObject
@property(nonatomic, assign) ZONAuthPhase phase;
@property(nonatomic, copy) NSString *udid;
@property(nonatomic, copy) NSString *message;
@property(nonatomic, copy) NSDictionary *legacyPayload;
@property(nonatomic, copy) NSDictionary *verifyPayload;
@end

NS_ASSUME_NONNULL_END

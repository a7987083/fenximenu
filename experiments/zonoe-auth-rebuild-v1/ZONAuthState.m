#import "ZONAuthState.h"

@implementation ZONAuthSnapshot
- (instancetype)init {
    self = [super init];
    if (!self) return nil;
    _phase = ZONAuthPhaseIdle;
    _udid = @"";
    _message = @"";
    _legacyPayload = @{};
    _verifyPayload = @{};
    return self;
}
@end

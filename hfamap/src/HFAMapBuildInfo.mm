#import "HFAMapBuildInfo.h"

NSString *HFAMapBuildVersion(void) {
    return @"2.5.27-dev";
}

NSString *HFAMapBuildComponent(void) {
    return @"2.5.27-dev-native-consumer-target-bridge";
}

NSString *HFAMapBuildPolicy(void) {
    return @"AUTO-HOST-AUTO-UNITY-STATIC-CONSUMER-LIVE-SLOT-IL2CPP-BRIDGE";
}

NSString *HFAMapDisplayVersion(void) {
    return [NSString stringWithFormat:@"HFAMap v%@", HFAMapBuildVersion()];
}

NSDictionary *HFAMapBuildIdentity(void) {
    return @{
        @"buildVersion": HFAMapBuildVersion(),
        @"componentVersion": HFAMapBuildComponent(),
        @"policy": HFAMapBuildPolicy()
    };
}

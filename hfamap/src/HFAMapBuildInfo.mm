#import "HFAMapBuildInfo.h"

NSString *HFAMapBuildVersion(void) {
    return @"2.5.28-dev";
}

NSString *HFAMapBuildComponent(void) {
    return @"2.5.28-dev-recursive-native-target-bridge";
}

NSString *HFAMapBuildPolicy(void) {
    return @"AUTO-HOST-AUTO-UNITY-RECURSIVE-NATIVE-TARGET-IL2CPP-BRIDGE";
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

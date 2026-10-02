#import "HFAMapBuildInfo.h"

NSString *HFAMapBuildVersion(void) {
    return @"2.5.24-dev";
}

NSString *HFAMapBuildComponent(void) {
    return @"2.5.24-dev-two-button-unified-ui";
}

NSString *HFAMapBuildPolicy(void) {
    return @"AUTO-HOST-AUTO-UNITY-TWO-BUTTON-UNIFIED-RESOLUTION";
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

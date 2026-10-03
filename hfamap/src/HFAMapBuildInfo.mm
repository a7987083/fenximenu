#import "HFAMapBuildInfo.h"

NSString *HFAMapBuildVersion(void) {
    return @"2.5.25-dev";
}

NSString *HFAMapBuildComponent(void) {
    return @"2.5.25-dev-two-button-unified-ui";
}

NSString *HFAMapBuildPolicy(void) {
    return @"AUTO-HOST-AUTO-UNITY-STATIC-CONSUMER-DIRECT-NATIVE-RESOLUTION";
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

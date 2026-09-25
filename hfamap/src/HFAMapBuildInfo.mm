#import "HFAMapBuildInfo.h"

NSString *HFAMapBuildVersion(void) {
    return @"2.5.22-dev";
}

NSString *HFAMapBuildComponent(void) {
    return @"2.5.22-dev-feature-dispatcher-slicing";
}

NSString *HFAMapBuildPolicy(void) {
    return @"READ-ONLY-FAST-UI-ASYNC-FEATURE-DISPATCHER-SLICING";
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

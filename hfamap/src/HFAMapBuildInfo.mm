#import "HFAMapBuildInfo.h"

NSString *HFAMapBuildVersion(void) {
    return @"2.5.21-dev";
}

NSString *HFAMapBuildComponent(void) {
    return @"2.5.21-dev-universal-feature-implementation";
}

NSString *HFAMapBuildPolicy(void) {
    return @"READ-ONLY-FAST-UI-ASYNC-UNIVERSAL-FEATURE-IMPLEMENTATION";
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

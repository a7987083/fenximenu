#import "HFAMapBuildInfo.h"

NSString *HFAMapBuildVersion(void) {
    return @"2.5.20.1-dev";
}

NSString *HFAMapBuildComponent(void) {
    return @"2.5.20.1-dev-inventory-cache-hotfix";
}

NSString *HFAMapBuildPolicy(void) {
    return @"READ-ONLY-BOUNDED-SHARED-IMPLEMENTATION-CACHE";
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

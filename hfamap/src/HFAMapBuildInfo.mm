#import "HFAMapBuildInfo.h"

NSString *HFAMapBuildVersion(void) {
    return @"2.5.29-dev";
}

NSString *HFAMapBuildComponent(void) {
    return @"2.5.29-dev-generic-lua-template-resolver";
}

NSString *HFAMapBuildPolicy(void) {
    return @"AUTO-GENERIC-RUNTIME-TEMPLATE-RECOVERY-READ-ONLY";
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

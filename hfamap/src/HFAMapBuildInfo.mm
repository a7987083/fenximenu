#import "HFAMapBuildInfo.h"

NSString *HFAMapBuildVersion(void) {
    return @"2.5.30-dev";
}

NSString *HFAMapBuildComponent(void) {
    return @"2.5.30-dev-decrypt-wrapper-semantic-resolver";
}

NSString *HFAMapBuildPolicy(void) {
    return @"AUTO-DECRYPT-WRAPPER-SEMANTIC-RUNTIME-TEMPLATE-RECOVERY";
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

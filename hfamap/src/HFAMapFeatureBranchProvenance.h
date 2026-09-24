#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSDictionary *HFAMapBuildFeatureBranchProvenance(NSString *loadedMenuPath,
                                                                    NSDictionary *featureInventory,
                                                                    NSError **error);
FOUNDATION_EXPORT BOOL HFAMapPersistFeatureBranchProvenance(NSDictionary *result, NSError **error);

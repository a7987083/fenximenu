#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSDictionary *HFAMapCorrelateFeatureOwnership(NSString *loadedMenuPath,
                                                                 NSDictionary *featureInventory,
                                                                 NSError **error);
FOUNDATION_EXPORT BOOL HFAMapPersistFeatureOwnership(NSDictionary *result, NSError **error);

#import <Foundation/Foundation.h>

// v2.5.20 unified read-only implementation inventory.
// Aggregates already validated memory-patch records, runtime IL2CPP method
// correlations and bounded direct-write/state-mutation evidence per menu feature.
FOUNDATION_EXPORT NSDictionary *HFAMapBuildMenuImplementationInventory(
    NSString *menuPath,
    NSDictionary *featureInventory,
    NSDictionary *directedDescriptors,
    NSDictionary *secretWrapperEvidence,
    NSArray<NSDictionary *> *canonicalPatchFeatures,
    NSError **error);

FOUNDATION_EXPORT BOOL HFAMapPersistMenuImplementationInventory(NSDictionary *inventory,
                                                                 NSError **error);

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Runtime-directed descriptor resolution from real UIKit controls/targets in an already loaded menu image.
// Read-only: no unknown selector invocation, no IMP replacement, no inline hook, no game-state write.
FOUNDATION_EXPORT NSDictionary * _Nullable HFAMapResolveDirectedDescriptors(NSString *loadedMenuPath,
                                                                            NSDictionary *rootGraph,
                                                                            NSError **error);
FOUNDATION_EXPORT BOOL HFAMapPersistDirectedDescriptors(NSDictionary *result, NSError **error);

NS_ASSUME_NONNULL_END

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Read-only runtime roots and descriptor graph for an already loaded menu dylib.
// Uses known UIKit/Foundation APIs plus ObjC metadata. No unknown selector invocation,
// no IMP replacement, no inline hook, no memory write.
FOUNDATION_EXPORT NSDictionary * _Nullable HFAMapResolveRuntimeRootGraph(NSString *loadedMenuPath,
                                                                         NSDictionary *loadedEvidence,
                                                                         NSError **error);
FOUNDATION_EXPORT BOOL HFAMapPersistRuntimeRootGraph(NSDictionary *graph, NSError **error);

NS_ASSUME_NONNULL_END

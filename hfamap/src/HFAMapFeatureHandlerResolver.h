#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

// Read-only, bounded analysis seeded only from already-known feature/action relationships.
// It never invokes a discovered block/selector and never writes target memory.
NSDictionary *HFAMapAnalyzeFeatureHandlerSnapshot(NSDictionary *snapshot,
                                                   NSDictionary *candidate);

NS_ASSUME_NONNULL_END

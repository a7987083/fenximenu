#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Read-only resolver for menu implementations that install a runtime hook instead
// of carrying a conventional offset/patch descriptor. It derives object-field
// semantics from the selected menu image, then looks for a unique matching
// load/arithmetic/store flow in currently loaded executable images.
NSDictionary *HFAMapResolveHookSemanticFeatures(NSDictionary *candidate,
                                                 NSArray<NSDictionary *> *registry,
                                                 NSArray<NSDictionary *> *executableImages,
                                                 NSTimeInterval deadline);

NS_ASSUME_NONNULL_END
#endif

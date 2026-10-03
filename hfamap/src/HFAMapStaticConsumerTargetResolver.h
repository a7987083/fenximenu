#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

// Read-only file-backed resolver. It correlates exact feature identifiers with
// references in the selected menu image and groups features that are consumed by
// the same native function. No selector/block is invoked and no memory is written.
NSDictionary *HFAMapResolveStaticNativeConsumers(NSDictionary *candidate,
                                                  NSArray<NSDictionary *> *registry,
                                                  NSTimeInterval deadline);
#endif

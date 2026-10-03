#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

// Read-only bridge from a statically identified menu native consumer to live
// indirect call/original slots. It never invokes the consumer, never installs a
// hook and never writes target memory. External live pointees are correlated
// with the existing IL2CPP exact/containing method index when possible.
NSDictionary *HFAMapResolveNativeConsumerTargets(NSDictionary *candidate,
                                                 NSDictionary *staticConsumers,
                                                 NSTimeInterval deadline);
#endif

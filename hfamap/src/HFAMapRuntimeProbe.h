#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

void HFAMapArmRuntimeProbeForCandidate(NSDictionary *candidate, NSTimeInterval duration,
                                      void (^completion)(NSDictionary *summary));
void HFAMapStopRuntimeProbe(NSString *reason);
BOOL HFAMapRuntimeProbeIsArmed(void);
#endif

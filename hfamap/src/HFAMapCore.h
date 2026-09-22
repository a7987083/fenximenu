#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>
void HFAMapRunMenuDiscovery(void (^completion)(NSDictionary *summary));
void HFAMapRunSelectedDeepAnalysis(void (^completion)(NSDictionary *summary));
// Compatibility alias retained for older callers/tests; maps to discovery only in v2.4.6.
void HFAMapRunBoundedScan(void (^completion)(NSDictionary *summary));
void HFAMapArmLastSelectedRuntimeProbe(void (^completion)(NSDictionary *summary));
void HFAMapStopActiveRuntimeProbe(NSString *reason);
BOOL HFAMapRuntimeProbeIsActive(void);
#endif

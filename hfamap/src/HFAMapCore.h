#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#ifdef __cplusplus
extern "C" {
#endif

void HFAMapRunMenuDiscovery(void (^completion)(NSDictionary *summary));
void HFAMapRunSelectedDeepAnalysis(void (^completion)(NSDictionary *summary));
void HFAMapRunBoundedScan(void (^completion)(NSDictionary *summary));
void HFAMapArmLastSelectedRuntimeProbe(void (^completion)(NSDictionary *summary));
void HFAMapStopActiveRuntimeProbe(NSString *reason);
BOOL HFAMapRuntimeProbeIsActive(void);
BOOL HFAMapSelectMenuCandidate(NSDictionary *candidate);

#ifdef __cplusplus
}
#endif
#endif

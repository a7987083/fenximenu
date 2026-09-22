#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>
void HFAMapRunBoundedScan(void (^completion)(NSDictionary *summary));
void HFAMapArmLastSelectedRuntimeProbe(void (^completion)(NSDictionary *summary));
void HFAMapStopActiveRuntimeProbe(NSString *reason);
BOOL HFAMapRuntimeProbeIsActive(void);
#endif

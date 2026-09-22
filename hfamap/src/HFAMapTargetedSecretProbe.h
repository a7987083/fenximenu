#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

NSDictionary *HFAMapArmTargetedSecretProbe(NSDictionary *candidate, NSTimeInterval duration);
void HFAMapStopTargetedSecretProbe(NSString *reason);
BOOL HFAMapTargetedSecretProbeIsActive(void);

#endif

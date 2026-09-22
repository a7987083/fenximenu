#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

NSDictionary *HFAIL2CPPRuntimeProbeArm(NSDictionary *candidate, NSTimeInterval duration);
void HFAIL2CPPRuntimeProbeMarkInteraction(NSString *label, NSString *controlToken);
NSDictionary *HFAIL2CPPRuntimeProbeStop(NSString *reason);
BOOL HFAIL2CPPRuntimeProbeIsArmed(void);
#endif

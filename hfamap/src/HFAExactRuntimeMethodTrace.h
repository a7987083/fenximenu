#pragma once
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *HFAExactRuntimeMethodTraceArm(NSTimeInterval duration);
void HFAExactRuntimeMethodTraceMarkInteraction(NSString *label, NSString *controlToken);
NSDictionary *HFAExactRuntimeMethodTraceStop(NSString *reason);
BOOL HFAExactRuntimeMethodTraceIsArmed(void);
#endif

#pragma once
#import <Foundation/Foundation.h>
#ifdef __cplusplus
extern "C" {
#endif
BOOL HFAUnifiedIL2CPPTraceIsArmed(void);
NSDictionary *HFAUnifiedIL2CPPTraceArm(NSTimeInterval duration);
NSDictionary *HFAUnifiedIL2CPPTraceStop(NSString *reason);
#ifdef __cplusplus
}
#endif

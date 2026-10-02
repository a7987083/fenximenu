#pragma once
#import <Foundation/Foundation.h>
BOOL HFAUnifiedIL2CPPTraceIsArmed(void);
NSDictionary *HFAUnifiedIL2CPPTraceArm(NSTimeInterval duration);
NSDictionary *HFAUnifiedIL2CPPTraceStop(NSString *reason);

#pragma once
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *ZPDescriptorObserverArm(NSDictionary *candidate, NSDictionary *descriptor, NSTimeInterval duration);
NSDictionary *ZPDescriptorObserverStatus(void);
void ZPDescriptorObserverDisarm(NSString *reason);
#endif

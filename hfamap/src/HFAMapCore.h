#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>
void HFAMapRunBoundedScan(void (^completion)(NSDictionary *summary));
#endif

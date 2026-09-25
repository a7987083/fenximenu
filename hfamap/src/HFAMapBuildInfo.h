#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
NSString *HFAMapBuildVersion(void);
NSString *HFAMapBuildComponent(void);
NSString *HFAMapBuildPolicy(void);
NSString *HFAMapDisplayVersion(void);
NSDictionary *HFAMapBuildIdentity(void);
NS_ASSUME_NONNULL_END
#endif

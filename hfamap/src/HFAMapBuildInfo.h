#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#ifdef __cplusplus
extern "C" {
#endif

NS_ASSUME_NONNULL_BEGIN
NSString *HFAMapBuildVersion(void);
NSString *HFAMapBuildComponent(void);
NSString *HFAMapBuildPolicy(void);
NSString *HFAMapDisplayVersion(void);
NSDictionary *HFAMapBuildIdentity(void);
NS_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif
#endif

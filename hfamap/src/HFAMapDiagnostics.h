#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
NSString *HFADiagnosticsBeginSession(void);
NSString *HFADiagnosticsSessionID(void);
void HFADiagnosticsLog(NSString *stage, NSString *status,
                       NSDictionary * _Nullable details);
void HFADiagnosticsFinishSession(NSString *status,
                                 NSDictionary * _Nullable details);
NS_ASSUME_NONNULL_END
#endif

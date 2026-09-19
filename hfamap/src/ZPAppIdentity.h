#pragma once
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *ZPAppIdentity(void);
NSString *ZPLogStem(void);
NSString *ZPLogFilename(NSString *suffix);
#endif

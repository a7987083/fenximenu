#import <Foundation/Foundation.h>

// Uses the host application's Info.plist at runtime, not the injected dylib's metadata.
FOUNDATION_EXPORT NSString *HFAHostAppName(void);
FOUNDATION_EXPORT NSString *HFAOutputFileName(NSString *suffix);

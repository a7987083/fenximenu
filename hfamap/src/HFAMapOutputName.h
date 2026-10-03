#import <Foundation/Foundation.h>

// Uses the host application's Info.plist at runtime, not the injected dylib's metadata.
FOUNDATION_EXPORT NSString *HFAHostAppName(void);
FOUNDATION_EXPORT NSString *HFAOutputFileName(NSString *suffix);

// Per-target output directory. The directory name is the selected target file's
// exact sanitized filename, including its extension (for example foo.dylib).
FOUNDATION_EXPORT void HFASetOutputTargetFileName(NSString *fileName);
FOUNDATION_EXPORT NSString *HFAOutputDirectoryPath(void);

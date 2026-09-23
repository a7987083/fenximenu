#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// Read-only, bounded callback-context analysis seeded from an exact UIControl
// target/action relationship. The ARM64 ABI context is x0=target, x1=_cmd,
// x2=sender. No selector is invoked, no hook is installed, and no game memory
// is written.
NSDictionary *HFAMapAnalyzeFeatureCallbackContext(const void *implementation,
                                                   NSString *implementationPath,
                                                   id target,
                                                   SEL selector,
                                                   UIControl *sender);
#endif

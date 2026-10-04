#pragma once
#import <Foundation/Foundation.h>
#include <stdint.h>

// Read-only, bounded traversal of menu-internal native trampolines.
// Follows only structurally unique ARM64 branch targets and never invokes code.
NSDictionary *HFAMapResolveRecursiveNativeTarget(uintptr_t startTarget,
                                                 NSString *menuImage,
                                                 NSTimeInterval deadline);

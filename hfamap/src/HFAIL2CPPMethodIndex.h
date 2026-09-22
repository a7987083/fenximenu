#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

// Builds a read-only, bounded Assembly-CSharp method-pointer index using
// dynamically resolved IL2CPP exports. No method is invoked and no game memory
// is written. The result is analysis-only evidence.
NSDictionary *HFAIL2CPPBuildMethodIndex(NSTimeInterval deadline);
NSDictionary *HFAIL2CPPMethodForRuntimeAddress(const void *address);
#endif

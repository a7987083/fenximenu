#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN

// Read-only IL2CPP runtime resolver. Records must carry targetImage + offset where
// offset uses preferred Mach-O VM address semantics. Only exact methodPointer
// matches are promoted to runtime_verified.
NSDictionary *HFAMapResolveIL2CPPMethods(NSArray<NSDictionary *> *records,
                                         NSArray<NSDictionary *> *executableImages,
                                         NSTimeInterval deadline);

NS_ASSUME_NONNULL_END
#endif

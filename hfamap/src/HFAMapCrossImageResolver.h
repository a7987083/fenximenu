#pragma once
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Resolve deterministic ARM64 import/stub/veneer chains without executing them.
// Returned dictionaries are analysis-only and include finalAddressValue for
// internal handoff to the IL2CPP semantic resolver.
FOUNDATION_EXPORT NSDictionary * _Nullable HFACrossImageResolveTarget(const void *target);
FOUNDATION_EXPORT NSDictionary * _Nullable HFACrossImageResolveBLRCallsite(const void *functionStart,
                                                                            unsigned callsiteOffset,
                                                                            unsigned targetRegister);
FOUNDATION_EXPORT NSDictionary *HFACrossImageResolverStatus(void);

NS_ASSUME_NONNULL_END

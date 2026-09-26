#import <Foundation/Foundation.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN

// v0.3.4 Semantic Backend Analyzer.
// Static analysis is the primary path. Runtime IL2CPP metadata is enrichment
// only: failure to resolve metadata must never discard a native backend.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacement(
    uintptr_t replacement,
    uintptr_t originalSlot);

FOUNDATION_EXPORT NSDictionary<NSString *, id> *HFAIL2CPPDescribeOwningMethod(
    uintptr_t targetRuntimeAddress);

NS_ASSUME_NONNULL_END

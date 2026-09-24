#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// UNIVERSAL / 通用 ONLY.
// Read-only runtime inventory for an already loaded dylib. No dlopen, no selector invocation,
// no IMP replacement, no memory writes, no game-specific names/UUIDs/offsets/patch bytes.
FOUNDATION_EXPORT NSDictionary * _Nullable HFAMapResolveLoadedDylibEvidence(NSString *importedPath,
                                                                            NSDictionary *staticEvidence,
                                                                            NSError **error);
FOUNDATION_EXPORT BOOL HFAMapPersistLoadedDylibEvidence(NSDictionary *evidence,
                                                        NSError **error);

NS_ASSUME_NONNULL_END

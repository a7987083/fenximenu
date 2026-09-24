#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// UNIVERSAL / 通用 ONLY.
// Read-only runtime evidence for an already loaded dylib. Inventories ObjC metadata and bounded
// initialized state from readable data sections/global roots, and reads accepted instance ivars
// by runtime-provided offsets. No dlopen, no unknown selector/IMP invocation, no hook replacement,
// no memory writes, and no game-specific names/UUIDs/offsets/patch bytes.
FOUNDATION_EXPORT NSDictionary * _Nullable HFAMapResolveLoadedDylibEvidence(NSString *importedPath,
                                                                            NSDictionary *staticEvidence,
                                                                            NSError **error);
FOUNDATION_EXPORT BOOL HFAMapPersistLoadedDylibEvidence(NSDictionary *evidence,
                                                        NSError **error);

NS_ASSUME_NONNULL_END

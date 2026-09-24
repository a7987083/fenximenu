#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Read-only evidence collector for initialized wrapper objects already reached by
// the directed runtime descriptor resolver. It does not invoke wrapper getters
// or decrypt routines; it only reads object ivars, bounded memory, ObjC metadata,
// and executable bytes for later static reconstruction.
FOUNDATION_EXPORT NSDictionary * _Nullable HFAMapResolveSecretWrapperEvidence(NSString *loadedMenuPath,
                                                                               NSDictionary *directedDescriptors,
                                                                               NSError **error);
FOUNDATION_EXPORT BOOL HFAMapPersistSecretWrapperEvidence(NSDictionary *result, NSError **error);

NS_ASSUME_NONNULL_END

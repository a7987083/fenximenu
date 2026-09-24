#import <Foundation/Foundation.h>

// UNIVERSAL / 通用 ONLY.
// This analyzer must stay generic across imported dylibs and games.
// Samples are validation fixtures only; never hard-code a game name, feature label,
// class/method name, image UUID, RVA/offset, patch bytes, or menu-family-specific target.
// Recognize reusable structural evidence and fail closed when provenance is ambiguous.
//
// Read-only static evidence extraction for an imported dylib.
// The dylib is never dlopen'ed or executed.
FOUNDATION_EXPORT NSDictionary *HFAMapAnalyzeImportedDylibEvidence(NSString *path,
                                                                   NSDictionary *staticCatalog,
                                                                   NSError **error);
FOUNDATION_EXPORT BOOL HFAMapPersistImportedDylibEvidence(NSDictionary *evidence,
                                                          NSError **error);

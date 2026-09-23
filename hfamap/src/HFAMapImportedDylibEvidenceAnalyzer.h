#import <Foundation/Foundation.h>

// Read-only static evidence extraction for an imported dylib.
// The dylib is never dlopen'ed or executed.
FOUNDATION_EXPORT NSDictionary *HFAMapAnalyzeImportedDylibEvidence(NSString *path,
                                                                   NSDictionary *staticCatalog,
                                                                   NSError **error);
FOUNDATION_EXPORT BOOL HFAMapPersistImportedDylibEvidence(NSDictionary *evidence,
                                                          NSError **error);

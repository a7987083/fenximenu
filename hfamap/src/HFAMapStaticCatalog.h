#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Enumerates analyzable dylibs under the app Documents directory (bounded depth/count).
NSArray<NSDictionary *> *HFAMapStaticCatalogListDocumentDylibs(void);

// Pure file analysis. The target dylib is never dlopen'ed or executed.
NSDictionary *HFAMapStaticCatalogAnalyzeFile(NSString *path, NSError **error);

// Registers a successfully generated catalog for immediate same-session lookup and persists it.
BOOL HFAMapStaticCatalogRegisterAndPersist(NSDictionary *catalog, NSError **error);

// Current in-memory catalog, if any.
nullable NSDictionary *HFAMapStaticCatalogCurrent(void);

// Runtime lookup by loaded image + RVA. UUID must match when both sides expose one.
nullable NSDictionary *HFAMapStaticCatalogLookup(NSString *loadedImage, uint64_t rva);

NS_ASSUME_NONNULL_END

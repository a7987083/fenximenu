#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Adds same-session static-catalog matches to runtime-discovered handler blocks.
// Input graph is not mutated.
NSDictionary *HFAMapStaticCatalogAnnotateHandlerGraph(NSDictionary *graph,
                                                      NSString *loadedImage);

NS_ASSUME_NONNULL_END

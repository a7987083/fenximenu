#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Correlates exact runtime feature descriptors with the already-generated offline
// static callback catalog. This is evidence-only and fail-closed: it never invokes
// callbacks/selectors and never writes target memory.
NSDictionary *HFAMapResolveDescriptorStaticCallbacks(NSDictionary *handlerGraph,
                                                      NSArray<NSDictionary *> *registry,
                                                      NSString *loadedImage);

NS_ASSUME_NONNULL_END

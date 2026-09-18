#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
NSDictionary *HFAMapCaptureFeatureSeeds(NSDictionary *candidate, NSTimeInterval deadline,
                                        NSMutableArray<NSDictionary *> *events);
NSDictionary *HFAMapResolveFeatureSeeds(NSDictionary *candidate, NSDictionary *snapshot,
                                        NSTimeInterval deadline,
                                        NSMutableArray<NSDictionary *> *events);
NS_ASSUME_NONNULL_END
#endif

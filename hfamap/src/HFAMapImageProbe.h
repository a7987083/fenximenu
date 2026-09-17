#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
NSArray<NSDictionary *> *HFAMapDiscoverMenuImages(NSTimeInterval deadline,
                                                    NSMutableArray<NSDictionary *> *events);
NS_ASSUME_NONNULL_END
#endif

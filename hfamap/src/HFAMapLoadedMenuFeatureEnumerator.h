#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

NSDictionary *HFAMapEnumerateLoadedMenuFeatures(NSString *loadedMenuPath,
                                                NSDictionary *rootGraph,
                                                NSDictionary *directed,
                                                NSError **error);
BOOL HFAMapPersistLoadedMenuFeatureInventory(NSDictionary *result, NSError **error);
#endif

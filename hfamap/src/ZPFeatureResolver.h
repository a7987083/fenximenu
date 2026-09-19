#pragma once
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
void ZPFeatureResolverReset(void);
NSArray<NSDictionary *> *ZPFeatureResolverCollect(void);
void ZPFeatureResolverMergeContainerFeatures(NSArray<NSDictionary *> *features);
NSDictionary * _Nullable ZPFeatureForIdentifier(NSString *identifier);
NS_ASSUME_NONNULL_END
#endif

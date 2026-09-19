#pragma once
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
void ZPFeatureResolverReset(void);
NSArray<NSDictionary *> *ZPFeatureResolverCollect(void);
NSDictionary * _Nullable ZPFeatureForIdentifier(NSString *identifier);
NS_ASSUME_NONNULL_END
#endif

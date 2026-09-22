#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
NSDictionary * _Nullable HFAMapBuildPatchV1Package(NSArray<NSDictionary *> *features,
                                                     NSString * _Nullable * _Nullable reason);
NSDictionary * _Nullable HFAMapBuildPatchV1PackageWithReport(
    NSArray<NSDictionary *> *features,
    NSString * _Nullable * _Nullable reason,
    NSDictionary * _Nullable * _Nullable report);
NS_ASSUME_NONNULL_END
#endif

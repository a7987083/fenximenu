#pragma once
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
NSDictionary *ZPContainerCaptureSeeds(NSString *candidateImage, NSTimeInterval deadline);
NSDictionary *ZPContainerResolve(NSString *candidateImage, NSDictionary *snapshot, NSTimeInterval deadline);
NS_ASSUME_NONNULL_END
#endif

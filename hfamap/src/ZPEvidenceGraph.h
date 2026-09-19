#pragma once
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
void ZPEvidenceGraphReset(void);
NSString *ZPEvidenceGraphAddNode(NSString *kind, NSDictionary *attributes);
void ZPEvidenceGraphAddEdge(NSString *fromNode, NSString *relation, NSString *toNode, NSDictionary *evidence);
NSDictionary *ZPEvidenceGraphSnapshot(void);
NS_ASSUME_NONNULL_END
#endif

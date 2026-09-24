#import "HFAMapFeatureBranchProvenance.h"
#import "HFAMapHandlerBranchProvenanceResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdlib.h>

static uintptr_t HFABPParseHex(NSString *value) {
    if (![value isKindOfClass:NSString.class] || !value.length) return 0;
    return (uintptr_t)strtoull(value.UTF8String, NULL, 0);
}

static NSArray *HFABPBlocksFromFields(NSArray *fields, NSString *ownerToken, NSString *kind) {
    NSMutableArray *out=[NSMutableArray array];
    for (NSDictionary *field in fields ?: @[]) {
        NSDictionary *block=field[@"blockEvidence"];
        if (![block isKindOfClass:NSDictionary.class]) continue;
        NSMutableDictionary *e=[[block mutableCopy] autorelease];
        e[@"ownership"]=@{ @"ownerToken":ownerToken?:@"", @"kind":kind?:@"", @"fieldName":field[@"name"]?:@"", @"fieldOffset":field[@"offset"]?:@"" };
        [out addObject:e];
    }
    return out;
}

static NSArray *HFABPUniqueBlocks(NSArray *blocks) {
    NSMutableArray *out=[NSMutableArray array]; NSMutableSet *seen=[NSMutableSet set];
    for (NSDictionary *b in blocks ?: @[]) {
        NSString *key=[NSString stringWithFormat:@"%@|%@|%@",b[@"token"]?:@"",b[@"ownership"][@"ownerToken"]?:@"",b[@"ownership"][@"fieldName"]?:@""];
        if ([seen containsObject:key]) continue; [seen addObject:key]; [out addObject:b];
    }
    return out;
}

NSDictionary *HFAMapBuildFeatureBranchProvenance(NSString *loadedMenuPath, NSDictionary *featureInventory, NSError **error) {
    if (![featureInventory isKindOfClass:NSDictionary.class]) {
        if (error) *error=[NSError errorWithDomain:@"com.hfa.feature-branch-provenance" code:1 userInfo:@{NSLocalizedDescriptionKey:@"missing-feature-inventory"}];
        return nil;
    }
    NSArray *features=featureInventory[@"featureCandidates"]?:@[];
    NSArray *controls=featureInventory[@"controls"]?:@[];
    NSArray *nodes=featureInventory[@"objectGraph"][@"nodes"]?:@[];
    NSMutableDictionary *controlByToken=[NSMutableDictionary dictionary],*nodeByToken=[NSMutableDictionary dictionary],*targetFeatureUse=[NSMutableDictionary dictionary];
    for (NSDictionary *c in controls) if ([c[@"controlToken"] length]) controlByToken[c[@"controlToken"]]=c;
    for (NSDictionary *n in nodes) if ([n[@"token"] length]) nodeByToken[n[@"token"]]=n;
    for (NSDictionary *feature in features) {
        NSMutableSet *seen=[NSMutableSet set];
        for (NSDictionary *cr in feature[@"controls"]?:@[]) for (NSDictionary *a in cr[@"actions"]?:@[]) {
            NSString *t=a[@"targetToken"]?:@""; if (!t.length || [seen containsObject:t]) continue; [seen addObject:t];
            targetFeatureUse[t]=@([targetFeatureUse[t] unsignedIntegerValue]+1U);
        }
    }

    NSMutableArray *outFeatures=[NSMutableArray array]; NSUInteger seededActions=0,sharedBlocks=0,ownedBlocks=0,entryBranches=0,entryCalls=0;
    for (NSDictionary *feature in features) {
        NSMutableArray *featureOwned=[NSMutableArray array],*sharedTarget=[NSMutableArray array],*actionResults=[NSMutableArray array];
        for (NSDictionary *cr in feature[@"controls"]?:@[]) {
            NSString *controlToken=cr[@"token"]?:@""; NSDictionary *control=controlByToken[controlToken]?:@{};
            [featureOwned addObjectsFromArray:HFABPBlocksFromFields(control[@"objectFields"],controlToken,@"feature-control-ivar")];
            for (NSDictionary *a in cr[@"actions"]?:@[]) {
                NSString *targetToken=a[@"targetToken"]?:@""; BOOL shared=[targetFeatureUse[targetToken] unsignedIntegerValue]>1;
                NSDictionary *targetNode=nodeByToken[targetToken]?:@{};
                NSArray *targetBlocks=HFABPBlocksFromFields(targetNode[@"fields"],targetToken,shared?@"shared-action-target-ivar":@"exclusive-action-target-ivar");
                if (shared) [sharedTarget addObjectsFromArray:targetBlocks]; else [featureOwned addObjectsFromArray:targetBlocks];
                NSDictionary *impl=a[@"implementation"]?:@{}; uintptr_t ptr=HFABPParseHex(impl[@"runtimeVA"]);
                NSDictionary *ctx=@{ @"featureTitle":feature[@"title"]?:@"", @"targetToken":targetToken, @"senderToken":controlToken, @"selector":a[@"selector"]?:@"", @"event":a[@"event"]?:@"" };
                NSDictionary *prov=ptr?HFAMapResolveHandlerBranchProvenance((const void *)ptr,loadedMenuPath,ctx):@{};
                if (ptr) ++seededActions; entryBranches += [prov[@"entryDerivedBranchCount"] unsignedIntegerValue]; entryCalls += [prov[@"entryDerivedCallCount"] unsignedIntegerValue];
                [actionResults addObject:@{ @"event":a[@"event"]?:@"", @"selector":a[@"selector"]?:@"", @"targetToken":targetToken, @"targetSharedAcrossFeatures":@(shared), @"targetFeatureUseCount":targetFeatureUse[targetToken]?:@0, @"implementation":impl, @"entrySeededProvenance":prov?:@{} }];
            }
        }
        NSArray *owned=HFABPUniqueBlocks(featureOwned),*shared=HFABPUniqueBlocks(sharedTarget); ownedBlocks+=owned.count; sharedBlocks+=shared.count;
        [outFeatures addObject:@{ @"title":feature[@"title"]?:@"", @"normalizedTitle":feature[@"normalizedTitle"]?:@"", @"identifiers":feature[@"identifiers"]?:@[], @"featureOwnedBlocks":owned, @"sharedTargetBlocks":shared, @"actionProvenance":actionResults, @"sharedTargetBlocksAreNotFeatureOwned":@YES, @"analysisOnly":@YES, @"canonicalEligible":@NO }];
    }
    NSDictionary *result=@{ @"schema":@"com.hfa.feature-branch-provenance/v1", @"buildVersion":@"2.5.15-dev", @"componentVersion":@"2.5.15-dev-shared-target-branch-provenance", @"policy":@"ENTRY-SEEDED-X0-X1-X2-SHARED-TARGET-DOWNGRADE", @"menuImage":loadedMenuPath.lastPathComponent?:@"", @"menuPath":loadedMenuPath?:@"", @"summary":@{ @"featureCount":@(outFeatures.count), @"seededActionCount":@(seededActions), @"featureOwnedBlockCount":@(ownedBlocks), @"sharedTargetBlockCount":@(sharedBlocks), @"entryDerivedBranchCount":@(entryBranches), @"entryDerivedCallCount":@(entryCalls) }, @"targetFeatureUseCounts":targetFeatureUse, @"features":outFeatures, @"rules":@{ @"sharedActionTargetBlockDowngraded":@YES, @"controlOwnedBlockAccepted":@YES, @"exclusiveTargetBlockAccepted":@YES, @"entryRegistersSeeded":@[ @"x0-target/self", @"x1-_cmd", @"x2-sender/control" ] }, @"safety":@{ @"unknownSelectorInvoked":@NO, @"actionInvoked":@NO, @"blockInvoked":@NO, @"hookInstalled":@NO, @"memoryWritten":@NO, @"gameStateWritten":@NO } };
    HFADiagnosticsLog(@"feature-branch-provenance",@"complete",result[@"summary"]);
    return result;
}

BOOL HFAMapPersistFeatureBranchProvenance(NSDictionary *result, NSError **error) {
    if (!result) return NO; NSData *data=[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:error]; if(!data)return NO;
    NSString *documents=[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES) firstObject];
    return [data writeToFile:[documents stringByAppendingPathComponent:HFAOutputFileName(@"FeatureBranchProvenance.json")] options:NSDataWritingAtomic error:error];
}

static void HFABPProcessInventory(void) {
    static NSString *lastDigest;
    NSString *documents=[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES) firstObject]; NSString *path=[documents stringByAppendingPathComponent:HFAOutputFileName(@"LoadedMenuFeatureInventory.json")];
    NSData *data=[NSData dataWithContentsOfFile:path]; if(!data.length)return; NSDictionary *attrs=[[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil]; NSString *digest=[NSString stringWithFormat:@"%lu:%@",(unsigned long)data.length,attrs.fileModificationDate?:@""]; if([digest isEqualToString:lastDigest])return;
    NSDictionary *inventory=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil]; if(![inventory isKindOfClass:NSDictionary.class])return; NSString *menuPath=inventory[@"menuPath"]?:@""; if(!menuPath.length)return;
    NSError *error=nil; NSDictionary *result=HFAMapBuildFeatureBranchProvenance(menuPath,inventory,&error); if(result&&HFAMapPersistFeatureBranchProvenance(result,&error)){[lastDigest release];lastDigest=[digest copy];HFADiagnosticsLog(@"feature-branch-provenance",@"persisted",result[@"summary"]?:@{});} else if(error) HFADiagnosticsLog(@"feature-branch-provenance",@"failed",@{ @"error":error.localizedDescription?:@"unknown" });
}

__attribute__((constructor)) static void HFAFeatureBranchProvenanceConstructor(void) {
    static dispatch_source_t timer; dispatch_queue_t q=dispatch_get_global_queue(QOS_CLASS_UTILITY,0); timer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,q); dispatch_source_set_timer(timer,dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.25*NSEC_PER_SEC)),(uint64_t)(1.25*NSEC_PER_SEC),(uint64_t)(0.1*NSEC_PER_SEC)); dispatch_source_set_event_handler(timer,^{HFABPProcessInventory();}); dispatch_resume(timer);
}

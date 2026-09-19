#import "HFAMapCore.h"
#import "ZPImageProbe.h"
#import "ZPResolver.h"
#import "ZPDescriptorObserver.h"
#import "ZPFeatureResolver.h"
#import "ZPContainerResolver.h"
#import "ZPEvidenceGraph.h"
#import "ZPAppIdentity.h"
#import "HFAMapDiagnostics.h"

static BOOL gHFAScanning;
static dispatch_queue_t ZPWorker(void){static dispatch_queue_t q;static dispatch_once_t once;dispatch_once(&once,^{q=dispatch_queue_create("com.hfa.zpatchig.worker",DISPATCH_QUEUE_SERIAL);});return q;}
static NSString *ZPDocs(void){return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES) firstObject];}
static void ZPWriteJSON(id object,NSString *suffix){NSData*d=[NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingPrettyPrinted error:nil];if(d)[d writeToFile:[ZPDocs() stringByAppendingPathComponent:ZPLogFilename(suffix)] atomically:YES];}
static void ZPWriteEvents(NSArray *events){NSMutableData*d=[NSMutableData data];for(NSDictionary*e in events){NSData*l=[NSJSONSerialization dataWithJSONObject:e options:0 error:nil];if(l){[d appendData:l];[d appendBytes:"\n" length:1];}}[d writeToFile:[ZPDocs() stringByAppendingPathComponent:ZPLogFilename(@"Process.jsonl")] atomically:YES];}
static NSDictionary *ZPSelect(NSArray<NSDictionary*>*c,NSString **reason){if(!c.count){if(reason)*reason=@"no-menu-candidate";return nil;}NSDictionary*f=c.firstObject;if([f[@"score"]unsignedIntValue]<70){if(reason)*reason=@"weak-family-fingerprint";return nil;}if(c.count>1){NSInteger a=[f[@"score"]integerValue],b=[c[1][@"score"]integerValue];if(a-b<10){if(reason)*reason=@"ambiguous-top-candidates";return nil;}}return f;}
static NSDictionary *ZPCaptureContainersOnMain(NSString *image){__block NSDictionary *snapshot=@{};void (^block)(void)=^{snapshot=ZPContainerCaptureSeeds(image,NSDate.date.timeIntervalSince1970+0.35);};if(NSThread.isMainThread)block();else dispatch_sync(dispatch_get_main_queue(),block);return snapshot?:@{};}
void HFAMapRunBoundedScan(void (^completion)(NSDictionary *summary)){
 @synchronized(NSObject.class){if(gHFAScanning){if(completion)completion(@{@"status":@"busy"});return;}gHFAScanning=YES;}
 dispatch_async(ZPWorker(),^{NSTimeInterval started=NSDate.date.timeIntervalSince1970;ZPEvidenceGraphReset();ZPFeatureResolverReset();NSString*session=HFADiagnosticsBeginSession();NSMutableArray*events=[NSMutableArray array];NSDictionary*appIdentity=ZPAppIdentity();[events addObject:@{@"time":@(started),@"stage":@"scan",@"status":@"start",@"version":@"zpatchig-v0.4.1",@"budgetMs":@6000,@"appIdentity":appIdentity}];NSArray*candidates=ZPDiscoverMenuImages(started+2.0,events);NSString*reason=nil;NSDictionary*selected=ZPSelect(candidates,&reason);NSDictionary*analysis=nil;
 if(!selected){analysis=@{@"schema":@"com.hfa.zpatchig.analysis/v4",@"version":@"0.4.1",@"status":@"incomplete",@"session":session,@"appIdentity":appIdentity,@"reason":reason?:@"selection-failed",@"candidates":candidates,@"uiFeatures":@[],@"containerFeatures":@[],@"descriptorEvidence":@[],@"observations":@[],@"validatedFeatures":@[],@"evidenceGraph":ZPEvidenceGraphSnapshot()};}
 else{
   NSDictionary*resolved=ZPResolveCandidate(selected,started+4.5,events);
   // v0.4.1 crash hotfix: do not run the legacy UI getter resolver here. The
   // proven v2.2.3 path is selector-free for feature identity and treats UI as
   // auxiliary seed evidence only.
   NSArray*uiFeatures=@[];
   HFADiagnosticsLog(@"container-capture",@"begin",@{@"image":selected[@"image"]?:@"?"});
   NSDictionary*containerSnapshot=ZPCaptureContainersOnMain(selected[@"image"]?:@"");
   HFADiagnosticsLog(@"container-capture",@"complete",containerSnapshot[@"metrics"]?:@{});
   HFADiagnosticsLog(@"container-resolve",@"begin",@{@"seedCount":@([containerSnapshot[@"seeds"] count])});
   NSDictionary*containerResult=ZPContainerResolve(selected[@"image"]?:@"",containerSnapshot,started+5.2);
   HFADiagnosticsLog(@"container-resolve",containerResult[@"status"]?:@"?",containerResult[@"metrics"]?:@{});
   NSArray*containerFeatures=containerResult[@"registry"]?:@[];NSArray*descriptorEvidence=containerResult[@"descriptorEvidence"]?:@[];
   [events addObject:@{@"time":@(NSDate.date.timeIntervalSince1970),@"stage":@"evidence-graph",@"status":containerResult[@"status"]?:@"?",@"uiFeatureCount":@(uiFeatures.count),@"containerFeatureCount":@(containerFeatures.count),@"descriptorEvidenceCount":@(descriptorEvidence.count)}];
   NSDictionary*descriptor=resolved[@"descriptor"]?:@{};NSDictionary*observer=descriptor.count?ZPDescriptorObserverArm(selected,descriptor,10.0):@{@"status":@"not-armed",@"reason":@"descriptor-missing"};[events addObject:@{@"time":@(NSDate.date.timeIntervalSince1970),@"stage":@"descriptor-observer",@"status":observer[@"status"]?:@"?",@"details":observer}];NSDictionary *graph=ZPEvidenceGraphSnapshot();analysis=@{@"schema":@"com.hfa.zpatchig.analysis/v4",@"version":@"0.4.1",@"status":resolved[@"status"]?:@"analysis-only",@"session":session,@"appIdentity":appIdentity,@"candidate":selected,@"family":resolved[@"family"]?:@"unknown",@"descriptor":descriptor,@"uiFeatures":uiFeatures,@"containerFeatures":containerFeatures,@"descriptorEvidence":descriptorEvidence,@"containerMetrics":containerResult[@"metrics"]?:@{},@"descriptorObserver":observer,@"observations":resolved[@"observations"]?:@[],@"validatedFeatures":resolved[@"validatedFeatures"]?:@[],@"canonicalEligible":resolved[@"canonicalEligible"]?:@NO,@"canonicalReason":resolved[@"canonicalReason"]?:@"unknown",@"evidenceGraph":graph};ZPWriteJSON(graph,@"EvidenceGraph.json");}
 ZPWriteJSON(analysis,@"Analysis.json");ZPWriteEvents(events);HFADiagnosticsFinishSession(analysis[@"status"],@{@"family":analysis[@"family"]?:@"unknown",@"uiFeatures":@([analysis[@"uiFeatures"]count]),@"containerFeatures":@([analysis[@"containerFeatures"]count]),@"descriptorEvidence":@([analysis[@"descriptorEvidence"]count]),@"observations":@([analysis[@"observations"]count]),@"validated":@([analysis[@"validatedFeatures"]count]),@"observer":analysis[@"descriptorObserver"]?:@{}});dispatch_async(dispatch_get_main_queue(),^{@synchronized(NSObject.class){gHFAScanning=NO;}if(completion)completion(analysis);});});
}

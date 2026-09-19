#import "HFAMapCore.h"
#import "ZPImageProbe.h"
#import "ZPResolver.h"
#import "HFAMapDiagnostics.h"

static BOOL gHFAScanning;
static dispatch_queue_t ZPWorker(void) {
    static dispatch_queue_t q; static dispatch_once_t once;
    dispatch_once(&once, ^{ q = dispatch_queue_create("com.hfa.zpatchig.worker", DISPATCH_QUEUE_SERIAL); });
    return q;
}
static NSString *ZPDocs(void) { return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject]; }
static void ZPWriteJSON(id object, NSString *name) {
    NSData *d=[NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingPrettyPrinted error:nil];
    if (d) [d writeToFile:[ZPDocs() stringByAppendingPathComponent:name] atomically:YES];
}
static void ZPWriteEvents(NSArray *events) {
    NSMutableData *d=[NSMutableData data];
    for (NSDictionary *e in events) { NSData *l=[NSJSONSerialization dataWithJSONObject:e options:0 error:nil]; if(l){[d appendData:l];[d appendBytes:"\n" length:1];} }
    [d writeToFile:[ZPDocs() stringByAppendingPathComponent:@"ZPatchIG_Process.jsonl"] atomically:YES];
}
static NSDictionary *ZPSelect(NSArray<NSDictionary *> *candidates, NSString **reason) {
    if (!candidates.count) { if(reason)*reason=@"no-menu-candidate"; return nil; }
    NSDictionary *first=candidates.firstObject;
    if ([first[@"score"] unsignedIntValue] < 70) { if(reason)*reason=@"weak-family-fingerprint"; return nil; }
    if (candidates.count>1) {
        NSInteger a=[first[@"score"] integerValue], b=[candidates[1][@"score"] integerValue];
        if (a-b<10) { if(reason)*reason=@"ambiguous-top-candidates"; return nil; }
    }
    return first;
}
void HFAMapRunBoundedScan(void (^completion)(NSDictionary *summary)) {
    @synchronized(NSObject.class) { if(gHFAScanning){ if(completion) completion(@{@"status":@"busy"}); return; } gHFAScanning=YES; }
    dispatch_async(ZPWorker(), ^{
        NSTimeInterval started=NSDate.date.timeIntervalSince1970;
        NSString *session=HFADiagnosticsBeginSession();
        NSMutableArray *events=[NSMutableArray array];
        [events addObject:@{@"time":@(started),@"stage":@"scan",@"status":@"start",@"version":@"zpatchig-v0.1.1",@"budgetMs":@5000}];
        NSArray *candidates=ZPDiscoverMenuImages(started+2.0,events);
        NSString *reason=nil; NSDictionary *selected=ZPSelect(candidates,&reason);
        NSDictionary *analysis=nil;
        if (!selected) {
            analysis=@{@"schema":@"com.hfa.zpatchig.analysis/v1",@"version":@"0.1.1",@"status":@"incomplete",
                       @"session":session,@"reason":reason?:@"selection-failed",@"candidates":candidates,
                       @"observations":@[],@"validatedFeatures":@[]};
        } else {
            NSDictionary *resolved=ZPResolveCandidate(selected,started+4.5,events);
            analysis=@{@"schema":@"com.hfa.zpatchig.analysis/v1",@"version":@"0.1.1",
                       @"status":resolved[@"status"]?:@"analysis-only",@"session":session,
                       @"candidate":selected,@"family":resolved[@"family"]?:@"unknown",
                       @"descriptor":resolved[@"descriptor"]?:@{},@"observations":resolved[@"observations"]?:@[],
                       @"validatedFeatures":resolved[@"validatedFeatures"]?:@[],
                       @"canonicalEligible":resolved[@"canonicalEligible"]?:@NO,
                       @"canonicalReason":resolved[@"canonicalReason"]?:@"unknown"};
        }
        ZPWriteJSON(analysis,@"ZPatchIG_Analysis.json"); ZPWriteEvents(events);
        HFADiagnosticsFinishSession(analysis[@"status"],@{@"family":analysis[@"family"]?:@"unknown",
                                   @"observations":@([analysis[@"observations"] count]),@"validated":@([analysis[@"validatedFeatures"] count])});
        dispatch_async(dispatch_get_main_queue(), ^{ @synchronized(NSObject.class){gHFAScanning=NO;} if(completion)completion(analysis); });
    });
}

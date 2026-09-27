from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
UI=Path('hfamap/src/HFAMapCyberUI.m')
s=TRACE.read_text()


def function_span(text, signature):
    start=text.find(signature)
    if start<0: raise SystemExit(f'missing function: {signature}')
    brace=text.find('{',start)
    if brace<0: raise SystemExit(f'missing brace: {signature}')
    depth=0; instr=False; esc=False
    for i in range(brace,len(text)):
        ch=text[i]
        if instr:
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch=='"': instr=False
            continue
        if ch=='"': instr=True; continue
        if ch=='{': depth+=1
        elif ch=='}':
            depth-=1
            if depth==0: return start,i+1
    raise SystemExit(f'unterminated function: {signature}')

for required in ['HFA0312AuditDirectory','HFA0312WriteAudit','HFAWritePatchPackage','HFAPatchTraceFinalizeScan','HFAAnalyzerV02ScanSelectedImage']:
    if required not in s: raise SystemExit('v0313 prerequisite missing '+required)

# Package/audit functions need these counters before their definitions.
global_anchor='static NSString *HFA0312AuditDirectory(void) {'
globals=r'''static NSUInteger gHFA0313AnalyzerStaticCount=0;
static NSUInteger gHFA0313AnalyzerMatchedCount=0;
static NSUInteger gHFA0313AnalyzerBridgedCount=0;
static BOOL gHFA0313AnalyzerAvailable=NO;
static BOOL gHFA0313LedgerParity=NO;
'''
if 'gHFA0313AnalyzerStaticCount' not in s:
    if global_anchor not in s: raise SystemExit('v0313 global anchor missing')
    s=s.replace(global_anchor,globals+'\n'+global_anchor,1)

# Replace audit writer: keep selection accounting separate from physical emission.
aa,ab=function_span(s,'static void HFA0312WriteAudit(NSArray *ledger,NSArray *featureDispositions,NSArray *conflicts,NSArray *features,NSDictionary *targets,NSString *packageStatus,NSString *rootPath,NSString *mirrorPath)')
new_audit=r'''static void HFA0312WriteAudit(NSArray *ledger,NSArray *featureDispositions,NSArray *conflicts,NSArray *features,NSDictionary *targets,NSString *packageStatus,NSString *rootPath,NSString *mirrorPath){
    NSString *dir=HFA0312AuditDirectory();NSString *path=[dir stringByAppendingPathComponent:@"HFAMap_StaticCanonical_v0313.json"];
    NSUInteger selected=0,excluded=0,conflicted=0,candidate=0;NSMutableArray *finalLedger=[NSMutableArray arrayWithCapacity:ledger.count];BOOL emittedPackage=[packageStatus isEqual:@"exported"];
    for(NSDictionary *raw in ledger?:@[]){NSMutableDictionary *e=[raw mutableCopy];NSString *st=e[@"status"]?:@"";if([st isEqual:@"exported"]){selected++;e[@"selectionStatus"]=@"selected";e[@"packageOutcome"]=emittedPackage?@"emitted":([packageStatus isEqual:@"blocked-conflict"]?@"blocked-by-package-conflict":@"not-emitted");}else if([st isEqual:@"conflict"]){conflicted++;e[@"selectionStatus"]=@"conflict";e[@"packageOutcome"]=@"not-emitted";}else if([st isEqual:@"candidate"]){candidate++;e[@"selectionStatus"]=@"candidate";e[@"packageOutcome"]=@"not-emitted";}else{excluded++;e[@"selectionStatus"]=@"excluded";e[@"packageOutcome"]=@"not-emitted";}[finalLedger addObject:e];}
    NSUInteger emitted=emittedPackage?selected:0;NSUInteger selectedPatches=HFA0312PatchCount(features),emittedPatches=emittedPackage?selectedPatches:0;
    NSNumber *size=@0;if(rootPath.length&&[[NSFileManager defaultManager] fileExistsAtPath:rootPath]){NSDictionary *a=[[NSFileManager defaultManager] attributesOfItemAtPath:rootPath error:nil];if([a[NSFileSize] isKindOfClass:NSNumber.class])size=a[NSFileSize];}
    NSInteger silent=(NSInteger)gHFA0313AnalyzerStaticCount-(NSInteger)ledger.count;if(silent<0)silent=0;
    NSDictionary *root=@{@"schema":@"com.hfa.static-canonical-audit/v0.3.13",@"policy":@"fail-closed-analyzer-ledger-parity",@"packageStatus":packageStatus?:@"unknown",@"packageRootPath":rootPath?:@"",@"packageMirrorPath":mirrorPath?:@"",@"packageSize":size,@"packageFeatureCount":@(features.count),@"packagePatchCount":@(selectedPatches),@"emittedPatchCount":@(emittedPatches),@"targetCount":@(targets.count),@"analyzerAvailable":@(gHFA0313AnalyzerAvailable),@"analyzerStaticCount":@(gHFA0313AnalyzerStaticCount),@"analyzerMatchedCount":@(gHFA0313AnalyzerMatchedCount),@"analyzerBridgedCount":@(gHFA0313AnalyzerBridgedCount),@"ledgerParity":@(gHFA0313LedgerParity),@"ledgerCount":@(ledger.count),@"selectedCount":@(selected),@"emittedCount":@(emitted),@"exportedCount":@(selected),@"excludedCount":@(excluded),@"conflictCount":@(conflicted),@"candidateCount":@(candidate),@"silentlyDropped":@(silent),@"ledger":finalLedger,@"featureDispositions":featureDispositions?:@[],@"conflicts":conflicts?:@[]};
    NSError *err=nil;NSData *json=[NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:&err];if(json&&[json writeToFile:path options:NSDataWritingAtomic error:&err])HFALog("[STATIC-AUDIT] status=pass path=%s analyzer=%u ledger=%u matched=%u bridged=%u parity=%u selected=%u emitted=%u excluded=%u conflicts=%u patches=%u emittedPatches=%u\n",path.UTF8String,(unsigned)gHFA0313AnalyzerStaticCount,(unsigned)ledger.count,(unsigned)gHFA0313AnalyzerMatchedCount,(unsigned)gHFA0313AnalyzerBridgedCount,gHFA0313LedgerParity?1:0,(unsigned)selected,(unsigned)emitted,(unsigned)excluded,(unsigned)conflicted,(unsigned)selectedPatches,(unsigned)emittedPatches);else HFALog("[STATIC-AUDIT] status=fail reason=%s\n",err.localizedDescription.UTF8String?:"json");
}'''
s=s[:aa]+new_audit+s[ab:]

# Helper layer is inserted after package/audit helpers and before the finalizer.
final_anchor='unsigned HFAPatchTraceFinalizeScan(void) {'
helper=r'''
static NSArray *HFA0313LoadAnalyzerStaticBackends(void){
    NSString *path=[HFA0312AuditDirectory() stringByAppendingPathComponent:@"HFAMap_RuntimeAnalyzer_v0311.json"];NSData *data=[NSData dataWithContentsOfFile:path];if(!data.length)return nil;NSError *err=nil;NSDictionary *root=[NSJSONSerialization JSONObjectWithData:data options:0 error:&err];if(![root isKindOfClass:NSDictionary.class])return nil;NSArray *all=[root[@"backends"] isKindOfClass:NSArray.class]?root[@"backends"]:@[];NSMutableArray *out=[NSMutableArray array];for(NSDictionary *b in all){if(![b isKindOfClass:NSDictionary.class])continue;if(![b[@"backendType"] isEqual:@"static-patch"])continue;[out addObject:b];}return out;
}
static uintptr_t HFA0313RuntimeAddressForTarget(NSString *target,NSString *offset){
    if(!target.length||!offset.length)return 0;int idx=[target isEqual:@"main"]?0:HFAImageIndexForName(target.UTF8String);if(idx<0)return 0;const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header((uint32_t)idx);if(!h||h->magic!=MH_MAGIC_64)return 0;char *end=NULL;uint64_t raw=strtoull(offset.UTF8String,&end,16);if(!end||*end)return 0;intptr_t slide=_dyld_get_image_vmaddr_slide((uint32_t)idx);uint64_t minVM=UINT64_MAX;BOOL preferred=NO;const uint8_t *cur=(const uint8_t*)(h+1);for(uint32_t i=0;i<h->ncmds;i++){const struct load_command *lc=(const struct load_command*)cur;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *seg=(const struct segment_command_64*)cur;if(strcmp(seg->segname,"__PAGEZERO")&&seg->vmsize&&seg->vmaddr<minVM)minVM=seg->vmaddr;if(seg->vmsize&&raw>=seg->vmaddr&&raw<seg->vmaddr+seg->vmsize)preferred=YES;}cur+=lc->cmdsize;}if(preferred)return (uintptr_t)((int64_t)raw+slide);if(minVM!=UINT64_MAX)return (uintptr_t)((int64_t)(minVM+raw)+slide);return 0;
}
static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates){
    gHFA0313AnalyzerStaticCount=backends.count;gHFA0313AnalyzerMatchedCount=0;gHFA0313AnalyzerBridgedCount=0;NSMutableDictionary *runtimeToLedger=[NSMutableDictionary dictionary];
    for(NSDictionary *c in candidates){uintptr_t ra=HFA0313RuntimeAddressForTarget(c[@"target"],c[@"offset"]);if(!ra)continue;runtimeToLedger[[NSString stringWithFormat:@"%llX",(unsigned long long)ra]]=c[@"ledgerIndex"]?:@0;}
    for(NSDictionary *b in backends){NSDictionary *tr=[b[@"targetResolution"] isKindOfClass:NSDictionary.class]?b[@"targetResolution"]:@{};uintptr_t ra=(uintptr_t)[tr[@"runtimeAddress"] unsignedLongLongValue];NSString *rk=ra?[NSString stringWithFormat:@"%llX",(unsigned long long)ra]:@"";NSNumber *existing=rk.length?runtimeToLedger[rk]:nil;if(existing){NSUInteger li=existing.unsignedIntegerValue;if(li<ledger.count){NSMutableDictionary *e=ledger[li];e[@"analyzerMatched"]=@YES;e[@"analyzerBackendId"]=b[@"backendId"]?:@0;e[@"family"]=b[@"family"]?:@"";e[@"descriptorRVA"]=b[@"descriptorRVA"]?:@"";e[@"patchDescriptorRVA"]=b[@"patchDescriptorRVA"]?:@"";e[@"analyzerTargetRVA"]=b[@"targetRVA"]?:@"";gHFA0313AnalyzerMatchedCount++;}continue;}
        NSMutableDictionary *e=[NSMutableDictionary dictionary];e[@"source"]=@"runtime-analyzer-binary-first";e[@"analyzerMatched"]=@NO;e[@"analyzerBackendId"]=b[@"backendId"]?:@0;e[@"family"]=b[@"family"]?:@"";e[@"descriptorRVA"]=b[@"descriptorRVA"]?:@"";e[@"patchDescriptorRVA"]=b[@"patchDescriptorRVA"]?:@"";e[@"targetRVA"]=b[@"targetRVA"]?:@"";e[@"offset"]=b[@"targetRVA"]?:@"";e[@"targetUUID"]=b[@"targetUUID"]?:@"";e[@"original"]=b[@"original"]?:@"";e[@"enabled"]=b[@"enabled"]?:@"";NSString *image=b[@"targetImage"]?:tr[@"image"]?:@"";NSString *mainName=NSBundle.mainBundle.executablePath.lastPathComponent?:@"";e[@"target"]=[image isEqual:mainName]?@"main":image;e[@"canonicalEligible"]=b[@"canonicalEligible"]?:@NO;e[@"key"]=@"";e[@"featureId"]=@"";e[@"ownershipSource"]=@"runtime-analyzer-unowned";NSString *reason=@"unowned-static-backend";if(![tr[@"status"] isEqual:@"unique"])reason=@"analyzer-target-not-unique";else if(![b[@"canonicalEligible"] boolValue])reason=@"analyzer-noncanonical-static";else if(![e[@"original"] length]||![e[@"enabled"] length])reason=@"analyzer-bytes-incomplete";e[@"status"]=@"excluded";e[@"reason"]=reason;[ledger addObject:e];gHFA0313AnalyzerBridgedCount++;HFALog("[STATIC-BRIDGE] backend=%u family=%s target=%s offset=%s status=excluded reason=%s\n",[e[@"analyzerBackendId"] unsignedIntValue],[e[@"family"] UTF8String]?:"?",[e[@"target"] UTF8String]?:"?",[e[@"offset"] UTF8String]?:"?",reason.UTF8String?:"?");
    }
    gHFA0313LedgerParity=gHFA0313AnalyzerAvailable&&gHFA0313AnalyzerStaticCount==ledger.count&&(gHFA0313AnalyzerMatchedCount+gHFA0313AnalyzerBridgedCount)==gHFA0313AnalyzerStaticCount;HFALog("[V0313-LEDGER-BRIDGE] analyzer=%u matched=%u bridged=%u ledger=%u parity=%u\n",(unsigned)gHFA0313AnalyzerStaticCount,(unsigned)gHFA0313AnalyzerMatchedCount,(unsigned)gHFA0313AnalyzerBridgedCount,(unsigned)ledger.count,gHFA0313LedgerParity?1:0);
}
'''
if 'HFA0313BridgeAnalyzerStaticBackends' not in s:
    if final_anchor not in s: raise SystemExit('v0313 finalizer anchor missing')
    s=s.replace(final_anchor,helper+'\n'+final_anchor,1)

# Analyzer must run before canonical ledger is audited.
old='NSMutableArray *ledger=[NSMutableArray array],*candidates=[NSMutableArray array],*conflicts=[NSMutableArray array];NSMutableDictionary *featureMeta=[NSMutableDictionary dictionary],*featurePatches=[NSMutableDictionary dictionary],*exportTargets=[NSMutableDictionary dictionary];NSMutableSet *groupKeys=[NSMutableSet set];unsigned validParts=0;'
new=old+'\n    unsigned analyzerNative=HFAAnalyzerV02ScanSelectedImage();NSArray *analyzerStatic=HFA0313LoadAnalyzerStaticBackends();gHFA0313AnalyzerAvailable=(analyzerStatic!=nil);HFALog("[V0313-ANALYZER-PREPASS] native=%u available=%u static=%u\\n",analyzerNative,gHFA0313AnalyzerAvailable?1:0,(unsigned)analyzerStatic.count);'
if old not in s: raise SystemExit('v0313 finalizer init anchor missing')
s=s.replace(old,new,1)

# Mark legacy source explicitly so analyzer-derived entries are distinguishable.
old_e='NSMutableDictionary *e=[NSMutableDictionary dictionary];e[@"descriptorIndex"]=@(i);'
new_e='NSMutableDictionary *e=[NSMutableDictionary dictionary];e[@"source"]=@"legacy-descriptor";e[@"descriptorIndex"]=@(i);'
if old_e not in s: raise SystemExit('v0313 legacy ledger anchor missing')
s=s.replace(old_e,new_e,1)

# Bridge after every legacy descriptor has been converted, but before target conflict audit.
bridge_anchor='    NSMutableDictionary *byTarget=[NSMutableDictionary dictionary];for(NSDictionary *c in candidates)'
if bridge_anchor not in s: raise SystemExit('v0313 conflict audit anchor missing')
s=s.replace(bridge_anchor,'    HFA0313BridgeAnalyzerStaticBackends(analyzerStatic?:@[],ledger,candidates);\n'+bridge_anchor,1)

# Rename final summary marker and include analyzer parity.
s=s.replace('[V0312-STATIC-CANONICAL] ledger=%u candidates=%u exported=%u excluded=%u conflicts=%u packageFeatures=%u packagePatches=%u','[V0313-STATIC-CANONICAL] analyzer=%u ledger=%u parity=%u candidates=%u exported=%u excluded=%u conflicts=%u packageFeatures=%u packagePatches=%u',1)
old_args='(unsigned)ledger.count,(unsigned)candidates.count,(unsigned)exported,(unsigned)excluded,(unsigned)conflicted,(unsigned)exportFeatures.count,(unsigned)HFA0312PatchCount(exportFeatures));HFAWritePatchPackage'
new_args='(unsigned)gHFA0313AnalyzerStaticCount,(unsigned)ledger.count,gHFA0313LedgerParity?1:0,(unsigned)candidates.count,(unsigned)exported,(unsigned)excluded,(unsigned)conflicted,(unsigned)exportFeatures.count,(unsigned)HFA0312PatchCount(exportFeatures));HFAWritePatchPackage'
if old_args not in s: raise SystemExit('v0313 summary args anchor missing')
s=s.replace(old_args,new_args,1)

# If analyzer/ledger parity is not provable, the package must fail closed.
status_anchor='NSString *rootPath=[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:name];NSString *mirrorPath=[HFA0312AuditDirectory() stringByAppendingPathComponent:name];NSString *status=@"not-exported";'
status_new=status_anchor+'\n    if(!gHFA0313AnalyzerAvailable||!gHFA0313LedgerParity){status=gHFA0313AnalyzerAvailable?@"blocked-ledger-parity":@"blocked-analyzer-unavailable";HFALog("[CANONICAL-CHECK] status=fail reason=%s analyzer=%u ledger=%u parity=%u\\n",status.UTF8String?:"?",(unsigned)gHFA0313AnalyzerStaticCount,(unsigned)ledger.count,gHFA0313LedgerParity?1:0);HFA0312WriteAudit(ledger,featureDispositions,conflicts,features,targets,status,@"",@"");return;}'
if status_anchor not in s: raise SystemExit('v0313 package status anchor missing')
s=s.replace(status_anchor,status_new,1)

TRACE.write_text(s)
ui=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.12 StaticCanonicalCompletion','HFAMap RuntimeAnalyzer v0.3.13 StaticBackendLedgerBridge')
UI.write_text(ui)

out=TRACE.read_text()
for req in ['HFA0313BridgeAnalyzerStaticBackends','runtime-analyzer-binary-first','unowned-static-backend','[STATIC-BRIDGE]','[V0313-ANALYZER-PREPASS]','[V0313-LEDGER-BRIDGE]','[V0313-STATIC-CANONICAL]','HFAMap_StaticCanonical_v0313.json','selectedCount','emittedCount','blocked-by-package-conflict','blocked-ledger-parity']:
    if req not in out: raise SystemExit('v0313 missing '+req)
print('v0.3.13 static backend ledger bridge applied')

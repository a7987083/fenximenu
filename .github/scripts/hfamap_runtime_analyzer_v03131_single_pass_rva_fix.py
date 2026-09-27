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

# v0.3.13 regression: v0.2 already inserted a full analyzer call in this same
# finalizer. Reuse the v0.3.13 prepass result instead of scanning the selected
# image a second time. This remains per-export; a later user export still runs a
# fresh prepass.
old_second='''unsigned v02Native=HFAAnalyzerV02ScanSelectedImage();
    HFALog("[V02-OWNERSHIP-FINALIZE] nativeCandidates=%u\\n",v02Native);'''
new_second='''unsigned v02Native=analyzerNative;
    HFALog("[V03131-ANALYZER-REUSE] nativeCandidates=%u source=canonical-prepass\\n",v02Native);'''
if s.count(old_second)!=1:
    raise SystemExit(f'v03131 second analyzer call: expected 1 match, got {s.count(old_second)}')
s=s.replace(old_second,new_second,1)

# The v0.3.13 runtime-address helper is retained for source compatibility, but
# the bridge below deliberately matches stable target identity + canonical RVA.
s=s.replace('static uintptr_t HFA0313RuntimeAddressForTarget(NSString *target,NSString *offset){',
            'static uintptr_t __attribute__((unused)) HFA0313RuntimeAddressForTarget(NSString *target,NSString *offset){',1)

sig='static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates)'
a,b=function_span(s,sig)
helper=r'''static NSString *HFA03131ImageUUIDForIndex(int idx){
    if(idx<0)return @"";const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header((uint32_t)idx);if(!h||h->magic!=MH_MAGIC_64)return @"";const uint8_t *cur=(const uint8_t*)(h+1);
    for(uint32_t i=0;i<h->ncmds;i++){const struct load_command *lc=(const struct load_command*)cur;if(!lc->cmdsize)break;if(lc->cmd==LC_UUID&&lc->cmdsize>=sizeof(struct uuid_command)){const struct uuid_command *u=(const struct uuid_command*)cur;const unsigned char *x=u->uuid;return [[NSString stringWithFormat:@"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",x[0],x[1],x[2],x[3],x[4],x[5],x[6],x[7],x[8],x[9],x[10],x[11],x[12],x[13],x[14],x[15]] uppercaseString];}cur+=lc->cmdsize;}return @"";
}
static BOOL HFA03131CanonicalTarget(NSString *target,NSString *offset,NSString *explicitUUID,NSString **identityOut,uint64_t *rvaOut){
    if(!target.length||!offset.length)return NO;int idx=[target isEqual:@"main"]?0:HFAImageIndexForName(target.UTF8String);if(idx<0)return NO;const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header((uint32_t)idx);if(!h||h->magic!=MH_MAGIC_64)return NO;char *end=NULL;uint64_t raw=strtoull(offset.UTF8String,&end,16);if(!end||*end)return NO;
    uint64_t minVM=UINT64_MAX;BOOL preferred=NO;const uint8_t *cur=(const uint8_t*)(h+1);for(uint32_t i=0;i<h->ncmds;i++){const struct load_command *lc=(const struct load_command*)cur;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *seg=(const struct segment_command_64*)cur;if(strcmp(seg->segname,"__PAGEZERO")&&seg->vmsize&&seg->vmaddr<minVM)minVM=seg->vmaddr;if(seg->vmsize&&raw>=seg->vmaddr&&raw<seg->vmaddr+seg->vmsize)preferred=YES;}cur+=lc->cmdsize;}if(minVM==UINT64_MAX)return NO;
    uint64_t rva=preferred?(raw-minVM):raw;NSString *identity=explicitUUID.length?[explicitUUID uppercaseString]:HFA03131ImageUUIDForIndex(idx);if(!identity.length){const char *p=_dyld_get_image_name((uint32_t)idx);identity=p?[NSString stringWithUTF8String:HFABase(p)]:target;}if(identityOut)*identityOut=identity?:@"";if(rvaOut)*rvaOut=rva;return YES;
}
static NSString *HFA03131MatchKey(NSString *identity,uint64_t rva,NSString *original,NSString *enabled){
    return [NSString stringWithFormat:@"%@|%llX|%@|%@",identity?:@"",(unsigned long long)rva,[original uppercaseString]?:@"",[enabled uppercaseString]?:@""];
}
static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates){
    gHFA0313AnalyzerStaticCount=backends.count;gHFA0313AnalyzerMatchedCount=0;gHFA0313AnalyzerBridgedCount=0;NSMutableDictionary *signatureToLedger=[NSMutableDictionary dictionary];
    for(NSDictionary *c in candidates){NSString *identity=nil;uint64_t rva=0;if(!HFA03131CanonicalTarget(c[@"target"],c[@"offset"],c[@"targetUUID"],&identity,&rva))continue;NSString *key=HFA03131MatchKey(identity,rva,c[@"original"]?:@"",c[@"enabled"]?:@"");NSMutableArray *q=signatureToLedger[key];if(!q){q=[NSMutableArray array];signatureToLedger[key]=q;}[q addObject:c[@"ledgerIndex"]?:@0];NSMutableDictionary *le=([c[@"ledgerIndex"] unsignedIntegerValue]<ledger.count)?ledger[[c[@"ledgerIndex"] unsignedIntegerValue]]:nil;if(le){le[@"canonicalTargetIdentity"]=identity?:@"";le[@"canonicalRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva];}}
    for(NSDictionary *b in backends){NSDictionary *tr=[b[@"targetResolution"] isKindOfClass:NSDictionary.class]?b[@"targetResolution"]:@{};NSString *image=b[@"targetImage"]?:tr[@"image"]?:@"";NSString *mainName=NSBundle.mainBundle.executablePath.lastPathComponent?:@"";NSString *target=[image isEqual:mainName]?@"main":image;NSString *identity=nil;uint64_t rva=0;BOOL normalized=HFA03131CanonicalTarget(target,b[@"targetRVA"]?:@"",b[@"targetUUID"]?:@"",&identity,&rva);NSString *key=normalized?HFA03131MatchKey(identity,rva,b[@"original"]?:@"",b[@"enabled"]?:@""):@"";NSMutableArray *q=key.length?signatureToLedger[key]:nil;NSNumber *existing=q.count?q.firstObject:nil;
        if(existing){[q removeObjectAtIndex:0];NSUInteger li=existing.unsignedIntegerValue;if(li<ledger.count){NSMutableDictionary *e=ledger[li];e[@"analyzerMatched"]=@YES;e[@"analyzerBackendId"]=b[@"backendId"]?:@0;e[@"family"]=b[@"family"]?:@"";e[@"descriptorRVA"]=b[@"descriptorRVA"]?:@"";e[@"patchDescriptorRVA"]=b[@"patchDescriptorRVA"]?:@"";e[@"analyzerTargetRVA"]=b[@"targetRVA"]?:@"";e[@"canonicalTargetIdentity"]=identity?:@"";e[@"canonicalRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva];e[@"analyzerMatchKey"]=@"identity+rva+original+enabled";gHFA0313AnalyzerMatchedCount++;}continue;}
        NSMutableDictionary *e=[NSMutableDictionary dictionary];e[@"source"]=@"runtime-analyzer-binary-first";e[@"analyzerMatched"]=@NO;e[@"analyzerBackendId"]=b[@"backendId"]?:@0;e[@"family"]=b[@"family"]?:@"";e[@"descriptorRVA"]=b[@"descriptorRVA"]?:@"";e[@"patchDescriptorRVA"]=b[@"patchDescriptorRVA"]?:@"";e[@"targetRVA"]=b[@"targetRVA"]?:@"";e[@"offset"]=b[@"targetRVA"]?:@"";e[@"targetUUID"]=b[@"targetUUID"]?:@"";e[@"original"]=b[@"original"]?:@"";e[@"enabled"]=b[@"enabled"]?:@"";e[@"target"]=target?:@"";e[@"canonicalTargetIdentity"]=identity?:@"";if(normalized)e[@"canonicalRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva];e[@"canonicalEligible"]=b[@"canonicalEligible"]?:@NO;e[@"key"]=@"";e[@"featureId"]=@"";e[@"ownershipSource"]=@"runtime-analyzer-unowned";NSString *reason=@"unowned-static-backend";if(!normalized)reason=@"target-rva-normalization-failed";else if(![tr[@"status"] isEqual:@"unique"])reason=@"analyzer-target-not-unique";else if(![b[@"canonicalEligible"] boolValue])reason=@"analyzer-noncanonical-static";else if(![e[@"original"] length]||![e[@"enabled"] length])reason=@"analyzer-bytes-incomplete";e[@"status"]=@"excluded";e[@"reason"]=reason;[ledger addObject:e];gHFA0313AnalyzerBridgedCount++;HFALog("[STATIC-BRIDGE] backend=%u family=%s target=%s offset=%s canonicalRVA=%s status=excluded reason=%s\\n",[e[@"analyzerBackendId"] unsignedIntValue],[e[@"family"] UTF8String]?:"?",[e[@"target"] UTF8String]?:"?",[e[@"offset"] UTF8String]?:"?",[e[@"canonicalRVA"] UTF8String]?:"?",reason.UTF8String?:"?");
    }
    gHFA0313LedgerParity=gHFA0313AnalyzerAvailable&&gHFA0313AnalyzerStaticCount==ledger.count&&(gHFA0313AnalyzerMatchedCount+gHFA0313AnalyzerBridgedCount)==gHFA0313AnalyzerStaticCount;HFALog("[V03131-LEDGER-BRIDGE] analyzer=%u matched=%u bridged=%u ledger=%u parity=%u matchKey=identity+rva+original+enabled\\n",(unsigned)gHFA0313AnalyzerStaticCount,(unsigned)gHFA0313AnalyzerMatchedCount,(unsigned)gHFA0313AnalyzerBridgedCount,(unsigned)ledger.count,gHFA0313LedgerParity?1:0);
}'''
s=s[:a]+helper+s[b:]

# Version the audit/markers without changing v0.3.13 semantics outside this hotfix.
s=s.replace('com.hfa.static-canonical-audit/v0.3.13','com.hfa.static-canonical-audit/v0.3.13.1')
s=s.replace('HFAMap_StaticCanonical_v0313.json','HFAMap_StaticCanonical_v03131.json')
s=s.replace('[V0313-ANALYZER-PREPASS]','[V03131-ANALYZER-PREPASS]')
s=s.replace('[V0313-STATIC-CANONICAL]','[V03131-STATIC-CANONICAL]')
TRACE.write_text(s)

ui=UI.read_text()
ui=ui.replace('HFAMap RuntimeAnalyzer v0.3.13 StaticBackendLedgerBridge','HFAMap RuntimeAnalyzer v0.3.13.1 SinglePassLedgerBridge')
UI.write_text(ui)

out=TRACE.read_text()
if out.count('HFAAnalyzerV02ScanSelectedImage();')!=1:
    raise SystemExit(f'v03131 full analyzer call count must be 1, got {out.count("HFAAnalyzerV02ScanSelectedImage();")}')
for req in ['[V03131-ANALYZER-REUSE]','[V03131-ANALYZER-PREPASS]','[V03131-LEDGER-BRIDGE]','[V03131-STATIC-CANONICAL]','identity+rva+original+enabled','canonicalTargetIdentity','canonicalRVA','HFAMap_StaticCanonical_v03131.json']:
    if req not in out: raise SystemExit('v03131 generated trace missing '+req)
print('v0.3.13.1 single-pass + canonical-RVA hotfix applied')

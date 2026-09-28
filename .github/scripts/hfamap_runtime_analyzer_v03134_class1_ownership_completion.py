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
            if depth==0:return start,i+1
    raise SystemExit(f'unterminated function: {signature}')

# Preserve the strongest ownership evidence available at descriptor registration time:
# the currently armed feature identifier and its exact *-switch key.
secret_sig='void HFARegisterPatchSecret(id owner, id wrapper, const char *kind)'
a,b=function_span(s,secret_sig)
secret=s[a:b]
old='    d->seenEvent = gEvent;\n'
new='''    d->seenEvent = gEvent;\n    if (!d->key[0] && gIdentifier[0] && gWantedKey[0]) {\n        snprintf(d->key, sizeof(d->key), "%s", gWantedKey);\n        HFALog("[V03134-EVENT-OWNERSHIP] event=%u identifier=%s key=%s owner=%p\\n",\n               gEvent, gIdentifier, d->key, owner);\n    }\n'''
if old not in secret: raise SystemExit('v03134 secret registration anchor missing')
secret=secret.replace(old,new,1)
s=s[:a]+secret+s[b:]

sig='static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates)'
a,b=function_span(s,sig)
bridge=r'''static uint64_t HFA03134HexRVA(id value){
    if(![value isKindOfClass:NSString.class]||![(NSString*)value length])return 0;char *end=NULL;uint64_t v=strtoull([(NSString*)value UTF8String],&end,16);return end&&!*end?v:0;
}
static uint64_t HFA03134WrapperSecretRVA(id wrapper,NSString **imageOut){
    if(!wrapper)return 0;SEL sel=sel_registerName("secret");Method m=class_getInstanceMethod(object_getClass(wrapper),sel);if(!m)return 0;void *p=((void *(*)(id,SEL))objc_msgSend)(wrapper,sel);if(!p)return 0;Dl_info info={0};if(!dladdr(p,&info)||!info.dli_fbase||!info.dli_fname)return 0;if(imageOut)*imageOut=[NSString stringWithUTF8String:HFABase(info.dli_fname)];return (uint64_t)((uintptr_t)p-(uintptr_t)info.dli_fbase);
}
static NSDictionary *HFA03134OwnershipForBackend(NSDictionary *backend){
    uint64_t descriptor=HFA03134HexRVA(backend[@"descriptorRVA"]),patchDescriptor=HFA03134HexRVA(backend[@"patchDescriptorRVA"]);if(!descriptor&&!patchDescriptor)return nil;
    NSMutableArray *matches=[NSMutableArray array];
    for(unsigned i=0;i<gDescriptorCount;i++){
        HFADescriptor *d=&gDescriptors[i];if(!d->key[0])continue;NSString *oi=nil,*pi=nil;uint64_t orva=HFA03134WrapperSecretRVA(d->offsetWrapper,&oi),prva=HFA03134WrapperSecretRVA(d->patchWrapper,&pi);unsigned exact=0;
        if(descriptor&&(descriptor==orva||descriptor==prva))exact++;
        if(patchDescriptor&&(patchDescriptor==orva||patchDescriptor==prva))exact++;
        if(!exact)continue;NSDictionary *ident=HFA0312FeatureIdentityForKey(d->key);if(!ident)continue;
        [matches addObject:@{@"descriptorIndex":@(i),@"featureId":ident[@"id"]?:@"",@"title":ident[@"title"]?:ident[@"id"]?:@"",@"key":[NSString stringWithUTF8String:d->key],@"offsetSecretRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)orva],@"patchSecretRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)prva],@"exactFieldMatches":@(exact),@"offsetImage":oi?:@"",@"patchImage":pi?:@""}];
    }
    if(matches.count!=1){HFALog("[V03134-OWNERSHIP] backend=%u status=%s matches=%u descriptor=%s patchDescriptor=%s\\n",[backend[@"backendId"] unsignedIntValue],matches.count?"ambiguous":"none",(unsigned)matches.count,[backend[@"descriptorRVA"] UTF8String]?:"?",[backend[@"patchDescriptorRVA"] UTF8String]?:"?");return nil;}
    NSDictionary *m=matches.firstObject;HFALog("[V03134-OWNERSHIP] backend=%u status=unique feature=%s key=%s descriptorIndex=%u exact=%u\\n",[backend[@"backendId"] unsignedIntValue],[m[@"featureId"] UTF8String]?:"?",[m[@"key"] UTF8String]?:"?",[m[@"descriptorIndex"] unsignedIntValue],[m[@"exactFieldMatches"] unsignedIntValue]);return m;
}
static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates){
    gHFA0313AnalyzerStaticCount=backends.count;gHFA0313AnalyzerMatchedCount=0;gHFA0313AnalyzerBridgedCount=0;NSMutableDictionary *signatureToLedger=[NSMutableDictionary dictionary];
    for(NSDictionary *c in candidates){NSString *identity=nil;uint64_t rva=0;if(!HFA03133CanonicalTarget(c[@"target"],c[@"offset"],c[@"targetUUID"],&identity,&rva))continue;NSString *key=HFA03131MatchKey(identity,rva,c[@"original"]?:@"",c[@"enabled"]?:@"");NSMutableArray *q=signatureToLedger[key];if(!q){q=[NSMutableArray array];signatureToLedger[key]=q;}[q addObject:c[@"ledgerIndex"]?:@0];NSUInteger li=[c[@"ledgerIndex"] unsignedIntegerValue];if(li<ledger.count){NSMutableDictionary *le=ledger[li];le[@"canonicalTargetIdentity"]=identity?:@"";le[@"canonicalRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva];}}
    for(NSDictionary *b in backends){NSDictionary *tr=[b[@"targetResolution"] isKindOfClass:NSDictionary.class]?b[@"targetResolution"]:@{};NSString *image=b[@"targetImage"]?:tr[@"image"]?:@"";NSString *mainName=NSBundle.mainBundle.executablePath.lastPathComponent?:@"";NSString *target=[image isEqual:mainName]?@"main":image;NSString *identity=nil;uint64_t rva=0;BOOL normalized=HFA03133CanonicalTarget(target,b[@"targetRVA"]?:@"",b[@"targetUUID"]?:@"",&identity,&rva);NSString *key=normalized?HFA03131MatchKey(identity,rva,b[@"original"]?:@"",b[@"enabled"]?:@""):@"";NSMutableArray *q=key.length?signatureToLedger[key]:nil;NSNumber *existing=q.count?q.firstObject:nil;
        if(existing){[q removeObjectAtIndex:0];NSUInteger li=existing.unsignedIntegerValue;if(li<ledger.count){NSMutableDictionary *e=ledger[li];e[@"analyzerMatched"]=@YES;e[@"analyzerBackendId"]=b[@"backendId"]?:@0;e[@"family"]=b[@"family"]?:@"";e[@"descriptorRVA"]=b[@"descriptorRVA"]?:@"";e[@"patchDescriptorRVA"]=b[@"patchDescriptorRVA"]?:@"";e[@"analyzerTargetRVA"]=b[@"targetRVA"]?:@"";e[@"canonicalTargetIdentity"]=identity?:@"";e[@"canonicalRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva];e[@"analyzerMatchKey"]=@"identity+rva+original+enabled";gHFA0313AnalyzerMatchedCount++;}continue;}
        NSMutableDictionary *e=[NSMutableDictionary dictionary];e[@"source"]=@"runtime-analyzer-binary-first";e[@"analyzerMatched"]=@NO;e[@"analyzerBackendId"]=b[@"backendId"]?:@0;e[@"family"]=b[@"family"]?:@"";e[@"descriptorRVA"]=b[@"descriptorRVA"]?:@"";e[@"patchDescriptorRVA"]=b[@"patchDescriptorRVA"]?:@"";e[@"targetRVA"]=b[@"targetRVA"]?:@"";e[@"offset"]=normalized?[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva]:(b[@"targetRVA"]?:@"");e[@"targetUUID"]=b[@"targetUUID"]?:@"";e[@"original"]=b[@"original"]?:@"";e[@"enabled"]=b[@"enabled"]?:@"";e[@"target"]=target?:@"";e[@"canonicalTargetIdentity"]=identity?:@"";if(normalized)e[@"canonicalRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva];e[@"canonicalEligible"]=b[@"canonicalEligible"]?:@NO;e[@"key"]=@"";e[@"featureId"]=@"";e[@"ownershipSource"]=@"runtime-analyzer-unowned";
        NSString *reason=@"unowned-static-backend";if(!normalized)reason=@"target-rva-normalization-failed";else if(![tr[@"status"] isEqual:@"unique"])reason=@"analyzer-target-not-unique";else if(![b[@"canonicalEligible"] boolValue])reason=@"analyzer-noncanonical-static";else if(![e[@"original"] length]||![e[@"enabled"] length])reason=@"analyzer-bytes-incomplete";
        NSDictionary *owner=nil;if([reason isEqual:@"unowned-static-backend"])owner=HFA03134OwnershipForBackend(b);
        NSUInteger li=ledger.count;
        if(owner){NSString *fid=owner[@"featureId"]?:@"",*ownerKey=owner[@"key"]?:@"";e[@"featureId"]=fid;e[@"title"]=owner[@"title"]?:fid;e[@"key"]=ownerKey;e[@"ownershipSource"]=@"wrapper-secret-rva+event-identifier";e[@"ownershipEvidence"]=owner;e[@"status"]=@"candidate";e[@"reason"]=@"awaiting-conflict-audit";[ledger addObject:e];NSString *exportImage=[target isEqual:@"main"]?@"@main":([image length]?image:target);[candidates addObject:@{@"ledgerIndex":@(li),@"featureId":fid,@"target":target?:@"",@"image":exportImage?:@"",@"offset":e[@"offset"]?:@"",@"original":e[@"original"]?:@"",@"enabled":e[@"enabled"]?:@"",@"targetUUID":e[@"targetUUID"]?:@""}];HFALog("[V03134-OWNERSHIP-BRIDGE] backend=%u feature=%s target=%s offset=%s status=candidate\\n",[e[@"analyzerBackendId"] unsignedIntValue],fid.UTF8String?:"?",target.UTF8String?:"?",[e[@"offset"] UTF8String]?:"?");}
        else{e[@"status"]=@"excluded";e[@"reason"]=reason;[ledger addObject:e];HFALog("[STATIC-BRIDGE] backend=%u family=%s target=%s offset=%s canonicalRVA=%s status=excluded reason=%s\\n",[e[@"analyzerBackendId"] unsignedIntValue],[e[@"family"] UTF8String]?:"?",[e[@"target"] UTF8String]?:"?",[e[@"offset"] UTF8String]?:"?",[e[@"canonicalRVA"] UTF8String]?:"?",reason.UTF8String?:"?");}
        gHFA0313AnalyzerBridgedCount++;
    }
    gHFA0313LedgerParity=gHFA0313AnalyzerAvailable&&gHFA0313AnalyzerStaticCount==ledger.count&&(gHFA0313AnalyzerMatchedCount+gHFA0313AnalyzerBridgedCount)==gHFA0313AnalyzerStaticCount;HFALog("[V03134-LEDGER-BRIDGE] analyzer=%u matched=%u bridged=%u ledger=%u parity=%u ownership=secret-rva+event-identifier\\n",(unsigned)gHFA0313AnalyzerStaticCount,(unsigned)gHFA0313AnalyzerMatchedCount,(unsigned)gHFA0313AnalyzerBridgedCount,(unsigned)ledger.count,gHFA0313LedgerParity?1:0);
}'''
s=s[:a]+bridge+s[b:]

s=s.replace('com.hfa.static-canonical-audit/v0.3.13.3','com.hfa.static-canonical-audit/v0.3.13.4')
s=s.replace('HFAMap_StaticCanonical_v03133.json','HFAMap_StaticCanonical_v03134.json')
s=s.replace('[V03133-ANALYZER-PREPASS]','[V03134-ANALYZER-PREPASS]')
s=s.replace('[V03133-STATIC-CANONICAL]','[V03134-STATIC-CANONICAL]')
TRACE.write_text(s)

ui=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.3 PageZeroRVAFix','HFAMap RuntimeAnalyzer v0.3.13.4 Class1OwnershipCompletion')
UI.write_text(ui)

out=TRACE.read_text()
for req in ['[V03134-EVENT-OWNERSHIP]','HFA03134WrapperSecretRVA','HFA03134OwnershipForBackend','wrapper-secret-rva+event-identifier','[V03134-OWNERSHIP-BRIDGE]','[V03134-LEDGER-BRIDGE]','[V03134-STATIC-CANONICAL]','HFAMap_StaticCanonical_v03134.json']:
    if req not in out: raise SystemExit('v03134 generated trace missing '+req)
if 'HFA03133CanonicalTarget' not in out or 'realSegment=strcmp(seg->segname,"__PAGEZERO")!=0' not in out:
    raise SystemExit('v03134 regressed v03133 PAGEZERO canonicalizer')
print('v0.3.13.4 Class1 ownership completion applied')

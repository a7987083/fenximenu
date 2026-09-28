from pathlib import Path

TRACE = Path('hfamap/src/HFAMapPatchExecutionTrace.m')


def function_span(text, signature):
    start = text.find(signature)
    if start < 0:
        raise SystemExit(f'missing function: {signature}')
    brace = text.find('{', start)
    if brace < 0:
        raise SystemExit(f'missing brace: {signature}')
    depth = 0
    instr = False
    esc = False
    for i in range(brace, len(text)):
        ch = text[i]
        if instr:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                instr = False
            continue
        if ch == '"':
            instr = True
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return start, i + 1
    raise SystemExit(f'unterminated function: {signature}')


s = TRACE.read_text()

sig = 'static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates)'
a, b = function_span(s, sig)

replacement = r'''static uint64_t HFA03134FirstXrefRVA(NSDictionary *backend){
    NSArray *x=[backend[@"xrefs"] isKindOfClass:NSArray.class]?backend[@"xrefs"]:@[];
    for(id v in x){uint64_t r=HFA03134HexRVA(v);if(r)return r;}
    return 0;
}
static NSDictionary *HFA03134ClusterOwnerRecord(NSDictionary *source,NSString *clusterId){
    if(!source)return nil;NSMutableDictionary *m=[source mutableCopy];m[@"source"]=@"static-xref-cluster";m[@"clusterId"]=clusterId?:@"";return m;
}
static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates){
    gHFA0313AnalyzerStaticCount=backends.count;gHFA0313AnalyzerMatchedCount=0;gHFA0313AnalyzerBridgedCount=0;
    NSMutableDictionary *signatureToLedger=[NSMutableDictionary dictionary];
    for(NSDictionary *c in candidates){NSString *identity=nil;uint64_t rva=0;if(!HFA03133CanonicalTarget(c[@"target"],c[@"offset"],c[@"targetUUID"],&identity,&rva))continue;NSString *key=HFA03131MatchKey(identity,rva,c[@"original"]?:@"",c[@"enabled"]?:@"");NSMutableArray *q=signatureToLedger[key];if(!q){q=[NSMutableArray array];signatureToLedger[key]=q;}[q addObject:c[@"ledgerIndex"]?:@0];NSUInteger li=[c[@"ledgerIndex"] unsignedIntegerValue];if(li<ledger.count){NSMutableDictionary *le=ledger[li];le[@"canonicalTargetIdentity"]=identity?:@"";le[@"canonicalRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva];}}

    // First pass: identify strong static owners and learn the natural intra-feature
    // xref spacing from already-proven multi-patch features. This is intentionally
    // sample-agnostic and never uses titles, bundle IDs, fixed RVAs or array order.
    NSMutableDictionary *strongOwnerByBackend=[NSMutableDictionary dictionary];
    NSMutableDictionary *featureXrefs=[NSMutableDictionary dictionary];
    NSMutableDictionary *probeQueues=[NSMutableDictionary dictionary];
    for(NSString *k in signatureToLedger)probeQueues[k]=[signatureToLedger[k] mutableCopy];
    for(NSDictionary *backend in backends){
        NSDictionary *tr=[backend[@"targetResolution"] isKindOfClass:NSDictionary.class]?backend[@"targetResolution"]:@{};NSString *image=backend[@"targetImage"]?:tr[@"image"]?:@"";NSString *mainName=NSBundle.mainBundle.executablePath.lastPathComponent?:@"";NSString *target=[image isEqual:mainName]?@"main":image;NSString *identity=nil;uint64_t rva=0;BOOL normalized=HFA03133CanonicalTarget(target,backend[@"targetRVA"]?:@"",backend[@"targetUUID"]?:@"",&identity,&rva);if(!normalized)continue;NSString *mk=HFA03131MatchKey(identity,rva,backend[@"original"]?:@"",backend[@"enabled"]?:@"");NSMutableArray *q=probeQueues[mk];if(!q.count)continue;NSNumber *liN=q.firstObject;[q removeObjectAtIndex:0];NSUInteger li=liN.unsignedIntegerValue;if(li>=ledger.count)continue;NSDictionary *le=ledger[li];NSString *fid=[le[@"featureId"] description]?:@"";if(!fid.length)continue;NSDictionary *owner=@{@"featureId":fid,@"title":le[@"title"]?:fid,@"key":le[@"key"]?:@"",@"descriptorIndex":le[@"descriptorIndex"]?:@(-1),@"source":@"strong-signature-anchor"};strongOwnerByBackend[[backend[@"backendId"] description]?:@""]=owner;uint64_t xr=HFA03134FirstXrefRVA(backend);if(xr){NSMutableArray *arr=featureXrefs[fid];if(!arr){arr=[NSMutableArray array];featureXrefs[fid]=arr;}[arr addObject:@(xr)];}}

    uint64_t learnedGap=0;
    for(NSString *fid in featureXrefs){NSArray *sorted=[featureXrefs[fid] sortedArrayUsingSelector:@selector(compare:)];for(NSUInteger i=1;i<sorted.count;i++){uint64_t a=[sorted[i-1] unsignedLongLongValue],z=[sorted[i] unsignedLongLongValue],g=z>a?z-a:0;if(g&&g<0x400&&g>learnedGap)learnedGap=g;}}
    uint64_t clusterGap=learnedGap?MIN(MAX(learnedGap*2,0x80ULL),0x400ULL):0x100ULL;

    NSMutableArray *ordered=[NSMutableArray array];
    for(NSDictionary *backend in backends){uint64_t xr=HFA03134FirstXrefRVA(backend);if(xr)[ordered addObject:@{@"backend":backend,@"xref":@(xr)}];}
    [ordered sortUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){return [a[@"xref"] compare:b[@"xref"]];}];
    NSMutableDictionary *clusterOwnerByBackend=[NSMutableDictionary dictionary];
    NSMutableDictionary *clusterIdByBackend=[NSMutableDictionary dictionary];
    NSUInteger clusterStart=0,clusterNo=0;
    while(clusterStart<ordered.count){NSUInteger end=clusterStart+1;uint64_t prev=[ordered[clusterStart][@"xref"] unsignedLongLongValue];while(end<ordered.count){uint64_t cur=[ordered[end][@"xref"] unsignedLongLongValue];if(cur<=prev||cur-prev>clusterGap)break;prev=cur;end++;}
        clusterNo++;NSMutableDictionary *owners=[NSMutableDictionary dictionary];for(NSUInteger i=clusterStart;i<end;i++){NSDictionary *be=ordered[i][@"backend"];NSDictionary *o=strongOwnerByBackend[[be[@"backendId"] description]?:@""];NSString *fid=[o[@"featureId"] description]?:@"";if(fid.length)owners[fid]=o;}
        NSString *clusterId=[NSString stringWithFormat:@"xref-cluster-%lu",(unsigned long)clusterNo];NSString *status=owners.count==1?@"anchored":(owners.count?@"ambiguous":@"orphan");HFALog("[V03134-STATIC-CLUSTER] id=%s members=%u owners=%u status=%s gap=0x%llX learned=0x%llX first=%s last=%s\\n",clusterId.UTF8String?:"?",(unsigned)(end-clusterStart),(unsigned)owners.count,status.UTF8String?:"?",(unsigned long long)clusterGap,(unsigned long long)learnedGap,[[NSString stringWithFormat:@"0x%llX",(unsigned long long)[ordered[clusterStart][@"xref"] unsignedLongLongValue]] UTF8String],[[NSString stringWithFormat:@"0x%llX",(unsigned long long)[ordered[end-1][@"xref"] unsignedLongLongValue]] UTF8String]);
        NSDictionary *only=owners.count==1?owners.allValues.firstObject:nil;for(NSUInteger i=clusterStart;i<end;i++){NSDictionary *be=ordered[i][@"backend"];NSString *bid=[be[@"backendId"] description]?:@"";clusterIdByBackend[bid]=clusterId;if(only)clusterOwnerByBackend[bid]=HFA03134ClusterOwnerRecord(only,clusterId);}
        clusterStart=end;
    }

    // Second pass: preserve the v03134 strong signature bridge and direct static
    // ownership. Xref-cluster ownership is only a fallback when a cluster has one
    // and only one already-proven feature owner.
    NSMutableDictionary *liveQueues=[NSMutableDictionary dictionary];for(NSString *k in signatureToLedger)liveQueues[k]=[signatureToLedger[k] mutableCopy];
    for(NSDictionary *be in backends){NSDictionary *tr=[be[@"targetResolution"] isKindOfClass:NSDictionary.class]?be[@"targetResolution"]:@{};NSString *image=be[@"targetImage"]?:tr[@"image"]?:@"";NSString *mainName=NSBundle.mainBundle.executablePath.lastPathComponent?:@"";NSString *target=[image isEqual:mainName]?@"main":image;NSString *identity=nil;uint64_t rva=0;BOOL normalized=HFA03133CanonicalTarget(target,be[@"targetRVA"]?:@"",be[@"targetUUID"]?:@"",&identity,&rva);NSString *matchKey=normalized?HFA03131MatchKey(identity,rva,be[@"original"]?:@"",be[@"enabled"]?:@""):@"";NSMutableArray *q=matchKey.length?liveQueues[matchKey]:nil;NSNumber *existing=q.count?q.firstObject:nil;
        if(existing){[q removeObjectAtIndex:0];NSUInteger li=existing.unsignedIntegerValue;if(li<ledger.count){NSMutableDictionary *e=ledger[li];e[@"analyzerMatched"]=@YES;e[@"analyzerBackendId"]=be[@"backendId"]?:@0;e[@"family"]=be[@"family"]?:@"";e[@"descriptorRVA"]=be[@"descriptorRVA"]?:@"";e[@"patchDescriptorRVA"]=be[@"patchDescriptorRVA"]?:@"";e[@"analyzerTargetRVA"]=be[@"targetRVA"]?:@"";e[@"canonicalTargetIdentity"]=identity?:@"";e[@"canonicalRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva];e[@"analyzerMatchKey"]=@"identity+rva+original+enabled";NSString *cid=clusterIdByBackend[[be[@"backendId"] description]?:@""];if(cid.length)e[@"staticClusterId"]=cid;gHFA0313AnalyzerMatchedCount++;}continue;}
        NSMutableDictionary *e=[NSMutableDictionary dictionary];e[@"source"]=@"runtime-analyzer-binary-first";e[@"analyzerMatched"]=@NO;e[@"analyzerBackendId"]=be[@"backendId"]?:@0;e[@"family"]=be[@"family"]?:@"";e[@"descriptorRVA"]=be[@"descriptorRVA"]?:@"";e[@"patchDescriptorRVA"]=be[@"patchDescriptorRVA"]?:@"";e[@"targetRVA"]=be[@"targetRVA"]?:@"";e[@"offset"]=normalized?[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva]:(be[@"targetRVA"]?:@"");e[@"targetUUID"]=be[@"targetUUID"]?:@"";e[@"original"]=be[@"original"]?:@"";e[@"enabled"]=be[@"enabled"]?:@"";e[@"target"]=target?:@"";e[@"canonicalTargetIdentity"]=identity?:@"";if(normalized)e[@"canonicalRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva];e[@"canonicalEligible"]=be[@"canonicalEligible"]?:@NO;e[@"key"]=@"";e[@"featureId"]=@"";e[@"ownershipSource"]=@"runtime-analyzer-unowned";NSString *cid=clusterIdByBackend[[be[@"backendId"] description]?:@""];if(cid.length)e[@"staticClusterId"]=cid;
        NSString *reason=@"unowned-static-backend";if(!normalized)reason=@"target-rva-normalization-failed";else if(![tr[@"status"] isEqual:@"unique"])reason=@"analyzer-target-not-unique";else if(![be[@"canonicalEligible"] boolValue])reason=@"analyzer-noncanonical-static";else if(![e[@"original"] length]||![e[@"enabled"] length])reason=@"analyzer-bytes-incomplete";
        NSDictionary *owner=nil;if([reason isEqual:@"unowned-static-backend"]){owner=HFA03134OwnershipForBackend(be);if(!owner)owner=clusterOwnerByBackend[[be[@"backendId"] description]?:@""];}
        NSUInteger li=ledger.count;
        if(owner){NSString *fid=owner[@"featureId"]?:@"",*ownerKey=owner[@"key"]?:@"";e[@"featureId"]=fid;e[@"title"]=owner[@"title"]?:fid;e[@"key"]=ownerKey;e[@"ownershipSource"]=owner[@"source"]?:@"static-structural";e[@"ownershipEvidence"]=owner;e[@"status"]=@"candidate";e[@"reason"]=@"awaiting-conflict-audit";[ledger addObject:e];NSString *exportImage=[target isEqual:@"main"]?@"@main":([image length]?image:target);[candidates addObject:@{@"ledgerIndex":@(li),@"featureId":fid,@"target":target?:@"",@"image":exportImage?:@"",@"offset":e[@"offset"]?:@"",@"original":e[@"original"]?:@"",@"enabled":e[@"enabled"]?:@"",@"targetUUID":e[@"targetUUID"]?:@""}];HFALog("[V03134-OWNERSHIP-BRIDGE] backend=%u feature=%s source=%s cluster=%s target=%s offset=%s status=candidate\\n",[e[@"analyzerBackendId"] unsignedIntValue],fid.UTF8String?:"?",[e[@"ownershipSource"] UTF8String]?:"?",cid.UTF8String?:"-",target.UTF8String?:"?",[e[@"offset"] UTF8String]?:"?");}
        else{if([reason isEqual:@"unowned-static-backend"]&&cid.length)reason=@"orphan-static-feature-cluster";e[@"status"]=@"excluded";e[@"reason"]=reason;[ledger addObject:e];HFALog("[STATIC-BRIDGE] backend=%u family=%s cluster=%s target=%s offset=%s canonicalRVA=%s status=excluded reason=%s\\n",[e[@"analyzerBackendId"] unsignedIntValue],[e[@"family"] UTF8String]?:"?",cid.UTF8String?:"-",[e[@"target"] UTF8String]?:"?",[e[@"offset"] UTF8String]?:"?",[e[@"canonicalRVA"] UTF8String]?:"?",reason.UTF8String?:"?");}
        gHFA0313AnalyzerBridgedCount++;
    }
    gHFA0313LedgerParity=gHFA0313AnalyzerAvailable&&gHFA0313AnalyzerStaticCount==ledger.count&&(gHFA0313AnalyzerMatchedCount+gHFA0313AnalyzerBridgedCount)==gHFA0313AnalyzerStaticCount;HFALog("[V03134-LEDGER-BRIDGE] analyzer=%u matched=%u bridged=%u ledger=%u parity=%u ownership=static-structural+xref-cluster clusterGap=0x%llX learnedGap=0x%llX\\n",(unsigned)gHFA0313AnalyzerStaticCount,(unsigned)gHFA0313AnalyzerMatchedCount,(unsigned)gHFA0313AnalyzerBridgedCount,(unsigned)ledger.count,gHFA0313LedgerParity?1:0,(unsigned long long)clusterGap,(unsigned long long)learnedGap);
}'''

s = s[:a] + replacement + s[b:]
TRACE.write_text(s)

out = TRACE.read_text()
for marker in ['[V03134-STATIC-CLUSTER]', 'orphan-static-feature-cluster', 'static-xref-cluster', 'ownership=static-structural+xref-cluster']:
    if marker not in out:
        raise SystemExit('missing cluster marker '+marker)
print('v0.3.13.4 generic static xref cluster ownership applied')

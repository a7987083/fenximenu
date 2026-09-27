from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
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
    raise SystemExit('unterminated function')

sig='static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates)'
a,b=function_span(s,sig)
new=r'''static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates){
    gHFA0313AnalyzerStaticCount=backends.count;gHFA0313AnalyzerMatchedCount=0;gHFA0313AnalyzerBridgedCount=0;NSMutableDictionary *signatureToLedger=[NSMutableDictionary dictionary];
    for(NSDictionary *c in candidates){uintptr_t ra=HFA0313RuntimeAddressForTarget(c[@"target"],c[@"offset"]);if(!ra)continue;NSString *key=[NSString stringWithFormat:@"%llX|%@|%@",(unsigned long long)ra,c[@"original"]?:@"",c[@"enabled"]?:@""];NSMutableArray *q=signatureToLedger[key];if(!q){q=[NSMutableArray array];signatureToLedger[key]=q;}[q addObject:c[@"ledgerIndex"]?:@0];}
    for(NSDictionary *b in backends){NSDictionary *tr=[b[@"targetResolution"] isKindOfClass:NSDictionary.class]?b[@"targetResolution"]:@{};uintptr_t ra=(uintptr_t)[tr[@"runtimeAddress"] unsignedLongLongValue];NSString *key=ra?[NSString stringWithFormat:@"%llX|%@|%@",(unsigned long long)ra,b[@"original"]?:@"",b[@"enabled"]?:@""]:@"";NSMutableArray *q=key.length?signatureToLedger[key]:nil;NSNumber *existing=q.count?q.firstObject:nil;if(existing){[q removeObjectAtIndex:0];NSUInteger li=existing.unsignedIntegerValue;if(li<ledger.count){NSMutableDictionary *e=ledger[li];e[@"analyzerMatched"]=@YES;e[@"analyzerBackendId"]=b[@"backendId"]?:@0;e[@"family"]=b[@"family"]?:@"";e[@"descriptorRVA"]=b[@"descriptorRVA"]?:@"";e[@"patchDescriptorRVA"]=b[@"patchDescriptorRVA"]?:@"";e[@"analyzerTargetRVA"]=b[@"targetRVA"]?:@"";e[@"analyzerMatchKey"]=@"runtime+original+enabled";gHFA0313AnalyzerMatchedCount++;}continue;}
        NSMutableDictionary *e=[NSMutableDictionary dictionary];e[@"source"]=@"runtime-analyzer-binary-first";e[@"analyzerMatched"]=@NO;e[@"analyzerBackendId"]=b[@"backendId"]?:@0;e[@"family"]=b[@"family"]?:@"";e[@"descriptorRVA"]=b[@"descriptorRVA"]?:@"";e[@"patchDescriptorRVA"]=b[@"patchDescriptorRVA"]?:@"";e[@"targetRVA"]=b[@"targetRVA"]?:@"";e[@"offset"]=b[@"targetRVA"]?:@"";e[@"targetUUID"]=b[@"targetUUID"]?:@"";e[@"original"]=b[@"original"]?:@"";e[@"enabled"]=b[@"enabled"]?:@"";NSString *image=b[@"targetImage"]?:tr[@"image"]?:@"";NSString *mainName=NSBundle.mainBundle.executablePath.lastPathComponent?:@"";e[@"target"]=[image isEqual:mainName]?@"main":image;e[@"canonicalEligible"]=b[@"canonicalEligible"]?:@NO;e[@"key"]=@"";e[@"featureId"]=@"";e[@"ownershipSource"]=@"runtime-analyzer-unowned";NSString *reason=@"unowned-static-backend";if(![tr[@"status"] isEqual:@"unique"])reason=@"analyzer-target-not-unique";else if(![b[@"canonicalEligible"] boolValue])reason=@"analyzer-noncanonical-static";else if(![e[@"original"] length]||![e[@"enabled"] length])reason=@"analyzer-bytes-incomplete";e[@"status"]=@"excluded";e[@"reason"]=reason;[ledger addObject:e];gHFA0313AnalyzerBridgedCount++;HFALog("[STATIC-BRIDGE] backend=%u family=%s target=%s offset=%s status=excluded reason=%s\n",[e[@"analyzerBackendId"] unsignedIntValue],[e[@"family"] UTF8String]?:"?",[e[@"target"] UTF8String]?:"?",[e[@"offset"] UTF8String]?:"?",reason.UTF8String?:"?");
    }
    gHFA0313LedgerParity=gHFA0313AnalyzerAvailable&&gHFA0313AnalyzerStaticCount==ledger.count&&(gHFA0313AnalyzerMatchedCount+gHFA0313AnalyzerBridgedCount)==gHFA0313AnalyzerStaticCount;HFALog("[V0313-LEDGER-BRIDGE] analyzer=%u matched=%u bridged=%u ledger=%u parity=%u matchKey=runtime+original+enabled\n",(unsigned)gHFA0313AnalyzerStaticCount,(unsigned)gHFA0313AnalyzerMatchedCount,(unsigned)gHFA0313AnalyzerBridgedCount,(unsigned)ledger.count,gHFA0313LedgerParity?1:0);
}'''
s=s[:a]+new+s[b:]
TRACE.write_text(s)
out=TRACE.read_text()
for req in ['signatureToLedger','runtime+original+enabled','analyzerMatchKey']:
    if req not in out: raise SystemExit('v0313 conflict-match fix missing '+req)
print('v0.3.13 one-to-one analyzer ledger match fix applied')

from pathlib import Path
import re

SRC = Path('hfamap/src/HFAMapRuntimeAnalyzerV02.m')
UI = Path('hfamap/src/HFAMapCyberUI.m')
s = SRC.read_text()

# v0.3.3: make on-device discovery structurally equivalent to the offline
# simulator. Descriptor discovery is binary-first and may not be discarded
# merely because decrypt resolution/plaintext validation is unavailable.
helper = r'''
static uintptr_t HFAV033StaticDecryptFingerprint(HFAV02Layout l,unsigned *matches){
    if(matches)*matches=0;if(!l.text.start||l.text.end<=l.text.start+0x44)return 0;
    uintptr_t only=0;unsigned count=0;
    for(uintptr_t p=l.text.start;p+0x44<=l.text.end;p+=4){
        uint32_t a=0,b=0,c=0;memcpy(&a,(void*)p,4);memcpy(&b,(void*)(p+0x30),4);memcpy(&c,(void*)(p+0x40),4);
        if(a==0xD105C3FFu&&b==0xB9400408u&&c==0x53187D00u){only=p;count++;if(count>1)break;}
    }
    if(matches)*matches=count;return count==1?only:0;
}
static NSDictionary *HFAV033HookReturnEvidence(uintptr_t repl,HFAV02Layout l){
    if(!repl||repl<l.text.start||repl>=l.text.end)return @{};
    const uint32_t *w=(const uint32_t*)repl;NSUInteger n=MIN((NSUInteger)192,(NSUInteger)((l.text.end-repl)/4));
    uint32_t vals[32]={0};BOOL known[32]={0};BOOL cond=NO;NSMutableArray *returns=[NSMutableArray array];
    for(NSUInteger i=0;i<n;i++){
        uint32_t x=w[i];if(HFAV032Cond(x))cond=YES;HFAV032MoveWide32(x,vals,known);
        if(!known[0]||vals[0]>1)continue;
        for(NSUInteger j=1;j<=3&&i+j<n;j++)if(w[i+j]==0xD65F03C0u){
            uint32_t seq[2]={0x52800000u|((vals[0]&0xFFFFu)<<5),0xD65F03C0u};
            [returns addObject:@{@"returnValue":@(vals[0]),@"sourceRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(repl+i*4-l.base)],@"enabled":HFAV032HexBytes(seq,8)}];
            break;
        }
        known[0]=NO;
    }
    return @{@"hasConditionalBranch":@(cond),@"constantReturnCandidateCount":@(returns.count),@"constantReturnCandidates":returns,@"status":@"diagnostic-only"};
}
'''
anchor = 'unsigned HFAAnalyzerV02ScanSelectedImage(void)'
if 'HFAV033StaticDecryptFingerprint' not in s:
    i = s.find(anchor)
    if i < 0: raise SystemExit('v033 scan anchor missing')
    s = s[:i] + helper + '\n' + s[i:]

old = 'uintptr_t decrypt=HFAV02ResolveDecrypt(image,l);if(!decrypt){HFAV02Log([NSString stringWithFormat:@"[V032-SCAN] image=%s status=no-decrypt",image]);return 0;}'
new = 'uintptr_t decrypt=HFAV02ResolveDecrypt(image,l);unsigned decryptMatches=0;NSString *decryptSource=@"runtime-resolver";if(!decrypt){decrypt=HFAV033StaticDecryptFingerprint(l,&decryptMatches);decryptSource=decrypt?@"static-fingerprint":@"unavailable";}BOOL haveDecrypt=decrypt!=0;HFAV02Log([NSString stringWithFormat:@"[V033-DECRYPT] image=%s source=%@ matches=%u rva=%@",image,decryptSource,decryptMatches,haveDecrypt?[NSString stringWithFormat:@"0x%llX",(unsigned long long)(decrypt-l.base)]:@"-"]);'
if old not in s: raise SystemExit('v033 decrypt gate anchor missing')
s = s.replace(old,new,1)

# Align the structural record walk with the offline simulator's 8-byte record
# alignment. The current families are 0x031201/0x031211 and 0x021401/0x021411.
s = s.replace('for(uintptr_t p=r.start;p+0x30<=r.end;p+=4){', 'for(uintptr_t p=r.start;p+0x30<=r.end;p+=8){', 1)

pat = re.compile(r'void \*copy=malloc\(blob\),\*plain=calloc\(1,len\+0x20\);if\(!copy\|\|!plain\)\{free\(copy\);free\(plain\);continue;\}memcpy\(copy,\(void\*\)p,blob\);int rc=\(\(HFASecretDecryptFn\)decrypt\)\(copy,plain\);if\(rc\)\{free\(copy\);free\(plain\);continue;\}char buf\[0x241\]=\{0\};unsigned nc=MIN\(len,\(uint32_t\)0x240\);memcpy\(buf,plain,nc\);free\(copy\);free\(plain\);if\(!HFAV02Printable\(buf,nc\)\)continue;NSString \*pt=\[NSString stringWithUTF8String:buf\]\?:@"";NSString \*kind=HFAV02Kind\(fam,pt\);')
rep = r'''NSString *pt=@"";NSString *decryptStatus=haveDecrypt?@"decrypt-not-attempted":@"decrypt-unavailable";
        if(haveDecrypt){void *copy=malloc(blob),*plain=calloc(1,len+0x20);if(copy&&plain){memcpy(copy,(void*)p,blob);int rc=((HFASecretDecryptFn)decrypt)(copy,plain);if(!rc){char buf[0x241]={0};unsigned nc=MIN(len,(uint32_t)0x240);memcpy(buf,plain,nc);if(HFAV02Printable(buf,nc)){pt=[NSString stringWithUTF8String:buf]?:@"";decryptStatus=@"ok";}else decryptStatus=@"non-printable";}else decryptStatus=[NSString stringWithFormat:@"rc-%d",rc];}else decryptStatus=@"alloc-failed";free(copy);free(plain);}NSString *kind=HFAV02Kind(fam,pt);'''
s, n = pat.subn(rep, s, count=1)
if n != 1: raise SystemExit('v033 decrypt/printable filter block missing')

needle='@"plain":pt,@"xrefs":xrefs?:@[]'
if needle not in s: raise SystemExit('v033 record dictionary anchor missing')
s=s.replace(needle,'@"plain":pt,@"decryptStatus":decryptStatus,@"xrefs":xrefs?:@[]',1)

# Runtime-state hooks with no object field offsets are not converted into a
# canonical patch. Export read-only return-override evidence so the next device
# log can distinguish a boolean-return hook from a stateful callback/dataflow.
old_sem='NSDictionary *sem=HFAV032ReplacementSemantics(repl,slot,l);NSString *stype=sem[@"semanticType"]?:@"native-hook";b[@"backendType"]=stype;'
new_sem='NSDictionary *sem=HFAV032ReplacementSemantics(repl,slot,l);NSString *stype=sem[@"semanticType"]?:@"native-hook";b[@"backendType"]=stype;b[@"hookReturnEvidence"]=HFAV033HookReturnEvidence(repl,l);'
if old_sem not in s: raise SystemExit('v033 runtime-state evidence anchor missing')
s=s.replace(old_sem,new_sem,1)

# A single conditional constant-return pattern is exported only as a diagnostic
# target-entry candidate. It remains non-canonical until device/original-byte
# evidence proves the semantics.
old_tail='NSArray *derived=HFAV032FieldConsumers(b[@"fieldOffsets"],image);b[@"derivedPatches"]=derived;derivedCount+=(unsigned)derived.count;b[@"canonicalEligible"]=@NO;}'
new_tail='NSArray *derived=HFAV032FieldConsumers(b[@"fieldOffsets"],image);b[@"derivedPatches"]=derived;derivedCount+=(unsigned)derived.count;NSDictionary *hre=b[@"hookReturnEvidence"];NSArray *rcs=hre[@"constantReturnCandidates"]?:@[];if([stype isEqual:@"runtime-state"]&&[hre[@"hasConditionalBranch"] boolValue]&&rcs.count==1&&[target[@"status"] isEqual:@"unique"]){NSDictionary *rc=rcs.firstObject;NSString *enabled=rc[@"enabled"]?:@"";NSData *ed=HFAV032HexData(enabled);uintptr_t ra=(uintptr_t)[target[@"runtimeAddress"] unsignedLongLongValue];NSString *original=ed.length?HFAV032HexBytes((const void*)ra,ed.length):@"";b[@"staticOverrideCandidates"]=@[@{@"status":@"diagnostic-only",@"targetImage":target[@"image"]?:@"?",@"targetUUID":target[@"uuid"]?:@"unknown",@"patchRVA":target[@"targetRVA"]?:@"",@"original":original,@"enabled":enabled,@"returnValue":rc[@"returnValue"]?:@0}];}b[@"canonicalEligible"]=@NO;}'
if old_tail not in s: raise SystemExit('v033 derived-tail anchor missing')
s=s.replace(old_tail,new_tail,1)

s=s.replace('@"schema":@"com.hfa.runtime-analyzer/v0.3.2"', '@"schema":@"com.hfa.runtime-analyzer/v0.3.3",@"structuralParity":@YES,@"decryptSource":decryptSource', 1)
s=s.replace('NSString *p32=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v032.json");NSString *p03=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v03.json");[json writeToFile:p32 atomically:YES];[json writeToFile:p03 atomically:YES];', 'NSString *p33=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v033.json");NSString *p32=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v032.json");NSString *p03=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v03.json");[json writeToFile:p33 atomically:YES];[json writeToFile:p32 atomically:YES];[json writeToFile:p03 atomically:YES];', 1)
s=s.replace('[V032-BACKEND]', '[V033-BACKEND]').replace('[V032-SCAN-END]', '[V033-SCAN-END]')
SRC.write_text(s)

ui=UI.read_text()
ui=ui.replace('HFAMap RuntimeAnalyzer v0.3.2 AutoBackend','HFAMap RuntimeAnalyzer v0.3.3 StaticParity',2)
UI.write_text(ui)

# Regression gates: universal second-button entry and per-bundle output routing
# must remain intact.
ui=UI.read_text()
if 'HFAAppLocalExecuteParser()' not in ui or 'HFAAnalyzerV02ScanSelectedImage()' not in ui:
    raise SystemExit('v033 universal AutoBackend entry missing')
if 'HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v033.json")' not in SRC.read_text():
    raise SystemExit('v033 bundle-folder output missing')
if 'Documents/HFAMap_RuntimeAnalyzer' in SRC.read_text():
    raise SystemExit('v033 direct Documents output regression')
print('v0.3.3 static parity + runtime-state diagnostics applied')

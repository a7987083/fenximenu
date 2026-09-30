from pathlib import Path

TRUTH=Path('hfamap/src/HFAMapRuntimeModificationTruth.m')
TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
UI=Path('hfamap/src/HFAMapCyberUI.m')

s=TRUTH.read_text()

# Conservative native target classifier. It does not claim method ownership.
addr_anchor='''static NSDictionary *HFATAddressInfo(uintptr_t a){\n    if(!a)return @{};Dl_info d={0};if(!dladdr((void*)a,&d)||!d.dli_fbase||!d.dli_fname)return @{ @"address":[NSString stringWithFormat:@"0x%llX",(unsigned long long)a] };\n    return @{ @"address":[NSString stringWithFormat:@"0x%llX",(unsigned long long)a],@"image":HFATBaseName(d.dli_fname),@"rva":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(a-(uintptr_t)d.dli_fbase)],@"symbol":d.dli_sname?[NSString stringWithUTF8String:d.dli_sname]:@"" };\n}\n'''
classifier=r'''

static NSDictionary *HFATNativeTargetClassify(uintptr_t address,NSDictionary *semantic){
    if(!address)return @{ @"kind":@"unavailable",@"executable":@NO,@"candidateOnly":@YES };
    BOOL executable=HFATRange(address,4,YES);NSMutableDictionary *out=[NSMutableDictionary dictionaryWithDictionary:HFATAddressInfo(address)?:@{}];
    out[@"executable"]=@(executable);out[@"candidateOnly"]=@YES;
    NSString *mode=[semantic[@"resolutionMode"] description]?:@"";
    if([semantic[@"resolved"] boolValue]){
        if([mode isEqualToString:@"exact"]){out[@"kind"]=@"il2cpp-exact-method";out[@"candidateOnly"]=@NO;return out;}
        if([mode isEqualToString:@"containment"]){out[@"kind"]=@"il2cpp-contained-method";out[@"candidateOnly"]=@NO;return out;}
    }
    if(!executable){out[@"kind"]=@"non-executable";return out;}
    uint32_t insn=0;memcpy(&insn,(void*)address,sizeof(insn));out[@"firstInstruction"]=[NSString stringWithFormat:@"0x%08X",insn];
    if((insn&0xFC000000u)==0x14000000u){
        int64_t imm=(int64_t)(insn&0x03FFFFFFu);if(imm&0x02000000u)imm|=~0x03FFFFFFLL;uintptr_t dest=(uintptr_t)((int64_t)address+(imm<<2));
        out[@"kind"]=@"direct-branch-thunk";out[@"branchTarget"]=HFATAddressInfo(dest);return out;
    }
    if((insn&0xFFFFFC1Fu)==0xD61F0000u){out[@"kind"]=@"register-branch-thunk";return out;}
    if((insn&0xFFFFFC1Fu)==0xD65F0000u){out[@"kind"]=@"return-stub";return out;}
    Dl_info d={0};if(dladdr((void*)address,&d)&&d.dli_sname&&d.dli_saddr){uintptr_t ss=(uintptr_t)d.dli_saddr;uint64_t delta=address>=ss?(uint64_t)(address-ss):UINT64_MAX;if(delta==0){out[@"kind"]=@"symbol-entry";out[@"symbolCandidateOnly"]=@NO;}else{out[@"kind"]=@"executable-native-unknown";out[@"symbolCandidateOnly"]=@YES;}out[@"symbolStart"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)ss];if(delta!=UINT64_MAX)out[@"symbolOffset"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)delta];return out;}
    out[@"kind"]=@"executable-native-unknown";return out;
}

static BOOL HFATStructuralHookBackend(NSDictionary *b){
    if(![b isKindOfClass:NSDictionary.class])return NO;
    NSDictionary *tr=[b[@"targetResolution"] isKindOfClass:NSDictionary.class]?b[@"targetResolution"]:@{};
    BOOL unique=[[tr[@"status"] description] isEqualToString:@"unique"];
    return unique&&[[b[@"targetRVA"] description] length]&&[[b[@"replacementRVA"] description] length]&&[[b[@"originalSlotRVA"] description] length];
}
'''
if 'HFATNativeTargetClassify' not in s:
    if addr_anchor not in s: raise SystemExit('v031316 address-info anchor missing')
    s=s.replace(addr_anchor,addr_anchor+classifier,1)

# Attach native classification to fixed patches after semantic resolution.
old='''if(a){NSDictionary *sem=HFATIL2CPPSemantic(a);o[@"targetIL2CPP"]=sem;NSLog(@"[V031315-IL2CPP-TARGET] mechanism=fixed-patch target=%@+%@ resolved=%u canonical=%@",image,rva,[sem[@"resolved"] boolValue]?1:0,[sem[@"canonical"] description]?:@"");}'''
new='''if(a){NSDictionary *sem=HFATIL2CPPSemantic(a);o[@"targetIL2CPP"]=sem;o[@"nativeTarget"]=HFATNativeTargetClassify(a,sem);NSLog(@"[V031316-TARGET-CLASS] mechanism=fixed-patch target=%@+%@ il2cpp=%u kind=%@",image,rva,[sem[@"resolved"] boolValue]?1:0,[o[@"nativeTarget"] objectForKey:@"kind"]?:@"");}'''
if old not in s: raise SystemExit('v031316 fixed semantic anchor missing')
s=s.replace(old,new,1)

# Attach classification to runtime-hook target as well.
old='''if(original)o[@"originalPointer"]=HFATAddressInfo(original);if(target){o[@"targetAddress"]=HFATAddressInfo(target);NSDictionary *sem=HFATIL2CPPSemantic(target);o[@"targetIL2CPP"]=sem;NSLog(@"[V031315-IL2CPP-TARGET] mechanism=runtime-hook target=%@+%@ resolved=%u canonical=%@",targetImage,targetRVA,[sem[@"resolved"] boolValue]?1:0,[sem[@"canonical"] description]?:@"");}if(replacement)o[@"replacementAddress"]=HFATAddressInfo(replacement);'''
new='''if(original)o[@"originalPointer"]=HFATAddressInfo(original);if(target){o[@"targetAddress"]=HFATAddressInfo(target);NSDictionary *sem=HFATIL2CPPSemantic(target);o[@"targetIL2CPP"]=sem;o[@"nativeTarget"]=HFATNativeTargetClassify(target,sem);NSLog(@"[V031316-TARGET-CLASS] mechanism=runtime-hook target=%@+%@ il2cpp=%u kind=%@",targetImage,targetRVA,[sem[@"resolved"] boolValue]?1:0,[o[@"nativeTarget"] objectForKey:@"kind"]?:@"");}if(replacement)o[@"replacementAddress"]=HFATAddressInfo(replacement);'''
if old not in s: raise SystemExit('v031316 hook semantic anchor missing')
s=s.replace(old,new,1)

# Stabilize hook ingestion: semantic classification may degrade on budget, but structural hook evidence remains valid.
old='''for(NSDictionary *b in backends){if(![[b[@"backendType"] description] isEqual:@"runtime-semantic"])continue;NSDictionary *v=HFATVerifyHook(b,menuImage);[hooks addObject:v];if([v[@"installed"] boolValue])installedHooks++;}'''
new='''for(NSDictionary *b in backends){BOOL semantic=[[b[@"backendType"] description] isEqual:@"runtime-semantic"];BOOL structural=HFATStructuralHookBackend(b);if(!semantic&&!structural)continue;NSMutableDictionary *v=[[HFATVerifyHook(b,menuImage) mutableCopy] autorelease];v[@"sourceBackendType"]=[b[@"backendType"] description]?:@"";v[@"sourceSemanticType"]=[b[@"semanticType"] description]?:@"";NSDictionary *se=[b[@"semanticEvidence"] isKindOfClass:NSDictionary.class]?b[@"semanticEvidence"]:@{};v[@"sourceSemanticStatus"]=[se[@"status"] description]?:@"";v[@"ingestionReason"]=semantic?@"semantic-backend":@"structural-hook-evidence";[hooks addObject:v];if([v[@"installed"] boolValue])installedHooks++;NSLog(@"[V031316-HOOK-INGEST] backend=%@ type=%@ semanticStatus=%@ reason=%@ installed=%u",v[@"backendId"],v[@"sourceBackendType"],v[@"sourceSemanticStatus"],v[@"ingestionReason"],[v[@"installed"] boolValue]?1:0);}'''
if old not in s: raise SystemExit('v031316 hook ingestion anchor missing')
s=s.replace(old,new,1)

s=s.replace('com.hfa.runtime-modification-truth/v0.3.13.15','com.hfa.runtime-modification-truth/v0.3.13.16')
TRUTH.write_text(s)

t=TRACE.read_text()
t=t.replace('HFAMap_RuntimeModificationTruth_v031315.json','HFAMap_RuntimeModificationTruth_v031316.json')
t=t.replace('[V031315-TRUTH-FILE]','[V031316-TRUTH-FILE]')
t=t.replace('[V031315-TRUTH-SUMMARY]','[V031316-TRUTH-SUMMARY]')
t=t.replace('[V031315-MOD-SEMANTIC]','[V031316-MOD-SEMANTIC]')
# Enrich exported semantic lines with structural-ingestion/native-target evidence.
t=t.replace('confidence=%s canonical=%s\\n",[[h[@"backendId"] description] UTF8String]?:"?",', 'confidence=%s ingest=%s nativeKind=%s canonical=%s\\n",[[h[@"backendId"] description] UTF8String]?:"?",')
t=t.replace('[[sem[@"confidence"] description] UTF8String]?:"exact",[[sem[@"canonical"] description] UTF8String]?:"");}', '[[sem[@"confidence"] description] UTF8String]?:"exact",[[h[@"ingestionReason"] description] UTF8String]?:"?",[[[h[@"nativeTarget"] isKindOfClass:NSDictionary.class]?h[@"nativeTarget"]:@{} objectForKey:@"kind"] description].UTF8String?:"?",[[sem[@"canonical"] description] UTF8String]?:"");}',1)
# Fixed-patch line has no ingestion reason; only add native kind.
t=t.replace('confidence=%s canonical=%s\\n",[[p[@"analyzerBackendId"] description] UTF8String]?:"?",', 'confidence=%s nativeKind=%s canonical=%s\\n",[[p[@"analyzerBackendId"] description] UTF8String]?:"?",')
t=t.replace('[[sem[@"confidence"] description] UTF8String]?:"exact",[[sem[@"canonical"] description] UTF8String]?:"");}', '[[sem[@"confidence"] description] UTF8String]?:"exact",[[[[p[@"nativeTarget"] isKindOfClass:NSDictionary.class]?p[@"nativeTarget"]:@{} objectForKey:@"kind"] description] UTF8String]?:"?",[[sem[@"canonical"] description] UTF8String]?:"");}',1)
TRACE.write_text(t)

u=UI.read_text()
u=u.replace('HFAMap RuntimeAnalyzer v0.3.13.15 MethodContainmentResolver','HFAMap RuntimeAnalyzer v0.3.13.16 TruthStabilizerNativeClassifier')
UI.write_text(u)

for token in ['HFATStructuralHookBackend','HFATNativeTargetClassify','[V031316-HOOK-INGEST]','[V031316-TARGET-CLASS]','structural-hook-evidence','nativeTarget','com.hfa.runtime-modification-truth/v0.3.13.16']:
    if token not in TRUTH.read_text(): raise SystemExit('v031316 truth token missing '+token)
for token in ['[V031316-TRUTH-SUMMARY]','[V031316-MOD-SEMANTIC]','[V031316-TRUTH-FILE]','HFAMap_RuntimeModificationTruth_v031316.json']:
    if token not in TRACE.read_text(): raise SystemExit('v031316 trace token missing '+token)
if 'v0.3.13.16 TruthStabilizerNativeClassifier' not in UI.read_text(): raise SystemExit('v031316 UI marker missing')
print('v0.3.13.16 truth stabilizer/native classifier applied')

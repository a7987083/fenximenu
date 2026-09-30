from pathlib import Path

TRUTH=Path('hfamap/src/HFAMapRuntimeModificationTruth.m')
TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
UI=Path('hfamap/src/HFAMapCyberUI.m')

s=TRUTH.read_text()

# Give truth-side diagnostics their own bridge into Documents/HFAMap_Learn.log.
if '#include <stdio.h>' not in s:
    s=s.replace('#include <string.h>\n','#include <string.h>\n#include <stdio.h>\n#include <stdarg.h>\n',1)

addr_anchor='''static NSDictionary *HFATAddressInfo(uintptr_t a){\n    if(!a)return @{};Dl_info d={0};if(!dladdr((void*)a,&d)||!d.dli_fbase||!d.dli_fname)return @{ @"address":[NSString stringWithFormat:@"0x%llX",(unsigned long long)a] };\n    return @{ @"address":[NSString stringWithFormat:@"0x%llX",(unsigned long long)a],@"image":HFATBaseName(d.dli_fname),@"rva":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(a-(uintptr_t)d.dli_fbase)],@"symbol":d.dli_sname?[NSString stringWithUTF8String:d.dli_sname]:@"" };\n}\n'''
log_helper=r'''

static void HFATBundleLog(const char *fmt,...){
    @autoreleasepool {
        NSString *p=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];
        FILE *f=fopen(p.fileSystemRepresentation,"a");if(!f)return;
        va_list ap;va_start(ap,fmt);vfprintf(f,fmt,ap);va_end(ap);fflush(f);fclose(f);
    }
}
'''
if 'HFATBundleLog' not in s:
    if addr_anchor not in s: raise SystemExit('v031317 address-info anchor missing')
    s=s.replace(addr_anchor,addr_anchor+log_helper,1)

classifier_end='''static BOOL HFATStructuralHookBackend(NSDictionary *b){\n    if(![b isKindOfClass:NSDictionary.class])return NO;\n    NSDictionary *tr=[b[@"targetResolution"] isKindOfClass:NSDictionary.class]?b[@"targetResolution"]:@{};\n    BOOL unique=[[tr[@"status"] description] isEqualToString:@"unique"];\n    return unique&&[[b[@"targetRVA"] description] length]&&[[b[@"replacementRVA"] description] length]&&[[b[@"originalSlotRVA"] description] length];\n}\n'''
entry_helper=r'''

static uintptr_t HFATBranch26Target(uintptr_t pc,uint32_t insn){
    int64_t imm=(int64_t)(insn&0x03FFFFFFu);if(imm&0x02000000u)imm|=~0x03FFFFFFLL;return (uintptr_t)((int64_t)pc+(imm<<2));
}

static NSDictionary *HFATNativeEdge(uintptr_t from,uintptr_t to,NSString *op,NSUInteger index){
    NSMutableDictionary *e=[NSMutableDictionary dictionary];e[@"op"]=op?:@"?";e[@"instructionIndex"]=@(index);e[@"from"]=HFATAddressInfo(from);e[@"target"]=HFATAddressInfo(to);
    if(HFATRange(to,4,YES)){
        NSDictionary *sem=HFATIL2CPPSemantic(to);e[@"targetIL2CPP"]=sem?:@{};
        e[@"semanticResolved"]=@([sem[@"resolved"] boolValue]);
    }else e[@"semanticResolved"]=@NO;
    return e;
}

static NSDictionary *HFATNativeEntrySemantic(uintptr_t address,NSDictionary *nativeTarget){
    if(!address||!HFATRange(address,4,YES))return @{ @"attempted":@NO,@"candidateOnly":@YES,@"reason":@"not-executable" };
    NSString *kind=[nativeTarget[@"kind"] description]?:@"";
    BOOL eligible=[kind isEqualToString:@"symbol-entry"]||[kind isEqualToString:@"executable-native-unknown"]||[kind isEqualToString:@"direct-branch-thunk"]||[kind isEqualToString:@"register-branch-thunk"]||[kind isEqualToString:@"return-stub"];
    if(!eligible)return @{ @"attempted":@NO,@"candidateOnly":@NO,@"reason":@"already-semantic" };
    const NSUInteger maxInsns=64,maxEdges=4;NSMutableArray *edges=[NSMutableArray array],*head=[NSMutableArray array];NSUInteger bl=0,b=0,br=0,blr=0,ret=0,movz=0,movk=0,adrp=0,addImm=0,ldrLiteral=0,scanned=0,semanticHits=0;NSString *termination=@"window";
    for(NSUInteger i=0;i<maxInsns;i++){
        uintptr_t pc=address+i*4;if(!HFATRange(pc,4,YES)){termination=@"range-end";break;}uint32_t insn=0;memcpy(&insn,(void*)pc,4);scanned++;
        if(i<16)[head addObject:[NSString stringWithFormat:@"0x%08X",insn]];
        if((insn&0xFC000000u)==0x94000000u){bl++;uintptr_t dest=HFATBranch26Target(pc,insn);if(edges.count<maxEdges){NSDictionary *e=HFATNativeEdge(pc,dest,@"BL",i);[edges addObject:e];if([e[@"semanticResolved"] boolValue])semanticHits++;}continue;}
        if((insn&0xFC000000u)==0x14000000u){b++;uintptr_t dest=HFATBranch26Target(pc,insn);if(edges.count<maxEdges){NSDictionary *e=HFATNativeEdge(pc,dest,@"B",i);[edges addObject:e];if([e[@"semanticResolved"] boolValue])semanticHits++;}termination=@"tail-branch";break;}
        if((insn&0xFFFFFC1Fu)==0xD63F0000u){blr++;continue;}
        if((insn&0xFFFFFC1Fu)==0xD61F0000u){br++;termination=@"register-branch";break;}
        if((insn&0xFFFFFC1Fu)==0xD65F0000u){ret++;termination=@"ret";break;}
        if((insn&0x9F000000u)==0x90000000u)adrp++;
        if((insn&0x7F000000u)==0x11000000u)addImm++;
        if((insn&0x3B000000u)==0x18000000u)ldrLiteral++;
        if((insn&0x7F800000u)==0x52800000u)movz++;
        if((insn&0x7F800000u)==0x72800000u)movk++;
    }
    BOOL thin=(scanned<=8&&(b||br||ret));NSString *shape=ret?@"returning-function":((b||br)?@"tail-dispatch":(bl||blr?@"call-wrapper":@"linear-native"));
    if(thin&&[shape isEqualToString:@"returning-function"])shape=@"small-return-stub";
    NSDictionary *out=@{ @"attempted":@YES,@"candidateOnly":@YES,@"entryKind":kind,@"shape":shape,@"instructionsScanned":@(scanned),@"termination":termination,@"headInstructions":head,@"directEdges":edges,@"directCallCount":@(bl),@"directBranchCount":@(b),@"registerBranchCount":@(br),@"indirectCallCount":@(blr),@"returnCount":@(ret),@"movzCount":@(movz),@"movkCount":@(movk),@"adrpCount":@(adrp),@"addImmediateCount":@(addImm),@"ldrLiteralCount":@(ldrLiteral),@"semanticEdgeHitCount":@(semanticHits),@"thinWrapper":@(thin) };
    HFATBundleLog("[V031317-NATIVE-ENTRY] address=0x%llX kind=%s shape=%s scanned=%lu term=%s BL=%lu B=%lu BR=%lu BLR=%lu RET=%lu edges=%lu semanticHits=%lu\n",(unsigned long long)address,[kind UTF8String]?:"?",[shape UTF8String]?:"?",(unsigned long)scanned,[termination UTF8String]?:"?",(unsigned long)bl,(unsigned long)b,(unsigned long)br,(unsigned long)blr,(unsigned long)ret,(unsigned long)edges.count,(unsigned long)semanticHits);
    for(NSDictionary *e in edges){NSDictionary *ti=[e[@"target"] isKindOfClass:NSDictionary.class]?e[@"target"]:@{};NSDictionary *sem=[e[@"targetIL2CPP"] isKindOfClass:NSDictionary.class]?e[@"targetIL2CPP"]:@{};HFATBundleLog("[V031317-NATIVE-EDGE] op=%s idx=%u target=%s+%s resolved=%u mode=%s canonical=%s\n",[[e[@"op"] description] UTF8String]?:"?",[e[@"instructionIndex"] unsignedIntValue],[[ti[@"image"] description] UTF8String]?:"?",[[ti[@"rva"] description] UTF8String]?:"?",[sem[@"resolved"] boolValue]?1:0,[[sem[@"resolutionMode"] description] UTF8String]?:"?",[[sem[@"canonical"] description] UTF8String]?:"");}
    return out;
}
'''
if 'HFATNativeEntrySemantic' not in s:
    if classifier_end not in s: raise SystemExit('v031317 structural hook anchor missing')
    s=s.replace(classifier_end,classifier_end+entry_helper,1)

# Fixed patches: preserve nativeTarget and enrich unresolved native entries.
old='''if(a){NSDictionary *sem=HFATIL2CPPSemantic(a);o[@"targetIL2CPP"]=sem;o[@"nativeTarget"]=HFATNativeTargetClassify(a,sem);NSLog(@"[V031316-TARGET-CLASS] mechanism=fixed-patch target=%@+%@ il2cpp=%u kind=%@",image,rva,[sem[@"resolved"] boolValue]?1:0,[o[@"nativeTarget"] objectForKey:@"kind"]?:@"");}'''
new='''if(a){NSDictionary *sem=HFATIL2CPPSemantic(a);o[@"targetIL2CPP"]=sem;NSDictionary *native=HFATNativeTargetClassify(a,sem);o[@"nativeTarget"]=native;if(![sem[@"resolved"] boolValue])o[@"nativeEntrySemantic"]=HFATNativeEntrySemantic(a,native);NSString *nk=[native[@"kind"] description]?:@"";NSLog(@"[V031316-TARGET-CLASS] mechanism=fixed-patch target=%@+%@ il2cpp=%u kind=%@",image,rva,[sem[@"resolved"] boolValue]?1:0,nk);HFATBundleLog("[V031316-TARGET-CLASS] mechanism=fixed-patch target=%s+%s il2cpp=%u kind=%s\\n",[image UTF8String]?:"?",[rva UTF8String]?:"?",[sem[@"resolved"] boolValue]?1:0,[nk UTF8String]?:"?");}'''
if old not in s: raise SystemExit('v031317 fixed target anchor missing')
s=s.replace(old,new,1)

# Hooks: same enrichment when a target itself remains non-IL2CPP.
old='''if(original)o[@"originalPointer"]=HFATAddressInfo(original);if(target){o[@"targetAddress"]=HFATAddressInfo(target);NSDictionary *sem=HFATIL2CPPSemantic(target);o[@"targetIL2CPP"]=sem;o[@"nativeTarget"]=HFATNativeTargetClassify(target,sem);NSLog(@"[V031316-TARGET-CLASS] mechanism=runtime-hook target=%@+%@ il2cpp=%u kind=%@",targetImage,targetRVA,[sem[@"resolved"] boolValue]?1:0,[o[@"nativeTarget"] objectForKey:@"kind"]?:@"");}if(replacement)o[@"replacementAddress"]=HFATAddressInfo(replacement);'''
new='''if(original)o[@"originalPointer"]=HFATAddressInfo(original);if(target){o[@"targetAddress"]=HFATAddressInfo(target);NSDictionary *sem=HFATIL2CPPSemantic(target);o[@"targetIL2CPP"]=sem;NSDictionary *native=HFATNativeTargetClassify(target,sem);o[@"nativeTarget"]=native;if(![sem[@"resolved"] boolValue])o[@"nativeEntrySemantic"]=HFATNativeEntrySemantic(target,native);NSString *nk=[native[@"kind"] description]?:@"";NSLog(@"[V031316-TARGET-CLASS] mechanism=runtime-hook target=%@+%@ il2cpp=%u kind=%@",targetImage,targetRVA,[sem[@"resolved"] boolValue]?1:0,nk);HFATBundleLog("[V031316-TARGET-CLASS] mechanism=runtime-hook target=%s+%s il2cpp=%u kind=%s\\n",[targetImage UTF8String]?:"?",[targetRVA UTF8String]?:"?",[sem[@"resolved"] boolValue]?1:0,[nk UTF8String]?:"?");}if(replacement)o[@"replacementAddress"]=HFATAddressInfo(replacement);'''
if old not in s: raise SystemExit('v031317 hook target anchor missing')
s=s.replace(old,new,1)

# Bridge hook ingestion to the bundle log as requested by the v031316 field run.
old='''NSLog(@"[V031316-HOOK-INGEST] backend=%@ type=%@ semanticStatus=%@ reason=%@ installed=%u",v[@"backendId"],v[@"sourceBackendType"],v[@"sourceSemanticStatus"],v[@"ingestionReason"],[v[@"installed"] boolValue]?1:0);'''
new='''NSLog(@"[V031316-HOOK-INGEST] backend=%@ type=%@ semanticStatus=%@ reason=%@ installed=%u",v[@"backendId"],v[@"sourceBackendType"],v[@"sourceSemanticStatus"],v[@"ingestionReason"],[v[@"installed"] boolValue]?1:0);HFATBundleLog("[V031316-HOOK-INGEST] backend=%s type=%s semanticStatus=%s reason=%s installed=%u\\n",[[v[@"backendId"] description] UTF8String]?:"?",[[v[@"sourceBackendType"] description] UTF8String]?:"?",[[v[@"sourceSemanticStatus"] description] UTF8String]?:"?",[[v[@"ingestionReason"] description] UTF8String]?:"?",[v[@"installed"] boolValue]?1:0);'''
if old not in s: raise SystemExit('v031317 hook-ingest log anchor missing')
s=s.replace(old,new,1)

s=s.replace('com.hfa.runtime-modification-truth/v0.3.13.16','com.hfa.runtime-modification-truth/v0.3.13.17')
TRUTH.write_text(s)

t=TRACE.read_text()
t=t.replace('HFAMap_RuntimeModificationTruth_v031316.json','HFAMap_RuntimeModificationTruth_v031317.json')
t=t.replace('[V031316-TRUTH-FILE]','[V031317-TRUTH-FILE]')
t=t.replace('[V031316-TRUTH-SUMMARY]','[V031317-TRUTH-SUMMARY]')
t=t.replace('[V031316-MOD-SEMANTIC]','[V031317-MOD-SEMANTIC]')
TRACE.write_text(t)

u=UI.read_text()
u=u.replace('HFAMap RuntimeAnalyzer v0.3.13.16 TruthStabilizerNativeClassifier','HFAMap RuntimeAnalyzer v0.3.13.17 NativeEntrySemanticResolver')
UI.write_text(u)

for token in ['HFATNativeEntrySemantic','[V031317-NATIVE-ENTRY]','[V031317-NATIVE-EDGE]','nativeEntrySemantic','HFATBundleLog','com.hfa.runtime-modification-truth/v0.3.13.17']:
    if token not in TRUTH.read_text(): raise SystemExit('v031317 truth token missing '+token)
for token in ['[V031317-TRUTH-SUMMARY]','[V031317-MOD-SEMANTIC]','[V031317-TRUTH-FILE]','HFAMap_RuntimeModificationTruth_v031317.json']:
    if token not in TRACE.read_text(): raise SystemExit('v031317 trace token missing '+token)
if 'v0.3.13.17 NativeEntrySemanticResolver' not in UI.read_text(): raise SystemExit('v031317 UI marker missing')
print('v0.3.13.17 native entry semantic resolver applied')

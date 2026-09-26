from pathlib import Path

ROOT=Path('hfamap')
SEM=ROOT/'src'/'HFARuntimeSemanticAnalyzer.m'


def function_span(text,name):
    i=text.find(name+'(')
    if i<0: raise SystemExit(name+' missing')
    start=text.rfind('\n',0,i)+1
    b=text.find('{',i)
    if b<0: raise SystemExit(name+' body missing')
    depth=0; instr=False; esc=False
    for j in range(b,len(text)):
        ch=text[j]
        if instr:
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch=='"': instr=False
            continue
        if ch=='"': instr=True; continue
        if ch=='{': depth+=1
        elif ch=='}':
            depth-=1
            if depth==0:return start,j+1
    raise SystemExit(name+' unterminated')

s=SEM.read_text()

# Generic exact in-image writable state recorder. This intentionally excludes
# heap/object-field accesses so consumer binding cannot overfit arbitrary pointers.
anchor='NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacementBounded('
if anchor not in s: raise SystemExit('bounded semantic entry missing')
if 'HFASemRecordStateAccess' not in s:
    helper=r'''
static BOOL HFASemInImageWritable(uintptr_t address, HFASemImage image){
    return address && image.writableStart && address>=image.writableStart && address<image.writableEnd;
}
static void HFASemRecordStateAccess(NSMutableArray *out, NSMutableSet *seen,
                                    NSString *access, NSString *kind,
                                    uintptr_t address, uintptr_t pc,
                                    HFASemImage image, unsigned reg){
    if(!out||!seen||!access.length||!kind.length||!HFASemInImageWritable(address,image))return;
    NSString *key=[NSString stringWithFormat:@"%@:%llX:%llX:%u",access,(unsigned long long)address,(unsigned long long)pc,reg];
    if([seen containsObject:key])return;[seen addObject:key];
    [out addObject:@{@"access":access,@"kind":kind,@"exact":@YES,
                     @"runtimeAddress":@((unsigned long long)address),
                     @"rva":HFASemRVA(address,image),@"sourceRVA":HFASemRVA(pc,image),
                     @"register":@(reg)}];
}
'''
    s=s.replace(anchor,helper+'\n'+anchor,1)

a,b=function_span(s,'HFASemanticAnalyzeReplacementBounded')
fn=s[a:b]

vars_anchor='''    NSMutableArray *argumentFlows=[NSMutableArray array];'''
if vars_anchor not in fn: raise SystemExit('v037 semantic vars anchor missing')
fn=fn.replace(vars_anchor,vars_anchor+'''\n    NSMutableArray *semanticNodes=[NSMutableArray array];\n    NSMutableArray *stateAccesses=[NSMutableArray array];\n    NSMutableSet *seenStateAccess=[NSMutableSet set];''',1)

cf_old='''        if(HFASemConditional(w))conditional=YES;if(HFASemRET(w)){hasReachableReturn=YES;continue;}'''
cf_new=r'''        if(HFASemConditional(w)){
            conditional=YES;uintptr_t bt=0;BOOL hasTarget=HFASemConditionalTarget(w,pc,&bt);
            BOOL targetRet=NO,fallRet=NO;NSUInteger ti=0;
            if(hasTarget&&HFASemIndexForTarget(bt,replacement,count,&ti))targetRet=HFASemPathToRet(words,count,replacement,image,ti);
            if(i+1<count)fallRet=HFASemPathToRet(words,count,replacement,image,i+1);
            NSMutableDictionary *node=[@{@"kind":(targetRet||fallRet)?@"conditional-return-path":@"conditional-branch",
                                         @"rva":HFASemRVA(pc,image),@"reachable":@YES,
                                         @"targetReachesReturn":@(targetRet),@"fallthroughReachesReturn":@(fallRet)} mutableCopy];
            if(hasTarget&&bt>=image.base)node[@"targetRVA"]=HFASemRVA(bt,image);
            if(pc+4>=image.base)node[@"fallthroughRVA"]=HFASemRVA(pc+4,image);
            [semanticNodes addObject:node];
        }
        if(HFASemRET(w)){
            hasReachableReturn=YES;NSMutableDictionary *node=[@{@"kind":constKnown[0]?@"constant-return":@"return",
                                                               @"rva":HFASemRVA(pc,image),@"reachable":@YES} mutableCopy];
            if(constKnown[0])node[@"value"]=@(constValue[0]);[semanticNodes addObject:node];continue;
        }'''
if cf_old not in fn: raise SystemExit('v037 control-flow anchor missing')
fn=fn.replace(cf_old,cf_new,1)

ldr='''        if(HFASemLdrX(w,&rd,&rn,&off)){\n            uintptr_t eff=addrKnown[rn]?addr[rn]+off:0;'''
if ldr not in fn: raise SystemExit('v037 LDR anchor missing')
fn=fn.replace(ldr,'''        if(HFASemLdrX(w,&rd,&rn,&off)){\n            uintptr_t eff=addrKnown[rn]?addr[rn]+off:0;\n            HFASemRecordStateAccess(stateAccesses,seenStateAccess,@"read",@"ldr-global",eff,pc,image,rd);''',1)

atomic_load='''        if(HFASemLDAR64(w,&ar,&ab)||HFASemLDAXR64(w,&ar,&ab)){receiverTaint[ar]=NO;addrKnown[ar]=NO;continue;}'''
if atomic_load not in fn: raise SystemExit('v037 atomic-load anchor missing')
fn=fn.replace(atomic_load,'''        if(HFASemLDAR64(w,&ar,&ab)||HFASemLDAXR64(w,&ar,&ab)){uintptr_t src=addrKnown[ab]?addr[ab]:0;HFASemRecordStateAccess(stateAccesses,seenStateAccess,@"read",@"atomic-load",src,pc,image,ar);receiverTaint[ar]=NO;addrKnown[ar]=NO;continue;}''',1)

atomic_store='''            uintptr_t dst=addrKnown[ab]?addr[ab]:0;\n            if(dst&&dst!=originalSlot&&HFASemWritable(dst,image)&&receiverTaint[ar]){'''
if atomic_store not in fn: raise SystemExit('v037 atomic-store anchor missing')
fn=fn.replace(atomic_store,'''            uintptr_t dst=addrKnown[ab]?addr[ab]:0;\n            HFASemRecordStateAccess(stateAccesses,seenStateAccess,@"write",@"atomic-store",dst,pc,image,ar);\n            if(dst&&dst!=originalSlot&&HFASemWritable(dst,image)&&receiverTaint[ar]){''',1)

strx='''        if(HFASemStrX(w,&rd,&rn,&off)){\n            uintptr_t dst=addrKnown[rn]?addr[rn]+off:0;'''
if strx not in fn: raise SystemExit('v037 STR anchor missing')
fn=fn.replace(strx,'''        if(HFASemStrX(w,&rd,&rn,&off)){\n            uintptr_t dst=addrKnown[rn]?addr[rn]+off:0;\n            HFASemRecordStateAccess(stateAccesses,seenStateAccess,@"write",@"str-global",dst,pc,image,rd);''',1)

# Normalize arithmetic/callback evidence into semanticNodes without changing
# the existing classification logic.
class_anchor='''    unsigned returnTransforms=(returnMul?1u:0u)+(returnDiv?1u:0u)+(returnSelect?1u:0u);'''
if class_anchor not in fn: raise SystemExit('v037 classification anchor missing')
normalize=r'''    for(NSDictionary *op in ops){
        NSString *name=[op[@"op"] isKindOfClass:NSString.class]?op[@"op"]:@"";
        if(!name.length||[name isEqual:@"CALL_ORIGINAL"]||[name isEqual:@"TAILCALL_ORIGINAL"])continue;
        NSMutableDictionary *node=[@{@"kind":@"operation",@"op":name,@"reachable":@YES} mutableCopy];
        if([op[@"rva"] isKindOfClass:NSString.class])node[@"rva"]=op[@"rva"];
        if(op[@"phase"])node[@"phase"]=op[@"phase"];
        if(op[@"argumentIndex"])node[@"argumentIndex"]=op[@"argumentIndex"];
        [semanticNodes addObject:node];
    }
    for(NSDictionary *cr in constantReturns){
        NSMutableDictionary *node=[@{@"kind":@"constant-return",@"reachable":@YES} mutableCopy];
        if(cr[@"sourceRVA"])node[@"rva"]=cr[@"sourceRVA"];
        if(cr[@"value"])node[@"value"]=cr[@"value"];
        if(cr[@"path"])node[@"path"]=cr[@"path"];
        [semanticNodes addObject:node];
    }
'''
fn=fn.replace(class_anchor,normalize+class_anchor,1)

ret_key='''        @"argumentFlows":argumentFlows?:@[]'''
if ret_key not in fn: raise SystemExit('v037 semantic return anchor missing')
fn=fn.replace(ret_key,ret_key+''',\n        @"semanticNodes":semanticNodes?:@[],\n        @"stateAccesses":stateAccesses?:@[]''',1)

s=s[:a]+fn+s[b:]
s=s.replace('HFAMap_RuntimeAnalyzer_v036_stage.log','HFAMap_RuntimeAnalyzer_v037_stage.log')
s=s.replace('V036-','V037-')
SEM.write_text(s)

for required in ['semanticNodes','stateAccesses','conditional-return-path','HFASemRecordStateAccess','atomic-load','atomic-store']:
    if required not in s: raise SystemExit('missing '+required)
print('v0.3.7 semantic nodes + exact state access evidence applied')

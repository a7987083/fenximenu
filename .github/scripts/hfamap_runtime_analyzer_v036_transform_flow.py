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
a,b=function_span(s,'HFASemanticAnalyzeReplacementBounded')
fn=s[a:b]

anchor='''    BOOL constKnown[32]={0}; uint64_t constValue[32]={0};'''
if anchor not in fn: raise SystemExit('transform arrays anchor missing')
fn=fn.replace(anchor,anchor+'''\n    uint8_t intArgTransform[32]={0}; uintptr_t intArgTransformSource[32]={0};\n    uint8_t fpArgTransform[32]={0}; uintptr_t fpArgTransformSource[32]={0};\n    NSMutableArray *argumentFlows=[NSMutableArray array];''',1)

mov='''        if(HFASemMovReg(w,&rd,&rm)){addrKnown[rd]=addrKnown[rm];addr[rd]=addr[rm];originalReg[rd]=originalReg[rm];receiverTaint[rd]=receiverTaint[rm];receiverOffset[rd]=receiverOffset[rm];intReturnTaint[rd]=intReturnTaint[rm];fpReturnTaint[rd]=fpReturnTaint[rm];constKnown[rd]=constKnown[rm];constValue[rd]=constValue[rm];continue;}'''
if mov not in fn: raise SystemExit('mov propagation anchor missing')
fn=fn.replace(mov,'''        if(HFASemMovReg(w,&rd,&rm)){addrKnown[rd]=addrKnown[rm];addr[rd]=addr[rm];originalReg[rd]=originalReg[rm];receiverTaint[rd]=receiverTaint[rm];receiverOffset[rd]=receiverOffset[rm];intReturnTaint[rd]=intReturnTaint[rm];fpReturnTaint[rd]=fpReturnTaint[rm];constKnown[rd]=constKnown[rm];constValue[rd]=constValue[rm];intArgTransform[rd]=intArgTransform[rm];intArgTransformSource[rd]=intArgTransformSource[rm];fpArgTransform[rd]=fpArgTransform[rm];fpArgTransformSource[rd]=fpArgTransformSource[rm];continue;}''',1)

add='''        if(HFASemAddImm64(w,&rd,&rn,&imm)){if(addrKnown[rn]){addr[rd]=addr[rn]+imm;addrKnown[rd]=YES;HFASemRecordMaterialized(materializedAddresses,seenMaterialized,addr[rd],@"ADRP/ADD",pc,image);}else addrKnown[rd]=NO;if(receiverTaint[rn]){receiverTaint[rd]=YES;receiverOffset[rd]=receiverOffset[rn]+(uint32_t)imm;}continue;}'''
if add in fn:
    fn=fn.replace(add,'''        if(HFASemAddImm64(w,&rd,&rn,&imm)){if(addrKnown[rn]){addr[rd]=addr[rn]+imm;addrKnown[rd]=YES;HFASemRecordMaterialized(materializedAddresses,seenMaterialized,addr[rd],@"ADRP/ADD",pc,image);}else addrKnown[rd]=NO;if(receiverTaint[rn]){receiverTaint[rd]=YES;receiverOffset[rd]=receiverOffset[rn]+(uint32_t)imm;}intArgTransform[rd]=intArgTransform[rn];intArgTransformSource[rd]=intArgTransformSource[rn];continue;}''',1)

mul_start=fn.find('        if(HFASemMUL(w,&rd,&rn,&rm)){')
fp_start=fn.find('        NSString *fp=HFASemFPOp',mul_start)
if mul_start<0 or fp_start<0: raise SystemExit('mul block missing')
mul='''        if(HFASemMUL(w,&rd,&rn,&rm)){
            BOOL ret=intReturnTaint[rn]||intReturnTaint[rm];
            intReturnTaint[rd]=ret;
            if(ret){returnMul=YES;[ops addObject:@{@"op":@"MUL",@"phase":@"after-original",@"rva":HFASemRVA(pc,image)}];}
            else if(!callsOriginal){intArgTransform[rd]|=1u;intArgTransformSource[rd]=pc;if(rd<8){argMul=YES;[ops addObject:@{@"op":@"MUL",@"phase":@"before-original",@"argumentIndex":@(rd),@"rva":HFASemRVA(pc,image)}];}else [ops addObject:@{@"op":@"MUL",@"phase":@"pre-original-transform",@"rva":HFASemRVA(pc,image)}];}
            continue;
        }
'''
fn=fn[:mul_start]+mul+fn[fp_start:]

# Preserve generic FP transforms in temporary V registers. Existing direct-argument
# detection remains, while the taint is also available at the original call site.
needle='''if(fp){BOOL ret=fpReturnTaint[rn]||fpReturnTaint[rm];BOOL arg=(rd<8)&&!callsOriginal;fpReturnTaint[rd]=ret;'''
if needle not in fn: raise SystemExit('fp transform anchor missing')
fn=fn.replace(needle,'''if(fp){BOOL ret=fpReturnTaint[rn]||fpReturnTaint[rm];BOOL arg=(rd<8)&&!callsOriginal;fpReturnTaint[rd]=ret;if(!ret&&!callsOriginal){if([fp isEqual:@"FMUL"]){fpArgTransform[rd]|=1u;fpArgTransformSource[rd]=pc;}if([fp isEqual:@"FDIV"]){fpArgTransform[rd]|=2u;fpArgTransformSource[rd]=pc;}}''',1)

call='''            if(originalReg[br]){callsOriginal=YES;memset(intReturnTaint,0,sizeof(intReturnTaint));memset(fpReturnTaint,0,sizeof(fpReturnTaint));intReturnTaint[0]=YES;fpReturnTaint[0]=YES;[ops addObject:@{@"op":@"CALL_ORIGINAL",@"rva":HFASemRVA(pc,image)}];}'''
if call not in fn: raise SystemExit('original call anchor missing')
call_repl='''            if(originalReg[br]){
                for(unsigned arx=0;arx<8;arx++){
                    if(intArgTransform[arx]&1u){argMul=YES;[argumentFlows addObject:@{@"kind":@"integer-multiply",@"argumentIndex":@(arx),@"sourceRVA":HFASemRVA(intArgTransformSource[arx],image),@"callRVA":HFASemRVA(pc,image)}];}
                    if(intArgTransform[arx]&2u){argDiv=YES;[argumentFlows addObject:@{@"kind":@"integer-divide",@"argumentIndex":@(arx),@"sourceRVA":HFASemRVA(intArgTransformSource[arx],image),@"callRVA":HFASemRVA(pc,image)}];}
                    if(fpArgTransform[arx]&1u){argMul=YES;[argumentFlows addObject:@{@"kind":@"float-multiply",@"argumentIndex":@(arx),@"sourceRVA":HFASemRVA(fpArgTransformSource[arx],image),@"callRVA":HFASemRVA(pc,image)}];}
                    if(fpArgTransform[arx]&2u){argDiv=YES;[argumentFlows addObject:@{@"kind":@"float-divide",@"argumentIndex":@(arx),@"sourceRVA":HFASemRVA(fpArgTransformSource[arx],image),@"callRVA":HFASemRVA(pc,image)}];}
                }
                callsOriginal=YES;memset(intReturnTaint,0,sizeof(intReturnTaint));memset(fpReturnTaint,0,sizeof(fpReturnTaint));intReturnTaint[0]=YES;fpReturnTaint[0]=YES;[ops addObject:@{@"op":@"CALL_ORIGINAL",@"rva":HFASemRVA(pc,image)}];
            }'''
fn=fn.replace(call,call_repl,1)

ret='''        @"materializedAddresses":materializedAddresses?:[]'''
# The exact generated return is Objective-C @[]; patch by a stable neighboring key instead.
key='''        @"materializedAddresses":materializedAddresses?:@[]'''
if key not in fn: raise SystemExit('semantic return materialized key missing')
fn=fn.replace(key,key+''',\n        @"argumentFlows":argumentFlows?:@[]''',1)

s=s[:a]+fn+s[b:]
SEM.write_text(s)

for required in ['intArgTransform','argumentFlows','integer-multiply','pre-original-transform']:
    if required not in s: raise SystemExit('missing '+required)
for forbidden in ['RandomDice','SPGainMulti','WayOfKings','RogueLegend','MeChat']:
    if forbidden in s: raise SystemExit('game-specific token leaked into transform layer: '+forbidden)
print('v0.3.6 transform-flow propagation applied')

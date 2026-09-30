from pathlib import Path

GENERIC=Path('hfamap/src/HFAMapGenericMenuResolver.m')
UI=Path('hfamap/src/HFAMapCyberUI.m')


def function_span(text, signature):
    start=text.find(signature)
    if start<0: raise SystemExit('missing function: '+signature)
    brace=text.find('{',start)
    if brace<0: raise SystemExit('missing brace: '+signature)
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
    raise SystemExit('unterminated function: '+signature)


g=GENERIC.read_text()
a,b=function_span(g,'static NSDictionary *HFA03138SenderIdentifierDataflow(Method method, NSDictionary *discriminator)')
fn=g[a:b]

old='BOOL tainted[32]={0};uint64_t senderAddend[32]={0};tainted[2]=YES;'
new='BOOL tainted[32]={0};uint64_t senderAddend[32]={0};uint8_t derivedDepth[32]={0};tainted[2]=YES;derivedDepth[2]=0;'
if old not in fn: raise SystemExit('taint declaration anchor missing')
fn=fn.replace(old,new,1)

old='NSMutableSet *taintedSlots=[NSMutableSet set];\n    NSMutableArray *stackTransfers=[NSMutableArray array],*loads=[NSMutableArray array],*branches=[NSMutableArray array],*calls=[NSMutableArray array];'
new='NSMutableSet *taintedSlots=[NSMutableSet set];\n    NSMutableDictionary *slotDepth=[NSMutableDictionary dictionary];\n    NSMutableArray *stackTransfers=[NSMutableArray array],*loads=[NSMutableArray array],*branches=[NSMutableArray array],*calls=[NSMutableArray array],*derivedEvents=[NSMutableArray array];'
if old not in fn: raise SystemExit('collection anchor missing')
fn=fn.replace(old,new,1)

fn=fn.replace('tainted[rd]=tainted[rn];senderAddend[rd]=tainted[rn]?senderAddend[rn]+imm:0;','tainted[rd]=tainted[rn];senderAddend[rd]=tainted[rn]?senderAddend[rn]+imm:0;derivedDepth[rd]=tainted[rn]?derivedDepth[rn]:0;',1)
fn=fn.replace('tainted[rd]=tainted[rn];senderAddend[rd]=tainted[rn]?senderAddend[rn]-imm:0;','tainted[rd]=tainted[rn];senderAddend[rd]=tainted[rn]?senderAddend[rn]-imm:0;derivedDepth[rd]=tainted[rn]?derivedDepth[rn]:0;',1)
fn=fn.replace('tainted[rd]=tainted[rm];senderAddend[rd]=senderAddend[rm];\n            stackBaseKnown[rd]','tainted[rd]=tainted[rm];senderAddend[rd]=senderAddend[rm];derivedDepth[rd]=tainted[rm]?derivedDepth[rm]:0;\n            stackBaseKnown[rd]',1)

old='if(tainted[rn]&&isLoad){uint64_t effective=senderAddend[rn]+imm;NSDictionary *r=@{@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"baseRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"fieldOffsetValue":@(effective),@"matchesIdentifierField":@(effective==wanted),@"via":@"register"};if(loads.count<96)[loads addObject:r];if(effective==wanted){matched=YES;matchedOff=off;tainted[rt]=YES;senderAddend[rt]=0;HFAGenericLog("[V03139-IDFIELD-LOAD] via=register off=0x%X base=x%u dst=x%u field=0x%llX match=1\\n",off,rn,rt,(unsigned long long)effective);}}'
new='if(tainted[rn]&&isLoad){uint64_t effective=senderAddend[rn]+imm;NSDictionary *r=@{@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"baseRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"fieldOffsetValue":@(effective),@"matchesIdentifierField":@(effective==wanted),@"via":@"register",@"sourceDepth":@(derivedDepth[rn])};if(loads.count<128)[loads addObject:r];if(size==3){uint8_t nd=(uint8_t)MIN((unsigned)derivedDepth[rn]+1u,15u);tainted[rt]=YES;senderAddend[rt]=0;derivedDepth[rt]=nd;NSDictionary *de=@{@"type":@"object-load",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"sourceRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"depth":@(nd),@"identifierMatch":@(effective==wanted)};if(derivedEvents.count<192)[derivedEvents addObject:de];HFAGenericLog("[V031310-DERIVED] type=object-load off=0x%X src=x%u dst=x%u field=0x%llX depth=%u match=%u\\n",off,rn,rt,(unsigned long long)effective,nd,effective==wanted);if(effective==wanted){matched=YES;matchedOff=off;HFAGenericLog("[V031310-IDFIELD-LOAD] via=derived-register off=0x%X base=x%u dst=x%u field=0x%llX depth=%u match=1\\n",off,rn,rt,(unsigned long long)effective,nd);}}}'
if old not in fn: raise SystemExit('unsigned load anchor missing')
fn=fn.replace(old,new,1)

old='if(tainted[rn]&&isLoad){int64_t effective=(int64_t)senderAddend[rn]+imm;NSDictionary *r=@{@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"baseRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"fieldOffsetValue":@((unsigned long long)effective),@"matchesIdentifierField":@(effective==(int64_t)wanted),@"via":@"register-unscaled"};if(loads.count<96)[loads addObject:r];if(effective==(int64_t)wanted){matched=YES;matchedOff=off;tainted[rt]=YES;senderAddend[rt]=0;HFAGenericLog("[V03139-IDFIELD-LOAD] via=register-unscaled off=0x%X base=x%u dst=x%u field=0x%llX match=1\\n",off,rn,rt,(unsigned long long)effective);}}'
new='if(tainted[rn]&&isLoad){int64_t effective=(int64_t)senderAddend[rn]+imm;NSDictionary *r=@{@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"baseRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"fieldOffsetValue":@((unsigned long long)effective),@"matchesIdentifierField":@(effective==(int64_t)wanted),@"via":@"register-unscaled",@"sourceDepth":@(derivedDepth[rn])};if(loads.count<128)[loads addObject:r];if(size==3){uint8_t nd=(uint8_t)MIN((unsigned)derivedDepth[rn]+1u,15u);tainted[rt]=YES;senderAddend[rt]=0;derivedDepth[rt]=nd;NSDictionary *de=@{@"type":@"object-load-unscaled",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"sourceRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"depth":@(nd),@"identifierMatch":@(effective==(int64_t)wanted)};if(derivedEvents.count<192)[derivedEvents addObject:de];HFAGenericLog("[V031310-DERIVED] type=object-load-unscaled off=0x%X src=x%u dst=x%u field=0x%llX depth=%u match=%u\\n",off,rn,rt,(unsigned long long)effective,nd,effective==(int64_t)wanted);if(effective==(int64_t)wanted){matched=YES;matchedOff=off;HFAGenericLog("[V031310-IDFIELD-LOAD] via=derived-register-unscaled off=0x%X base=x%u dst=x%u field=0x%llX depth=%u match=1\\n",off,rn,rt,(unsigned long long)effective,nd);}}}'
if old not in fn: raise SystemExit('unscaled load anchor missing')
fn=fn.replace(old,new,1)

# Stack slot depth propagation.
fn=fn.replace('if([taintedSlots containsObject:key]){tainted[rt]=YES;senderAddend[rt]=0;NSDictionary *r=', 'if([taintedSlots containsObject:key]){tainted[rt]=YES;senderAddend[rt]=0;derivedDepth[rt]=(uint8_t)[[slotDepth objectForKey:key] unsignedIntValue];NSDictionary *r=',2)
fn=fn.replace('else if(tainted[rt]){[taintedSlots addObject:key];NSDictionary *r=', 'else if(tainted[rt]){[taintedSlots addObject:key];[slotDepth setObject:@(derivedDepth[rt]) forKey:key];NSDictionary *r=',2)
fn=fn.replace('[taintedSlots addObject:key];NSDictionary *r=@{@"type":@"call-memory-transfer"', '[taintedSlots addObject:key];[slotDepth setObject:@(derivedDepth[1]) forKey:key];NSDictionary *r=@{@"type":@"call-memory-transfer"',1)

old='if((ins&0xFC000000u)==0x94000000u){\n            int64_t d=HFA03135SignExtend(ins&0x03FFFFFFu,26)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+d);NSDictionary *ai=HFAAddressInfo((void*)target);'
new='if((ins&0xFC000000u)==0x94000000u){\n            int64_t d=HFA03135SignExtend(ins&0x03FFFFFFu,26)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+d);NSDictionary *ai=HFAAddressInfo((void*)target);BOOL hasTaintedArg=NO;uint8_t argDepth=15;unsigned argMask=0;for(unsigned ar=0;ar<8;ar++){if(tainted[ar]){hasTaintedArg=YES;argMask|=(1u<<ar);if(derivedDepth[ar]<argDepth)argDepth=derivedDepth[ar];}}'
if old not in fn: raise SystemExit('direct call anchor missing')
fn=fn.replace(old,new,1)

old='for(unsigned r=0;r<=17;r++){tainted[r]=NO;senderAddend[r]=0;stackBaseKnown[r]=NO;stackBaseOffset[r]=0;}\n            continue;'
new='for(unsigned r=0;r<=17;r++){tainted[r]=NO;senderAddend[r]=0;derivedDepth[r]=0;stackBaseKnown[r]=NO;stackBaseOffset[r]=0;}if(hasTaintedArg){uint8_t nd=(uint8_t)MIN((unsigned)argDepth+1u,15u);tainted[0]=YES;senderAddend[0]=0;derivedDepth[0]=nd;NSDictionary *de=@{@"type":@"call-return",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"argumentMask":@(argMask),@"depth":@(nd),@"target":ai?:@{},@"candidateOnly":@YES};if(derivedEvents.count<192)[derivedEvents addObject:de];HFAGenericLog("[V031310-RETURN] type=BL off=0x%X args=0x%X depth=%u image=%s rva=%s\\n",off,argMask,nd,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}continue;'
if old not in fn: raise SystemExit('call clobber anchor missing')
fn=fn.replace(old,new,1)

# Indirect BLR: tainted arguments imply candidate derived return in x0.
insert_anchor='if(matched && off>=matchedOff && off<=matchedOff+0x100){'
idx=fn.find(insert_anchor)
if idx<0: raise SystemExit('post-call branch anchor missing')
blr=r'''if((ins&0xFFFFFC1Fu)==0xD63F0000u){
            unsigned targetReg=(ins>>5)&31;BOOL hasTaintedArg=NO;uint8_t argDepth=15;unsigned argMask=0;for(unsigned ar=0;ar<8;ar++){if(tainted[ar]){hasTaintedArg=YES;argMask|=(1u<<ar);if(derivedDepth[ar]<argDepth)argDepth=derivedDepth[ar];}}
            for(unsigned r=0;r<=17;r++){tainted[r]=NO;senderAddend[r]=0;derivedDepth[r]=0;stackBaseKnown[r]=NO;stackBaseOffset[r]=0;}
            if(hasTaintedArg){uint8_t nd=(uint8_t)MIN((unsigned)argDepth+1u,15u);tainted[0]=YES;derivedDepth[0]=nd;NSDictionary *de=@{@"type":@"indirect-call-return",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"targetRegister":@(targetReg),@"argumentMask":@(argMask),@"depth":@(nd),@"candidateOnly":@YES};if(derivedEvents.count<192)[derivedEvents addObject:de];HFAGenericLog("[V031310-RETURN] type=BLR off=0x%X target=x%u args=0x%X depth=%u\n",off,targetReg,argMask,nd);}
            continue;
        }

        '''
fn=fn[:idx]+blr+fn[idx:]

old='return @{@"candidateOnly":@YES,@"discriminator":discriminator,@"identifierFieldLoads":loads,@"matchedIdentifierFieldLoad":@(matched),@"stackTransfers":stackTransfers,@"taintedStackSlots":@(taintedSlots.count),@"nearbyBranches":branches,@"nearbyCalls":calls,@"scanBytes":@(scanLimit),@"stackAware":@YES};'
new='return @{@"candidateOnly":@YES,@"discriminator":discriminator,@"identifierFieldLoads":loads,@"matchedIdentifierFieldLoad":@(matched),@"stackTransfers":stackTransfers,@"taintedStackSlots":@(taintedSlots.count),@"derivedObjectEvents":derivedEvents,@"nearbyBranches":branches,@"nearbyCalls":calls,@"scanBytes":@(scanLimit),@"stackAware":@YES,@"objectReturnAware":@YES};'
if old not in fn: raise SystemExit('return dictionary anchor missing')
fn=fn.replace(old,new,1)

g=g[:a]+fn+g[b:]

a,b=function_span(g,'void HFAGenericMenuObserveAction(id sender, id target, SEL action)')
obs=g[a:b]
log_anchor='HFAGenericLog("[V03139-STACK-SUMMARY]'
idx=obs.find(log_anchor)
if idx<0: raise SystemExit('v03139 summary anchor missing')
stmt='HFAGenericLog("[V031310-OBJECT-SUMMARY] identifier=%s derivedEvents=%u matchedLoad=%s branches=%u calls=%u\\n",identifier.UTF8String?:"?",(unsigned)[[senderIdentifierDataflow objectForKey:@"derivedObjectEvents"] count],[[[senderIdentifierDataflow objectForKey:@"matchedIdentifierFieldLoad"] description] UTF8String]?:"0",(unsigned)[[senderIdentifierDataflow objectForKey:@"nearbyBranches"] count],(unsigned)[[senderIdentifierDataflow objectForKey:@"nearbyCalls"] count]);\n        '
obs=obs[:idx]+stmt+obs[idx:]
g=g[:a]+obs+g[b:]
GENERIC.write_text(g)

u=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.9 StackAwareSenderDataflow','HFAMap RuntimeAnalyzer v0.3.13.10 ObjectReturnTaintResolver')
UI.write_text(u)

for path,markers in [
    (GENERIC,['[V031310-DERIVED]','[V031310-RETURN]','[V031310-IDFIELD-LOAD]','[V031310-OBJECT-SUMMARY]','derivedObjectEvents','@"objectReturnAware":@YES']),
    (UI,['v0.3.13.10 ObjectReturnTaintResolver'])]:
    text=path.read_text()
    for marker in markers:
        if marker not in text: raise SystemExit('missing v031310 marker '+marker)
print('v0.3.13.10 object-return taint resolver applied')

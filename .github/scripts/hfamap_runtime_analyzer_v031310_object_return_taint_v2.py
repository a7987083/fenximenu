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
new=r'''static NSDictionary *HFA03138SenderIdentifierDataflow(Method method, NSDictionary *discriminator){
    if(!method||![discriminator isKindOfClass:[NSDictionary class]]||!discriminator.count)return @{};
    uintptr_t start=(uintptr_t)method_getImplementation(method);if(!start)return @{};
    NSUInteger wanted=[[discriminator objectForKey:@"offsetValue"] unsignedIntegerValue];
    BOOL tainted[32]={0};uint64_t senderAddend[32]={0};uint8_t derivedDepth[32]={0};tainted[2]=YES;
    BOOL stackBaseKnown[32]={0};int64_t stackBaseOffset[32]={0};stackBaseKnown[31]=YES;stackBaseOffset[31]=0;
    NSMutableSet *taintedSlots=[NSMutableSet set];NSMutableDictionary *slotDepth=[NSMutableDictionary dictionary];
    NSMutableArray *stackTransfers=[NSMutableArray array],*loads=[NSMutableArray array],*branches=[NSMutableArray array],*calls=[NSMutableArray array],*derivedEvents=[NSMutableArray array];
    BOOL matched=NO;unsigned matchedOff=0;unsigned scanLimit=0x10000;
    for(unsigned off=0;off<scanLimit;off+=4){
        uint32_t ins=0;memcpy(&ins,(void*)(start+off),4);uintptr_t pc=start+off;
        // ADD Xd, Xn, #imm
        if((ins&0xFF000000u)==0x91000000u){unsigned rd=ins&31,rn=(ins>>5)&31;uint64_t imm=(ins>>10)&0xFFF;if((ins>>22)&1)imm<<=12;tainted[rd]=tainted[rn];senderAddend[rd]=tainted[rn]?senderAddend[rn]+imm:0;derivedDepth[rd]=tainted[rn]?derivedDepth[rn]:0;stackBaseKnown[rd]=stackBaseKnown[rn];stackBaseOffset[rd]=stackBaseKnown[rn]?stackBaseOffset[rn]+(int64_t)imm:0;continue;}
        // SUB Xd, Xn, #imm
        if((ins&0xFF000000u)==0xD1000000u){unsigned rd=ins&31,rn=(ins>>5)&31;uint64_t imm=(ins>>10)&0xFFF;if((ins>>22)&1)imm<<=12;tainted[rd]=tainted[rn];senderAddend[rd]=tainted[rn]?senderAddend[rn]-imm:0;derivedDepth[rd]=tainted[rn]?derivedDepth[rn]:0;stackBaseKnown[rd]=stackBaseKnown[rn];stackBaseOffset[rd]=stackBaseKnown[rn]?stackBaseOffset[rn]-(int64_t)imm:0;continue;}
        // MOV Xd, Xn alias (ORR Xd, XZR, Xn)
        if((ins&0xFFE0FFE0u)==0xAA0003E0u){unsigned rd=ins&31,rm=(ins>>16)&31;tainted[rd]=tainted[rm];senderAddend[rd]=senderAddend[rm];derivedDepth[rd]=tainted[rm]?derivedDepth[rm]:0;stackBaseKnown[rd]=stackBaseKnown[rm];stackBaseOffset[rd]=stackBaseOffset[rm];continue;}
        // LDR/STR unsigned immediate.
        if((ins&0x3B000000u)==0x39000000u){unsigned rn=(ins>>5)&31,rt=ins&31,size=(ins>>30)&3;uint64_t imm=((ins>>10)&0xFFFULL)<<size;BOOL isLoad=((ins>>22)&1)!=0;
            if(stackBaseKnown[rn]){int64_t slot=stackBaseOffset[rn]+(int64_t)imm;NSString *key=HFA03139StackKey(slot);if(isLoad&&[taintedSlots containsObject:key]){tainted[rt]=YES;senderAddend[rt]=0;derivedDepth[rt]=(uint8_t)[[slotDepth objectForKey:key] unsignedIntValue];NSDictionary *r=@{@"type":@"reload",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"slot":@(slot),@"register":@(rt),@"depth":@(derivedDepth[rt])};if(stackTransfers.count<160)[stackTransfers addObject:r];HFAGenericLog("[V03139-STACK] type=reload off=0x%X slot=%lld reg=x%u depth=%u\n",off,(long long)slot,rt,derivedDepth[rt]);}else if(!isLoad&&tainted[rt]){[taintedSlots addObject:key];[slotDepth setObject:@(derivedDepth[rt]) forKey:key];NSDictionary *r=@{@"type":@"spill",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"slot":@(slot),@"register":@(rt),@"depth":@(derivedDepth[rt])};if(stackTransfers.count<160)[stackTransfers addObject:r];HFAGenericLog("[V03139-STACK] type=spill off=0x%X slot=%lld reg=x%u depth=%u\n",off,(long long)slot,rt,derivedDepth[rt]);}}
            if(tainted[rn]&&isLoad){uint64_t effective=senderAddend[rn]+imm;BOOL idMatch=(effective==wanted);NSDictionary *r=@{@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"baseRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"fieldOffsetValue":@(effective),@"matchesIdentifierField":@(idMatch),@"via":@"register",@"sourceDepth":@(derivedDepth[rn])};if(loads.count<160)[loads addObject:r];if(size==3){unsigned nd=(unsigned)derivedDepth[rn]+1u;if(nd>15)nd=15;tainted[rt]=YES;senderAddend[rt]=0;derivedDepth[rt]=(uint8_t)nd;NSDictionary *de=@{@"type":@"object-load",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"sourceRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"depth":@(nd),@"identifierMatch":@(idMatch)};if(derivedEvents.count<256)[derivedEvents addObject:de];HFAGenericLog("[V031310-DERIVED] type=object-load off=0x%X src=x%u dst=x%u field=0x%llX depth=%u match=%u\n",off,rn,rt,(unsigned long long)effective,nd,idMatch);if(idMatch){matched=YES;matchedOff=off;HFAGenericLog("[V031310-IDFIELD-LOAD] via=derived-register off=0x%X base=x%u dst=x%u field=0x%llX depth=%u match=1\n",off,rn,rt,(unsigned long long)effective,nd);}}}
            continue;
        }
        // LDUR/STUR unscaled immediate.
        if((ins&0x3B200C00u)==0x38000000u){unsigned rn=(ins>>5)&31,rt=ins&31,size=(ins>>30)&3;int64_t imm=HFA03135SignExtend((ins>>12)&0x1FF,9);BOOL isLoad=((ins>>22)&1)!=0;
            if(stackBaseKnown[rn]){int64_t slot=stackBaseOffset[rn]+imm;NSString *key=HFA03139StackKey(slot);if(isLoad&&[taintedSlots containsObject:key]){tainted[rt]=YES;senderAddend[rt]=0;derivedDepth[rt]=(uint8_t)[[slotDepth objectForKey:key] unsignedIntValue];NSDictionary *r=@{@"type":@"reload-unscaled",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"slot":@(slot),@"register":@(rt),@"depth":@(derivedDepth[rt])};if(stackTransfers.count<160)[stackTransfers addObject:r];HFAGenericLog("[V03139-STACK] type=reload-unscaled off=0x%X slot=%lld reg=x%u depth=%u\n",off,(long long)slot,rt,derivedDepth[rt]);}else if(!isLoad&&tainted[rt]){[taintedSlots addObject:key];[slotDepth setObject:@(derivedDepth[rt]) forKey:key];NSDictionary *r=@{@"type":@"spill-unscaled",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"slot":@(slot),@"register":@(rt),@"depth":@(derivedDepth[rt])};if(stackTransfers.count<160)[stackTransfers addObject:r];HFAGenericLog("[V03139-STACK] type=spill-unscaled off=0x%X slot=%lld reg=x%u depth=%u\n",off,(long long)slot,rt,derivedDepth[rt]);}}
            if(tainted[rn]&&isLoad){int64_t effective=(int64_t)senderAddend[rn]+imm;BOOL idMatch=(effective==(int64_t)wanted);NSDictionary *r=@{@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"baseRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"fieldOffsetValue":@((unsigned long long)effective),@"matchesIdentifierField":@(idMatch),@"via":@"register-unscaled",@"sourceDepth":@(derivedDepth[rn])};if(loads.count<160)[loads addObject:r];if(size==3){unsigned nd=(unsigned)derivedDepth[rn]+1u;if(nd>15)nd=15;tainted[rt]=YES;senderAddend[rt]=0;derivedDepth[rt]=(uint8_t)nd;NSDictionary *de=@{@"type":@"object-load-unscaled",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"sourceRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"depth":@(nd),@"identifierMatch":@(idMatch)};if(derivedEvents.count<256)[derivedEvents addObject:de];HFAGenericLog("[V031310-DERIVED] type=object-load-unscaled off=0x%X src=x%u dst=x%u field=0x%llX depth=%u match=%u\n",off,rn,rt,(unsigned long long)effective,nd,idMatch);if(idMatch){matched=YES;matchedOff=off;HFAGenericLog("[V031310-IDFIELD-LOAD] via=derived-register-unscaled off=0x%X base=x%u dst=x%u field=0x%llX depth=%u match=1\n",off,rn,rt,(unsigned long long)effective,nd);}}}
            continue;
        }
        // Direct BL: model stack-like strong-store transfer and candidate object return.
        if((ins&0xFC000000u)==0x94000000u){int64_t d=HFA03135SignExtend(ins&0x03FFFFFFu,26)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+d);NSDictionary *ai=HFAAddressInfo((void*)target);BOOL hasTaintedArg=NO;uint8_t argDepth=15;unsigned argMask=0;for(unsigned ar=0;ar<8;ar++){if(tainted[ar]){hasTaintedArg=YES;argMask|=(1u<<ar);if(derivedDepth[ar]<argDepth)argDepth=derivedDepth[ar];}}
            if(tainted[1]&&stackBaseKnown[0]){int64_t slot=stackBaseOffset[0];NSString *key=HFA03139StackKey(slot);[taintedSlots addObject:key];[slotDepth setObject:@(derivedDepth[1]) forKey:key];NSDictionary *r=@{@"type":@"call-memory-transfer",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"slot":@(slot),@"sourceRegister":@1,@"depth":@(derivedDepth[1]),@"target":ai?:@{}};if(stackTransfers.count<160)[stackTransfers addObject:r];HFAGenericLog("[V03139-STACK] type=call-memory-transfer off=0x%X slot=%lld src=x1 depth=%u image=%s rva=%s\n",off,(long long)slot,derivedDepth[1],[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}
            if(matched&&off>=matchedOff&&off<=matchedOff+0x100&&ai&&calls.count<64){NSMutableDictionary *r=[ai mutableCopy];r[@"callsiteRVA"]=[NSString stringWithFormat:@"0x%X",off];[calls addObject:r];[r release];HFAGenericLog("[V03139-IDFIELD-CALL] off=0x%X image=%s rva=%s\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}
            for(unsigned r=0;r<=17;r++){tainted[r]=NO;senderAddend[r]=0;derivedDepth[r]=0;stackBaseKnown[r]=NO;stackBaseOffset[r]=0;}
            if(hasTaintedArg){unsigned nd=(unsigned)argDepth+1u;if(nd>15)nd=15;tainted[0]=YES;derivedDepth[0]=(uint8_t)nd;NSDictionary *de=@{@"type":@"call-return",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"argumentMask":@(argMask),@"depth":@(nd),@"target":ai?:@{},@"candidateOnly":@YES};if(derivedEvents.count<256)[derivedEvents addObject:de];HFAGenericLog("[V031310-RETURN] type=BL off=0x%X args=0x%X depth=%u image=%s rva=%s\n",off,argMask,nd,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}continue;
        }
        // BLR: preserve only candidate return provenance.
        if((ins&0xFFFFFC1Fu)==0xD63F0000u){unsigned targetReg=(ins>>5)&31;BOOL hasTaintedArg=NO;uint8_t argDepth=15;unsigned argMask=0;for(unsigned ar=0;ar<8;ar++){if(tainted[ar]){hasTaintedArg=YES;argMask|=(1u<<ar);if(derivedDepth[ar]<argDepth)argDepth=derivedDepth[ar];}}for(unsigned r=0;r<=17;r++){tainted[r]=NO;senderAddend[r]=0;derivedDepth[r]=0;stackBaseKnown[r]=NO;stackBaseOffset[r]=0;}if(hasTaintedArg){unsigned nd=(unsigned)argDepth+1u;if(nd>15)nd=15;tainted[0]=YES;derivedDepth[0]=(uint8_t)nd;NSDictionary *de=@{@"type":@"indirect-call-return",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"targetRegister":@(targetReg),@"argumentMask":@(argMask),@"depth":@(nd),@"candidateOnly":@YES};if(derivedEvents.count<256)[derivedEvents addObject:de];HFAGenericLog("[V031310-RETURN] type=BLR off=0x%X target=x%u args=0x%X depth=%u\n",off,targetReg,argMask,nd);}continue;}
        if(matched&&off>=matchedOff&&off<=matchedOff+0x100){if((ins&0x7E000000u)==0x34000000u){int64_t imm=HFA03135SignExtend((ins>>5)&0x7FFFF,19)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+imm);NSDictionary *ai=HFAAddressInfo((void*)target);NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObjectsAndKeys:@"CBZ/CBNZ",@"type",[NSString stringWithFormat:@"0x%X",off],@"insnRVA",nil];if(ai)[r addEntriesFromDictionary:ai];if(branches.count<64)[branches addObject:r];HFAGenericLog("[V03139-IDFIELD-BRANCH] type=CBZ off=0x%X target=%s+%s\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}else if((ins&0x7E000000u)==0x36000000u){int64_t imm=HFA03135SignExtend((ins>>5)&0x3FFF,14)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+imm);NSDictionary *ai=HFAAddressInfo((void*)target);NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObjectsAndKeys:@"TBZ/TBNZ",@"type",[NSString stringWithFormat:@"0x%X",off],@"insnRVA",nil];if(ai)[r addEntriesFromDictionary:ai];if(branches.count<64)[branches addObject:r];HFAGenericLog("[V03139-IDFIELD-BRANCH] type=TBZ off=0x%X target=%s+%s\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}else if((ins&0xFF000010u)==0x54000000u){int64_t imm=HFA03135SignExtend((ins>>5)&0x7FFFF,19)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+imm);NSDictionary *ai=HFAAddressInfo((void*)target);NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObjectsAndKeys:@"B.cond",@"type",[NSString stringWithFormat:@"0x%X",off],@"insnRVA",nil];if(ai)[r addEntriesFromDictionary:ai];if(branches.count<64)[branches addObject:r];HFAGenericLog("[V03139-IDFIELD-BRANCH] type=B.cond off=0x%X target=%s+%s\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}}
        if((ins&0x7F800000u)==0x52800000u||(ins&0x7F800000u)==0x12800000u){unsigned rd=ins&31;tainted[rd]=NO;senderAddend[rd]=0;derivedDepth[rd]=0;stackBaseKnown[rd]=NO;stackBaseOffset[rd]=0;}
    }
    HFAGenericLog("[V03139-STACK-SUMMARY] transfers=%u slots=%u matched=%u scan=0x%X\n",(unsigned)stackTransfers.count,(unsigned)taintedSlots.count,matched,scanLimit);
    return @{@"candidateOnly":@YES,@"discriminator":discriminator,@"identifierFieldLoads":loads,@"matchedIdentifierFieldLoad":@(matched),@"stackTransfers":stackTransfers,@"taintedStackSlots":@(taintedSlots.count),@"derivedObjectEvents":derivedEvents,@"nearbyBranches":branches,@"nearbyCalls":calls,@"scanBytes":@(scanLimit),@"stackAware":@YES,@"objectReturnAware":@YES};
}'''
g=g[:a]+new+g[b:]

a,b=function_span(g,'void HFAGenericMenuObserveAction(id sender, id target, SEL action)')
obs=g[a:b]
if '[V031310-OBJECT-SUMMARY]' not in obs:
    anchor='HFAGenericLog("[V03139-STACK-SUMMARY]'
    idx=obs.find(anchor)
    if idx<0: raise SystemExit('observer stack summary anchor missing')
    stmt='HFAGenericLog("[V031310-OBJECT-SUMMARY] identifier=%s derivedEvents=%u matchedLoad=%s branches=%u calls=%u\\n",identifier.UTF8String?:"?",(unsigned)[[senderIdentifierDataflow objectForKey:@"derivedObjectEvents"] count],[[[senderIdentifierDataflow objectForKey:@"matchedIdentifierFieldLoad"] description] UTF8String]?:"0",(unsigned)[[senderIdentifierDataflow objectForKey:@"nearbyBranches"] count],(unsigned)[[senderIdentifierDataflow objectForKey:@"nearbyCalls"] count]);\n        '
    obs=obs[:idx]+stmt+obs[idx:]
    g=g[:a]+obs+g[b:]
GENERIC.write_text(g)

u=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.9 StackAwareSenderDataflow','HFAMap RuntimeAnalyzer v0.3.13.10 ObjectReturnTaintResolver')
UI.write_text(u)
for path,markers in [(GENERIC,['[V031310-DERIVED]','[V031310-RETURN]','[V031310-IDFIELD-LOAD]','[V031310-OBJECT-SUMMARY]','derivedObjectEvents','@"objectReturnAware":@YES']),(UI,['v0.3.13.10 ObjectReturnTaintResolver'])]:
    text=path.read_text()
    for marker in markers:
        if marker not in text: raise SystemExit('missing v031310 marker '+marker)
print('v0.3.13.10 object-return taint v2 applied')

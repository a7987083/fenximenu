from pathlib import Path

GENERIC=Path('hfamap/src/HFAMapGenericMenuResolver.m')
EXPORTER=Path('hfamap/src/HFAMapJSONExport.m')
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
new=r'''static NSString *HFA03139StackKey(int64_t absoluteOffset){
    return [NSString stringWithFormat:@"%lld",(long long)absoluteOffset];
}
static NSDictionary *HFA03138SenderIdentifierDataflow(Method method, NSDictionary *discriminator){
    if(!method||![discriminator isKindOfClass:[NSDictionary class]]||!discriminator.count)return @{};
    uintptr_t start=(uintptr_t)method_getImplementation(method);if(!start)return @{};
    NSUInteger wanted=[[discriminator objectForKey:@"offsetValue"] unsignedIntegerValue];
    BOOL tainted[32]={0};uint64_t senderAddend[32]={0};tainted[2]=YES;
    BOOL stackBaseKnown[32]={0};int64_t stackBaseOffset[32]={0};
    stackBaseKnown[31]=YES;stackBaseOffset[31]=0; // entry SP
    NSMutableSet *taintedSlots=[NSMutableSet set];
    NSMutableArray *stackTransfers=[NSMutableArray array],*loads=[NSMutableArray array],*branches=[NSMutableArray array],*calls=[NSMutableArray array];
    BOOL matched=NO;unsigned matchedOff=0;unsigned scanLimit=0x10000;
    for(unsigned off=0;off<scanLimit;off+=4){
        uint32_t ins=0;memcpy(&ins,(void*)(start+off),4);uintptr_t pc=start+off;

        // ADD Xd, Xn, #imm. This also covers MOV Xd, SP (ADD #0).
        if((ins&0xFF000000u)==0x91000000u){
            unsigned rd=ins&31,rn=(ins>>5)&31;uint64_t imm=(ins>>10)&0xFFF;if((ins>>22)&1)imm<<=12;
            if(stackBaseKnown[rn]){stackBaseKnown[rd]=YES;stackBaseOffset[rd]=stackBaseOffset[rn]+(int64_t)imm;}else stackBaseKnown[rd]=NO;
            tainted[rd]=tainted[rn];senderAddend[rd]=tainted[rn]?senderAddend[rn]+imm:0;
            continue;
        }
        // SUB Xd, Xn, #imm. Track stack/frame aliases and sender-derived pointers.
        if((ins&0xFF000000u)==0xD1000000u){
            unsigned rd=ins&31,rn=(ins>>5)&31;uint64_t imm=(ins>>10)&0xFFF;if((ins>>22)&1)imm<<=12;
            if(stackBaseKnown[rn]){stackBaseKnown[rd]=YES;stackBaseOffset[rd]=stackBaseOffset[rn]-(int64_t)imm;}else stackBaseKnown[rd]=NO;
            tainted[rd]=tainted[rn];senderAddend[rd]=tainted[rn]?senderAddend[rn]-imm:0;
            continue;
        }
        // MOV Xd, Xm alias ORR Xd, XZR, Xm.
        if((ins&0xFFE0FFE0u)==0xAA0003E0u){
            unsigned rd=ins&31,rm=(ins>>16)&31;
            tainted[rd]=tainted[rm];senderAddend[rd]=senderAddend[rm];
            stackBaseKnown[rd]=stackBaseKnown[rm];stackBaseOffset[rd]=stackBaseOffset[rm];
            continue;
        }

        // Unsigned immediate load/store family.
        if((ins&0x3B000000u)==0x39000000u){
            unsigned rn=(ins>>5)&31,rt=ins&31;unsigned size=(ins>>30)&3;uint64_t imm=((ins>>10)&0xFFFULL)<<size;BOOL isLoad=((ins>>22)&1)!=0;
            if(tainted[rn]&&isLoad){uint64_t effective=senderAddend[rn]+imm;NSDictionary *r=@{@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"baseRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"fieldOffsetValue":@(effective),@"matchesIdentifierField":@(effective==wanted),@"via":@"register"};if(loads.count<96)[loads addObject:r];if(effective==wanted){matched=YES;matchedOff=off;tainted[rt]=YES;senderAddend[rt]=0;HFAGenericLog("[V03139-IDFIELD-LOAD] via=register off=0x%X base=x%u dst=x%u field=0x%llX match=1\\n",off,rn,rt,(unsigned long long)effective);}}
            if(stackBaseKnown[rn]){
                int64_t slot=stackBaseOffset[rn]+(int64_t)imm;NSString *key=HFA03139StackKey(slot);
                if(isLoad){if([taintedSlots containsObject:key]){tainted[rt]=YES;senderAddend[rt]=0;NSDictionary *r=@{@"type":@"reload",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"slot":key,@"register":@(rt)};if(stackTransfers.count<128)[stackTransfers addObject:r];HFAGenericLog("[V03139-STACK] type=reload off=0x%X slot=%s reg=x%u\\n",off,key.UTF8String?:"?",rt);}}
                else if(tainted[rt]){[taintedSlots addObject:key];NSDictionary *r=@{@"type":@"spill",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"slot":key,@"register":@(rt)};if(stackTransfers.count<128)[stackTransfers addObject:r];HFAGenericLog("[V03139-STACK] type=spill off=0x%X slot=%s reg=x%u\\n",off,key.UTF8String?:"?",rt);}
            }
            continue;
        }

        // Unscaled LDUR/STUR family (signed imm9), required by clang ARC spills.
        if((ins&0x3B200C00u)==0x38000000u){
            unsigned rn=(ins>>5)&31,rt=ins&31;unsigned size=(ins>>30)&3;int64_t imm=HFA03135SignExtend((ins>>12)&0x1FF,9);BOOL isLoad=((ins>>22)&1)!=0;
            if(tainted[rn]&&isLoad){int64_t effective=(int64_t)senderAddend[rn]+imm;NSDictionary *r=@{@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"baseRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"fieldOffsetValue":@((unsigned long long)effective),@"matchesIdentifierField":@(effective==(int64_t)wanted),@"via":@"register-unscaled"};if(loads.count<96)[loads addObject:r];if(effective==(int64_t)wanted){matched=YES;matchedOff=off;tainted[rt]=YES;senderAddend[rt]=0;HFAGenericLog("[V03139-IDFIELD-LOAD] via=register-unscaled off=0x%X base=x%u dst=x%u field=0x%llX match=1\\n",off,rn,rt,(unsigned long long)effective);}}
            if(stackBaseKnown[rn]){
                int64_t slot=stackBaseOffset[rn]+imm;NSString *key=HFA03139StackKey(slot);
                if(isLoad){if([taintedSlots containsObject:key]){tainted[rt]=YES;senderAddend[rt]=0;NSDictionary *r=@{@"type":@"reload-unscaled",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"slot":key,@"register":@(rt)};if(stackTransfers.count<128)[stackTransfers addObject:r];HFAGenericLog("[V03139-STACK] type=reload-unscaled off=0x%X slot=%s reg=x%u\\n",off,key.UTF8String?:"?",rt);}}
                else if(tainted[rt]){[taintedSlots addObject:key];NSDictionary *r=@{@"type":@"spill-unscaled",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"slot":key,@"register":@(rt)};if(stackTransfers.count<128)[stackTransfers addObject:r];HFAGenericLog("[V03139-STACK] type=spill-unscaled off=0x%X slot=%s reg=x%u\\n",off,key.UTF8String?:"?",rt);}
            }
            (void)size;continue;
        }

        // Direct call. Conservatively model ARC-style memory transfer when x1 is sender-tainted
        // and x0 is a known stack address (matches observed objc_storeStrong ground truth).
        if((ins&0xFC000000u)==0x94000000u){
            int64_t d=HFA03135SignExtend(ins&0x03FFFFFFu,26)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+d);NSDictionary *ai=HFAAddressInfo((void*)target);
            if(tainted[1]&&stackBaseKnown[0]){NSString *key=HFA03139StackKey(stackBaseOffset[0]);[taintedSlots addObject:key];NSDictionary *r=@{@"type":@"call-memory-transfer",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"slot":key,@"sourceRegister":@1,@"candidateOnly":@YES};if(stackTransfers.count<128)[stackTransfers addObject:r];HFAGenericLog("[V03139-STACK] type=call-transfer off=0x%X slot=%s source=x1\\n",off,key.UTF8String?:"?");}
            if(matched && off>=matchedOff && off<=matchedOff+0x100){if(ai&&calls.count<64){NSMutableDictionary *r=[ai mutableCopy];r[@"callsiteRVA"]=[NSString stringWithFormat:@"0x%X",off];[calls addObject:r];[r release];HFAGenericLog("[V03139-IDFIELD-CALL] off=0x%X image=%s rva=%s\\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}}
            for(unsigned r=0;r<=17;r++){tainted[r]=NO;senderAddend[r]=0;stackBaseKnown[r]=NO;stackBaseOffset[r]=0;}
            continue;
        }

        if(matched && off>=matchedOff && off<=matchedOff+0x100){
            if((ins&0x7E000000u)==0x34000000u){int64_t imm=HFA03135SignExtend((ins>>5)&0x7FFFF,19)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+imm);NSDictionary *ai=HFAAddressInfo((void*)target);NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObjectsAndKeys:@"CBZ/CBNZ",@"type",[NSString stringWithFormat:@"0x%X",off],@"insnRVA",nil];if(ai)[r addEntriesFromDictionary:ai];if(branches.count<64)[branches addObject:r];HFAGenericLog("[V03139-IDFIELD-BRANCH] type=CBZ off=0x%X target=%s+%s\\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}
            else if((ins&0x7E000000u)==0x36000000u){int64_t imm=HFA03135SignExtend((ins>>5)&0x3FFF,14)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+imm);NSDictionary *ai=HFAAddressInfo((void*)target);NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObjectsAndKeys:@"TBZ/TBNZ",@"type",[NSString stringWithFormat:@"0x%X",off],@"insnRVA",nil];if(ai)[r addEntriesFromDictionary:ai];if(branches.count<64)[branches addObject:r];HFAGenericLog("[V03139-IDFIELD-BRANCH] type=TBZ off=0x%X target=%s+%s\\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}
            else if((ins&0xFF000010u)==0x54000000u){int64_t imm=HFA03135SignExtend((ins>>5)&0x7FFFF,19)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+imm);NSDictionary *ai=HFAAddressInfo((void*)target);NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObjectsAndKeys:@"B.cond",@"type",[NSString stringWithFormat:@"0x%X",off],@"insnRVA",nil];if(ai)[r addEntriesFromDictionary:ai];if(branches.count<64)[branches addObject:r];HFAGenericLog("[V03139-IDFIELD-BRANCH] type=B.cond off=0x%X target=%s+%s\\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}
        }
    }
    return @{@"candidateOnly":@YES,@"discriminator":discriminator,@"identifierFieldLoads":loads,@"matchedIdentifierFieldLoad":@(matched),@"stackTransfers":stackTransfers,@"taintedStackSlots":@(taintedSlots.count),@"nearbyBranches":branches,@"nearbyCalls":calls,@"scanBytes":@(scanLimit),@"stackAware":@YES};
}'''
g=g[:a]+new+g[b:]

a,b=function_span(g,'void HFAGenericMenuObserveAction(id sender, id target, SEL action)')
fn=g[a:b]
log_anchor='HFAGenericLog("[V03138-IDFIELD]'
idx=fn.find(log_anchor)
if idx<0: raise SystemExit('v03138 idfield log anchor missing')
stmt='HFAGenericLog("[V03139-STACK-SUMMARY] identifier=%s stackTransfers=%u stackSlots=%u matchedLoad=%s branches=%u calls=%u scan=0x%X\\n",identifier.UTF8String?:"?",(unsigned)[[senderIdentifierDataflow objectForKey:@"stackTransfers"] count],[[senderIdentifierDataflow objectForKey:@"taintedStackSlots"] unsignedIntValue],[[[senderIdentifierDataflow objectForKey:@"matchedIdentifierFieldLoad"] description] UTF8String]?:"0",(unsigned)[[senderIdentifierDataflow objectForKey:@"nearbyBranches"] count],(unsigned)[[senderIdentifierDataflow objectForKey:@"nearbyCalls"] count],[[senderIdentifierDataflow objectForKey:@"scanBytes"] unsignedIntValue]);\n        '
fn=fn[:idx]+stmt+fn[idx:]
g=g[:a]+fn+g[b:]
GENERIC.write_text(g)

u=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.8 SenderIdentifierDataflowResolver','HFAMap RuntimeAnalyzer v0.3.13.9 StackAwareSenderDataflow')
UI.write_text(u)

for path,markers in [
    (GENERIC,['[V03139-STACK]','[V03139-STACK-SUMMARY]','[V03139-IDFIELD-LOAD]','@"stackAware":@YES','0x10000']),
    (UI,['v0.3.13.9 StackAwareSenderDataflow'])]:
    text=path.read_text()
    for marker in markers:
        if marker not in text: raise SystemExit('missing v03139 marker '+marker)
print('v0.3.13.9 stack-aware sender dataflow applied')

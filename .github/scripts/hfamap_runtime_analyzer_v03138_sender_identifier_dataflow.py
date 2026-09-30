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

# ---------------------------------------------------------------------------
# Sender identifier discriminator + bounded ARM64 x2(sender)-taint dataflow.
# This is analysis-only: no unknown game selectors are invoked and no state is
# mutated. Evidence stays candidateOnly until downstream semantic closure.
# ---------------------------------------------------------------------------
g=GENERIC.read_text()
anchor='void HFAGenericMenuObserveAction(id sender, id target, SEL action)'
pos=g.find(anchor)
if pos<0: raise SystemExit('action observer anchor missing')
if 'HFA03138IdentifierDiscriminator' not in g:
    helpers=r'''
static NSDictionary *HFA03138IdentifierDiscriminator(id sender, NSString *identifier){
    if(!sender||!identifier.length)return @{};Class cls=object_getClass(sender);NSUInteger instanceSize=cls?class_getInstanceSize(cls):0;
    for(Class cursor=cls;cursor&&cursor!=[NSObject class];cursor=class_getSuperclass(cursor)){
        unsigned count=0;Ivar *ivars=class_copyIvarList(cursor,&count);if(count>64)count=64;
        for(unsigned i=0;ivars&&i<count;i++){
            Ivar iv=ivars[i];const char *type=ivar_getTypeEncoding(iv);if(!type||type[0]!='@')continue;
            id value=nil;@try{value=object_getIvar(sender,iv);}@catch(__unused id ex){value=nil;}
            if(![value isKindOfClass:[NSString class]]||![(NSString*)value isEqualToString:identifier])continue;
            ptrdiff_t off=ivar_getOffset(iv);if(off<0||(NSUInteger)off>=instanceSize)continue;
            NSDictionary *r=@{@"ownerClass":[NSString stringWithUTF8String:class_getName(cursor)?:"?"],@"ivarName":[NSString stringWithUTF8String:ivar_getName(iv)?:"?"],@"offset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)off],@"offsetValue":@((unsigned long long)off),@"identifier":identifier};
            free(ivars);return r;
        }
        free(ivars);
    }
    return @{};
}
static NSDictionary *HFA03138SenderIdentifierDataflow(Method method, NSDictionary *discriminator){
    if(!method||![discriminator isKindOfClass:[NSDictionary class]]||!discriminator.count)return @{};
    uintptr_t start=(uintptr_t)method_getImplementation(method);if(!start)return @{};
    NSUInteger wanted=[[discriminator objectForKey:@"offsetValue"] unsignedIntegerValue];
    BOOL tainted[32]={0};uint64_t addend[32]={0};tainted[2]=YES;
    NSMutableArray *loads=[NSMutableArray array],*branches=[NSMutableArray array],*calls=[NSMutableArray array];
    BOOL matched=NO;unsigned matchedOff=0;unsigned scanLimit=0x300;
    for(unsigned off=0;off<scanLimit;off+=4){
        uint32_t ins=0;memcpy(&ins,(void*)(start+off),4);uintptr_t pc=start+off;
        if((ins&0xFFE0FFE0u)==0xAA0003E0u){unsigned rd=ins&31,rn=(ins>>16)&31;tainted[rd]=tainted[rn];addend[rd]=addend[rn];continue;}
        if((ins&0xFF000000u)==0x91000000u){unsigned rd=ins&31,rn=(ins>>5)&31;uint64_t imm=(ins>>10)&0xFFF;if((ins>>22)&1)imm<<=12;tainted[rd]=tainted[rn];addend[rd]=tainted[rn]?addend[rn]+imm:0;continue;}
        if((ins&0x3B000000u)==0x39000000u){unsigned rn=(ins>>5)&31,rt=ins&31;unsigned size=(ins>>30)&3;uint64_t imm=((ins>>10)&0xFFFULL)<<size;BOOL isLoad=((ins>>22)&1)!=0;
            if(tainted[rn]){uint64_t effective=addend[rn]+imm;if(isLoad){NSDictionary *r=@{@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"baseRegister":@(rn),@"destRegister":@(rt),@"fieldOffset":[NSString stringWithFormat:@"0x%llX",(unsigned long long)effective],@"fieldOffsetValue":@(effective),@"matchesIdentifierField":@(effective==wanted)};if(loads.count<48)[loads addObject:r];if(effective==wanted){matched=YES;matchedOff=off;tainted[rt]=YES;addend[rt]=0;HFAGenericLog("[V03138-IDFIELD-LOAD] off=0x%X senderReg=x%u dst=x%u field=0x%llX match=1\n",off,rn,rt,(unsigned long long)effective);}else{tainted[rt]=NO;addend[rt]=0;}}}
            continue;
        }
        if(matched && off>=matchedOff && off<=matchedOff+0xA0){
            if((ins&0x7E000000u)==0x34000000u){int64_t imm=HFA03135SignExtend((ins>>5)&0x7FFFF,19)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+imm);NSDictionary *ai=HFAAddressInfo((void*)target);NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObjectsAndKeys:@"CBZ/CBNZ",@"type",[NSString stringWithFormat:@"0x%X",off],@"insnRVA",nil];if(ai)[r addEntriesFromDictionary:ai];if(branches.count<32)[branches addObject:r];HFAGenericLog("[V03138-IDFIELD-BRANCH] type=CBZ off=0x%X target=%s+%s\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}
            else if((ins&0x7E000000u)==0x36000000u){int64_t imm=HFA03135SignExtend((ins>>5)&0x3FFF,14)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+imm);NSDictionary *ai=HFAAddressInfo((void*)target);NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObjectsAndKeys:@"TBZ/TBNZ",@"type",[NSString stringWithFormat:@"0x%X",off],@"insnRVA",nil];if(ai)[r addEntriesFromDictionary:ai];if(branches.count<32)[branches addObject:r];HFAGenericLog("[V03138-IDFIELD-BRANCH] type=TBZ off=0x%X target=%s+%s\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}
            else if((ins&0xFF000010u)==0x54000000u){int64_t imm=HFA03135SignExtend((ins>>5)&0x7FFFF,19)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+imm);NSDictionary *ai=HFAAddressInfo((void*)target);NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObjectsAndKeys:@"B.cond",@"type",[NSString stringWithFormat:@"0x%X",off],@"insnRVA",nil];if(ai)[r addEntriesFromDictionary:ai];if(branches.count<32)[branches addObject:r];HFAGenericLog("[V03138-IDFIELD-BRANCH] type=B.cond off=0x%X target=%s+%s\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}
            if((ins&0xFC000000u)==0x94000000u){int64_t d=HFA03135SignExtend(ins&0x03FFFFFFu,26)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+d);NSDictionary *ai=HFAAddressInfo((void*)target);if(ai&&calls.count<32){NSMutableDictionary *r=[ai mutableCopy];r[@"callsiteRVA"]=[NSString stringWithFormat:@"0x%X",off];[calls addObject:r];[r release];HFAGenericLog("[V03138-IDFIELD-CALL] off=0x%X image=%s rva=%s\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}}
        }
        if((ins&0x7F800000u)==0x52800000u || (ins&0x7F800000u)==0x12800000u){unsigned rd=ins&31;tainted[rd]=NO;addend[rd]=0;}
    }
    return @{@"candidateOnly":@YES,@"discriminator":discriminator,@"identifierFieldLoads":loads,@"matchedIdentifierFieldLoad":@(matched),@"nearbyBranches":branches,@"nearbyCalls":calls,@"scanBytes":@(scanLimit)};
}
'''
    g=g[:pos]+helpers+'\n'+g[pos:]

a,b=function_span(g,'void HFAGenericMenuObserveAction(id sender, id target, SEL action)')
fn=g[a:b]
anchor2='NSDictionary *senderState=HFA03137SenderSnapshot(sender);'
if anchor2 not in fn: raise SystemExit('sender state anchor missing')
fn=fn.replace(anchor2,anchor2+'NSDictionary *identifierDiscriminator=HFA03138IdentifierDiscriminator(sender,identifier);NSDictionary *senderIdentifierDataflow=method?HFA03138SenderIdentifierDataflow(method,identifierDiscriminator):@{};',1)
log_anchor='HFAGenericLog("[V03137-SENDER]'
idx=fn.find(log_anchor)
if idx<0: raise SystemExit('sender log anchor missing')
stmt='HFAGenericLog("[V03138-IDFIELD] identifier=%s class=%s ivar=%s offset=%s matchedLoad=%s branches=%u calls=%u\\n",identifier.UTF8String?:"?",[[identifierDiscriminator objectForKey:@"ownerClass"] UTF8String]?:"?",[[identifierDiscriminator objectForKey:@"ivarName"] UTF8String]?:"?",[[identifierDiscriminator objectForKey:@"offset"] UTF8String]?:"?",[[[senderIdentifierDataflow objectForKey:@"matchedIdentifierFieldLoad"] description] UTF8String]?:"0",(unsigned)[[senderIdentifierDataflow objectForKey:@"nearbyBranches"] count],(unsigned)[[senderIdentifierDataflow objectForKey:@"nearbyCalls"] count]);\n        '
fn=fn[:idx]+stmt+fn[idx:]
json_anchor='@"senderState":senderState?:@{}});'
if json_anchor not in fn: raise SystemExit('sender action JSON anchor missing')
fn=fn.replace(json_anchor,'@"senderState":senderState?:@{},@"identifierDiscriminator":identifierDiscriminator?:@{},@"senderIdentifierDataflow":senderIdentifierDataflow?:@{}});',1)
g=g[:a]+fn+g[b:]
GENERIC.write_text(g)

e=EXPORTER.read_text()
a,b=function_span(e,'static NSArray *HFAJSONObservedFeatures(NSString *path, NSUInteger *recordCountOut)')
fn=e[a:b]
needle='NSDictionary *senderState=[row[@"senderState"] isKindOfClass:[NSDictionary class]]?row[@"senderState"]:@{};'
if needle not in fn: raise SystemExit('sender state parse anchor missing')
fn=fn.replace(needle,needle+'NSDictionary *identifierDiscriminator=[row[@"identifierDiscriminator"] isKindOfClass:[NSDictionary class]]?row[@"identifierDiscriminator"]:@{};NSDictionary *senderIdentifierDataflow=[row[@"senderIdentifierDataflow"] isKindOfClass:[NSDictionary class]]?row[@"senderIdentifierDataflow"]:@{};',1)
needle2='if(senderState.count)runtime[@"senderState"]=senderState;'
if needle2 not in fn: raise SystemExit('sender state runtime merge anchor missing')
fn=fn.replace(needle2,needle2+'if(identifierDiscriminator.count)runtime[@"identifierDiscriminator"]=identifierDiscriminator;if(senderIdentifierDataflow.count)runtime[@"senderIdentifierDataflow"]=senderIdentifierDataflow;',1)
e=e[:a]+fn+e[b:]
EXPORTER.write_text(e)

u=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.7 UnifiedFeatureTruthSenderDataflow','HFAMap RuntimeAnalyzer v0.3.13.8 SenderIdentifierDataflowResolver')
UI.write_text(u)

for path,markers in [
    (GENERIC,['HFA03138IdentifierDiscriminator','HFA03138SenderIdentifierDataflow','[V03138-IDFIELD]','[V03138-IDFIELD-LOAD]','senderIdentifierDataflow']),
    (EXPORTER,['identifierDiscriminator','senderIdentifierDataflow']),
    (UI,['v0.3.13.8 SenderIdentifierDataflowResolver'])]:
    text=path.read_text()
    for marker in markers:
        if marker not in text: raise SystemExit('missing v03138 marker '+marker)
print('v0.3.13.8 sender identifier dataflow resolver applied')

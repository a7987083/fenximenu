from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
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

# ---------------------------------------------------------------------------
# 1) Feature-definition label precedence.
#    Preserve semantic titles over transient numeric control values.
# ---------------------------------------------------------------------------
t=TRACE.read_text()
a,b=function_span(t,'void HFARegisterFeatureDefinition(const char *label, const char *identifier)')
helpers=r'''static int HFA03135LabelScore(const char *label,const char *identifier){
    if(!label||!*label)return 0;
    if(identifier&&*identifier&&strcmp(label,identifier)==0)return 10;
    char *end=NULL;strtod(label,&end);if(end&&end!=label&&*end=='\0')return 5;
    int alpha=0,space=0,punct=0;for(const unsigned char *p=(const unsigned char*)label;*p;p++){if((*p>='A'&&*p<='Z')||(*p>='a'&&*p<='z')||*p>=0x80)alpha++;else if(*p==' ')space++;else if(*p!='_'&&*p!='-'&&(*p<'0'||*p>'9'))punct++;}
    if(alpha)return 60+MIN(alpha,30)+MIN(space,10);
    if(space||punct)return 30+MIN(space+punct,20);
    return 15;
}
'''
replacement=r'''void HFARegisterFeatureDefinition(const char *label, const char *identifier) {
    if (!label || !*label || !identifier || !*identifier) return;
    char key[128] = {0};
    size_t identifierLength = strlen(identifier);
    if (identifierLength > 7 && strcmp(identifier + identifierLength - 7, "-switch") == 0)
        snprintf(key, sizeof(key), "%s", identifier);
    else
        snprintf(key, sizeof(key), "%s-switch", identifier);
    for (unsigned i = 0; i < gFeatureDefinitionCount; i++) {
        HFAFeatureDefinition *definition = &gFeatureDefinitions[i];
        if (strcmp(definition->key, key) != 0) continue;
        int oldScore=HFA03135LabelScore(definition->label,definition->identifier);
        int newScore=HFA03135LabelScore(label,identifier);
        if(newScore>oldScore || !definition->label[0]){
            HFALog("[V03135-TITLE-MERGE] key=%s old=%s oldScore=%d new=%s newScore=%d action=replace\n",key,definition->label,oldScore,label,newScore);
            snprintf(definition->label, sizeof(definition->label), "%s", label);
        }else{
            HFALog("[V03135-TITLE-MERGE] key=%s old=%s oldScore=%d new=%s newScore=%d action=keep\n",key,definition->label,oldScore,label,newScore);
        }
        snprintf(definition->identifier, sizeof(definition->identifier), "%s", identifier);
        return;
    }
    if (gFeatureDefinitionCount >= 128) return;
    HFAFeatureDefinition *definition = &gFeatureDefinitions[gFeatureDefinitionCount++];
    memset(definition, 0, sizeof(*definition));
    snprintf(definition->label, sizeof(definition->label), "%s", label);
    snprintf(definition->identifier, sizeof(definition->identifier), "%s", identifier);
    snprintf(definition->key, sizeof(definition->key), "%s", key);
    HFALog("[V03135-TITLE-MERGE] key=%s old=? oldScore=0 new=%s newScore=%d action=create\n",key,label,HFA03135LabelScore(label,identifier));
}'''
t=t[:a]+helpers+'\n'+replacement+t[b:]
TRACE.write_text(t)

# ---------------------------------------------------------------------------
# 2) Input/slider taxonomy + currentValue + bounded ARM64 implementation probe.
# ---------------------------------------------------------------------------
g=GENERIC.read_text()
insert_pos=g.find('static NSString *HFASafeStringGetter')
if insert_pos<0: raise SystemExit('generic helper anchor missing')
helpers=r'''static BOOL HFA03135StringIsNumeric(NSString *s){
    if(![s isKindOfClass:NSString.class]||!s.length)return NO;NSScanner *sc=[NSScanner scannerWithString:s];double v=0;if(![sc scanDouble:&v])return NO;return sc.isAtEnd;
}
static NSString *HFA03135ScalarValue(id object,const char *selectorName){
    if(!object||!selectorName)return nil;SEL sel=sel_registerName(selectorName);Method m=class_getInstanceMethod(object_getClass(object),sel);if(!m)return nil;char *rt=method_copyReturnType(m);if(!rt)return nil;char t=rt[0];free(rt);
    @try{
        if(t=='f'){float v=((float(*)(id,SEL))objc_msgSend)(object,sel);return [NSString stringWithFormat:@"%.6g",v];}
        if(t=='d'){double v=((double(*)(id,SEL))objc_msgSend)(object,sel);return [NSString stringWithFormat:@"%.12g",v];}
        if(t=='q'||t=='Q'||t=='i'||t=='I'||t=='l'||t=='L'||t=='s'||t=='S'||t=='c'||t=='C'||t=='B'){long long v=((long long(*)(id,SEL))objc_msgSend)(object,sel);return [NSString stringWithFormat:@"%lld",v];}
    }@catch(__unused id ex){}
    return nil;
}
static NSString *HFA03135CurrentValue(id object,NSString *rawLabel,NSString *rawKind){
    if(!object)return nil;
    if([object isKindOfClass:UISlider.class])return [NSString stringWithFormat:@"%.6g",((UISlider*)object).value];
    if([object isKindOfClass:UITextField.class])return ((UITextField*)object).text;
    NSString *v=HFA03135ScalarValue(object,"value");if(v.length)return v;
    v=HFASafeStringGetter(object,"text");if(HFA03135StringIsNumeric(v))return v;
    if(([rawKind isEqual:@"slider"]||[rawKind isEqual:@"group"])&&HFA03135StringIsNumeric(rawLabel))return rawLabel;
    return nil;
}
static NSString *HFA03135SemanticKind(id object,NSString *rawKind,NSString *rawLabel){
    if(!object)return rawKind?:@"item";Class cls=object_getClass(object);
    if([object isKindOfClass:UISlider.class])return @"slider";
    if([object isKindOfClass:UITextField.class]||HFAClassHasObjectIvarType(cls,"UITextField"))return @"input";
    if(HFAClassHasSelector(cls,"text")&&HFAClassHasSelector(cls,"setText:"))return @"input";
    if([rawKind isEqual:@"group"]&&HFA03135StringIsNumeric(rawLabel))return @"input";
    return rawKind?:@"item";
}
static int64_t HFA03135SignExtend(uint64_t x,unsigned bits){uint64_t m=1ULL<<(bits-1);return (int64_t)((x^m)-m);}
static NSDictionary *HFA03135ProbeImplementation(Method method){
    if(!method)return @{};uintptr_t start=(uintptr_t)method_getImplementation(method);if(!start)return @{};NSMutableArray *calls=[NSMutableArray array],*mem=[NSMutableArray array];uintptr_t reg[32]={0};BOOL known[32]={0};unsigned retSeen=0;
    for(unsigned off=0;off<0x200;off+=4){uint32_t ins=0;memcpy(&ins,(void*)(start+off),4);uintptr_t pc=start+off;
        if((ins&0xFC000000u)==0x94000000u){int64_t d=HFA03135SignExtend(ins&0x03FFFFFFu,26)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+d);NSDictionary *a=HFAAddressInfo((void*)target);if(a&&calls.count<32){Dl_info di={0};dladdr((void*)target,&di);NSMutableDictionary *r=[a mutableCopy];if(di.dli_sname)r[@"symbol"]=[NSString stringWithUTF8String:di.dli_sname];r[@"callsiteRVA"]=[NSString stringWithFormat:@"0x%X",off];[calls addObject:r];}}
        if((ins&0x9F000000u)==0x90000000u){unsigned rd=ins&31;uint64_t immhi=(ins>>5)&0x7FFFF,immlo=(ins>>29)&3;int64_t imm=HFA03135SignExtend((immhi<<2)|immlo,21)<<12;reg[rd]=((pc)&~0xFFFULL)+imm;known[rd]=YES;continue;}
        if((ins&0xFF000000u)==0x91000000u){unsigned rd=ins&31,rn=(ins>>5)&31;if(known[rn]){uint64_t imm=(ins>>10)&0xFFF;if((ins>>22)&1)imm<<=12;reg[rd]=reg[rn]+imm;known[rd]=YES;NSDictionary *a=HFAAddressInfo((void*)reg[rd]);if(a&&mem.count<48){NSMutableDictionary *r=[a mutableCopy];r[@"kind"]=@"address";r[@"insnRVA"]=[NSString stringWithFormat:@"0x%X",off];[mem addObject:r];}}continue;}
        if((ins&0x3B000000u)==0x39000000u){unsigned rn=(ins>>5)&31;if(known[rn]){unsigned size=(ins>>30)&3;uint64_t imm=((ins>>10)&0xFFFULL)<<size;uintptr_t addr=reg[rn]+imm;NSDictionary *a=HFAAddressInfo((void*)addr);if(a&&mem.count<48){NSMutableDictionary *r=[a mutableCopy];r[@"kind"]=((ins>>22)&1)?@"load":@"store";r[@"insnRVA"]=[NSString stringWithFormat:@"0x%X",off];[mem addObject:r];}}}
        if(ins==0xD65F03C0u&&++retSeen>=1)break;
    }
    NSDictionary *impl=HFAAddressInfo((void*)start)?:@{};return @{@"implementation":impl,@"directCalls":calls,@"memoryRefs":mem,@"scanBytes":@0x200};
}
'''
if 'HFA03135ProbeImplementation' not in g:g=g[:insert_pos]+helpers+'\n'+g[insert_pos:]

# Object observation: keep raw kind, add semantic kind/currentValue.
a,b=function_span(g,'void HFAGenericMenuObserveObject(id object, const char *context)')
fn=g[a:b]
fn=fn.replace('NSString *kind = HFAKindForClass(cls);','NSString *rawKind = HFAKindForClass(cls);\n                NSString *currentValue = HFA03135CurrentValue(object,label,rawKind);\n                NSString *kind = HFA03135SemanticKind(object,rawKind,label);',1)
fn=fn.replace('@"kind": kind,\n                    @"identifier": identifier ?: @"",\n                    @"label": label ?: @"",','@"kind": kind,\n                    @"rawKind": rawKind ?: @"",\n                    @"identifier": identifier ?: @"",\n                    @"label": label ?: @"",\n                    @"currentValue": currentValue ?: @"",',1)
fn=fn.replace('kind.UTF8String, identifier.UTF8String ?: "?", label.UTF8String ?: "?",','kind.UTF8String, identifier.UTF8String ?: "?", label.UTF8String ?: "?",',1)
g=g[:a]+fn+g[b:]

# Action observation: export semantic kind, current value and bounded code evidence.
a,b=function_span(g,'void HFAGenericMenuObserveAction(id sender, id target, SEL action)')
old=g[a:b]
new=r'''void HFAGenericMenuObserveAction(id sender, id target, SEL action) {
    @autoreleasepool {
        Class senderClass = sender ? object_getClass(sender) : Nil;
        Class targetClass = target ? object_getClass(target) : Nil;
        BOOL senderRelevant = senderClass && (HFAClassLooksLikePatchItem(senderClass) || HFADescriptorScoreForClass(senderClass) >= 25);
        BOOL targetRelevant = targetClass && (HFAClassLooksLikePatchItem(targetClass) || HFADescriptorScoreForClass(targetClass) >= 25);
        if (!senderRelevant && !targetRelevant) return;
        HFAGenericMenuObserveObject(sender, "action-sender");HFAGenericMenuObserveObject(target, "action-target");
        Method method = (targetClass && action) ? class_getInstanceMethod(targetClass, action) : NULL;
        NSDictionary *impl = method ? HFAAddressInfo((const void *)method_getImplementation(method)) : nil;
        NSString *identifier = HFASafeStringGetter(sender, "identifier");
        NSString *label = HFALabelForObject(sender);NSString *rawKind=sender?HFAKindForClass(object_getClass(sender)):@"?";NSString *kind=HFA03135SemanticKind(sender,rawKind,label);NSString *currentValue=HFA03135CurrentValue(sender,label,rawKind);NSDictionary *probe=method?HFA03135ProbeImplementation(method):@{};
        const char *actionName = action ? sel_getName(action) : "?";
        HFAGenericLog("[V03135-RUNTIME-VALUE] identifier=%s kind=%s value=%s targetClass=%s action=%s image=%s rva=%s calls=%u memRefs=%u\n",identifier.UTF8String?:"?",kind.UTF8String?:"?",currentValue.UTF8String?:"?",targetClass?class_getName(targetClass):"?",actionName,[[impl objectForKey:@"image"] UTF8String]?:"?",[[impl objectForKey:@"rva"] UTF8String]?:"?",(unsigned)[probe[@"directCalls"] count],(unsigned)[probe[@"memoryRefs"] count]);
        HFAGenericJSON(@{@"record":@"action",@"senderClass":senderClass?[NSString stringWithUTF8String:class_getName(senderClass)]:@"",@"kind":kind?:@"",@"rawKind":rawKind?:@"",@"identifier":identifier?:@"",@"label":label?:@"",@"currentValue":currentValue?:@"",@"targetClass":targetClass?[NSString stringWithUTF8String:class_getName(targetClass)]:@"",@"action":[NSString stringWithUTF8String:actionName],@"implementation":impl?:@{},@"runtimeValueProbe":probe?:@{}});
    }
}'''
g=g[:a]+new+g[b:]
GENERIC.write_text(g)

u=UI.read_text()
u=u.replace('HFAMap RuntimeAnalyzer v0.3.13.4 Class1OwnershipCompletion','HFAMap RuntimeAnalyzer v0.3.13.5 RuntimeValueResolver')
UI.write_text(u)

for path,markers in [(TRACE,['[V03135-TITLE-MERGE]','HFA03135LabelScore']),(GENERIC,['[V03135-RUNTIME-VALUE]','currentValue','runtimeValueProbe','HFA03135ProbeImplementation','@"input"']),(UI,['v0.3.13.5 RuntimeValueResolver'])]:
    out=path.read_text()
    for marker in markers:
        if marker not in out: raise SystemExit('missing v03135 marker '+marker)
print('v0.3.13.5 runtime value resolver applied')

from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
EXPORTER=Path('hfamap/src/HFAMapJSONExport.m')
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

# 1) Export semantic title snapshot with lifetime valid for the caller.
t=TRACE.read_text()
a,b=function_span(t,'void HFARegisterFeatureDefinition(const char *label, const char *identifier)')
if 'HFAFeatureDefinitionTitleSnapshot' not in t:
    snapshot=r'''
NSDictionary *HFAFeatureDefinitionTitleSnapshot(void) {
    NSMutableDictionary *out=[NSMutableDictionary dictionary];
    for(unsigned i=0;i<gFeatureDefinitionCount;i++){
        HFAFeatureDefinition *definition=&gFeatureDefinitions[i];
        if(!definition->identifier[0]||!definition->label[0])continue;
        NSString *identifier=[NSString stringWithUTF8String:definition->identifier];
        NSString *title=[NSString stringWithUTF8String:definition->label];
        if(identifier.length&&title.length)out[identifier]=title;
    }
    HFALog("[V03137-FEATURE-TRUTH] definitions=%u titles=%lu\n",gFeatureDefinitionCount,(unsigned long)out.count);
    return [[out copy] autorelease];
}
'''
    t=t[:b]+"\n"+snapshot+t[b:]
TRACE.write_text(t)

# 2) Final JSON merge consults semantic title snapshot by identifier.
e=EXPORTER.read_text()
if 'extern NSDictionary *HFAFeatureDefinitionTitleSnapshot' not in e:
    insert=e.find('\n',e.find('#import'))
    if insert<0: raise SystemExit('exporter import anchor missing')
    e=e[:insert+1]+'extern NSDictionary *HFAFeatureDefinitionTitleSnapshot(void);\n'+e[insert+1:]

a,b=function_span(e,'static void HFAJSONMergeFeatures(NSMutableArray *destination,')
new=r'''static void HFAJSONMergeFeatures(NSMutableArray *destination,
                                 NSMutableSet<NSString *> *seenIDs,
                                 NSArray *incoming,
                                 NSUInteger *addedOut,
                                 NSUInteger *dedupedOut) {
    NSUInteger added=0,deduped=0;
    NSDictionary *semanticTitles=HFAFeatureDefinitionTitleSnapshot() ?: @{};
    for(NSDictionary *feature in incoming){
        if(![feature isKindOfClass:[NSDictionary class]])continue;
        NSString *identifier=[feature[@"id"] isKindOfClass:[NSString class]]?feature[@"id"]:@"";
        if(!identifier.length)continue;
        NSString *semanticTitle=[semanticTitles[identifier] isKindOfClass:[NSString class]]?semanticTitles[identifier]:@"";
        NSUInteger existingIndex=NSNotFound;
        for(NSUInteger i=0;i<destination.count;i++){
            NSDictionary *x=destination[i];
            NSString *xid=[x[@"id"] isKindOfClass:[NSString class]]?x[@"id"]:@"";
            if([xid isEqualToString:identifier]){existingIndex=i;break;}
        }
        if(existingIndex==NSNotFound){
            NSMutableDictionary *created=[[feature mutableCopy] autorelease];
            NSString *candidate=[created[@"title"] isKindOfClass:[NSString class]]?created[@"title"]:@"";
            if(semanticTitle.length && HFA03136ObservedTitleScore(semanticTitle,identifier)>=HFA03136ObservedTitleScore(candidate,identifier)) created[@"title"]=semanticTitle;
            [seenIDs addObject:identifier];
            [destination addObject:created];
            added++;
            HFAJSONLog([NSString stringWithFormat:@"[V03137-FEATURE-TRUTH-MERGE] id=%@ action=create title=%@ semantic=%@",identifier,[destination.lastObject objectForKey:@"title"]?:@"?",semanticTitle?:@""]);
            continue;
        }
        deduped++;
        NSMutableDictionary *merged=[[destination objectAtIndex:existingIndex] mutableCopy];
        NSString *oldTitle=[merged[@"title"] isKindOfClass:[NSString class]]?merged[@"title"]:@"";
        NSString *newTitle=[feature[@"title"] isKindOfClass:[NSString class]]?feature[@"title"]:@"";
        NSString *bestTitle=oldTitle;
        if(HFA03136ObservedTitleScore(newTitle,identifier)>HFA03136ObservedTitleScore(bestTitle,identifier))bestTitle=newTitle;
        if(semanticTitle.length && HFA03136ObservedTitleScore(semanticTitle,identifier)>=HFA03136ObservedTitleScore(bestTitle,identifier))bestTitle=semanticTitle;
        if(bestTitle.length)merged[@"title"]=bestTitle;
        for(NSString *key in @[@"control",@"runtimeEvidence",@"menuImage"]){id value=feature[key];if(value)merged[key]=value;}
        if(![merged[@"patches"] isKindOfClass:[NSArray class]] || ![(NSArray*)merged[@"patches"] count]){
            for(NSString *key in @[@"analysisKind",@"executionPrimitive",@"normalizedExecutionPrimitive",@"canonicalReason",@"normalizedCanonicalReason",@"backend"]){id value=feature[key];if(value)merged[key]=value;}
        }
        [destination replaceObjectAtIndex:existingIndex withObject:merged];
        HFAJSONLog([NSString stringWithFormat:@"[V03137-FEATURE-TRUTH-MERGE] id=%@ action=enrich title=%@ semantic=%@ control=%@ runtime=%@ patches=%lu",identifier,merged[@"title"]?:@"?",semanticTitle?:@"",merged[@"control"]?:@{},merged[@"runtimeEvidence"]?:@{},(unsigned long)([merged[@"patches"] isKindOfClass:[NSArray class]]?[(NSArray*)merged[@"patches"] count]:0)]);
        [merged release];
    }
    if(addedOut)*addedOut=added;if(dedupedOut)*dedupedOut=deduped;
}'''
e=e[:a]+new+e[b:]

a,b=function_span(e,'static NSArray *HFAJSONObservedFeatures(NSString *path, NSUInteger *recordCountOut)')
fn=e[a:b]
needle='NSDictionary *probe=[row[@"runtimeValueProbe"] isKindOfClass:[NSDictionary class]]?row[@"runtimeValueProbe"]:@{};'
if needle not in fn: raise SystemExit('runtime probe parse anchor missing')
fn=fn.replace(needle,needle+'NSDictionary *senderState=[row[@"senderState"] isKindOfClass:[NSDictionary class]]?row[@"senderState"]:@{};',1)
needle2='if(probe.count)runtime[@"runtimeValueProbe"]=probe;'
if needle2 not in fn: raise SystemExit('runtime probe merge anchor missing')
fn=fn.replace(needle2,needle2+'if(senderState.count)runtime[@"senderState"]=senderState;',1)
e=e[:a]+fn+e[b:]
EXPORTER.write_text(e)

# 3) Sender-centric evidence.
g=GENERIC.read_text()
anchor='void HFAGenericMenuObserveAction(id sender, id target, SEL action)'
pos=g.find(anchor)
if pos<0: raise SystemExit('action observer anchor missing')
if 'HFA03137SenderSnapshot' not in g:
    helpers=r'''
static NSString *HFA03137HexBytes(const void *bytes,size_t size){
    if(!bytes||!size||size>16)return nil;const unsigned char *p=(const unsigned char*)bytes;NSMutableString *s=[NSMutableString stringWithCapacity:size*2];for(size_t i=0;i<size;i++)[s appendFormat:@"%02X",p[i]];return s;
}
static size_t HFA03137PrimitiveSize(const char *type){
    if(!type||!*type)return 0;while(*type=='r'||*type=='n'||*type=='N'||*type=='o'||*type=='O'||*type=='R'||*type=='V')type++;switch(*type){case 'c':case 'C':case 'B':return 1;case 's':case 'S':return 2;case 'i':case 'I':case 'f':return 4;case 'l':case 'L':case 'q':case 'Q':case 'd':return 8;case '^':case '*':case '#':case ':':return sizeof(void*);default:return 0;}
}
static NSDictionary *HFA03137SenderSnapshot(id sender){
    if(!sender)return @{};NSMutableDictionary *out=[NSMutableDictionary dictionary];Class cls=object_getClass(sender);if(cls)out[@"class"]=[NSString stringWithUTF8String:class_getName(cls)?:"?"];out[@"pointer"]=[NSString stringWithFormat:@"%p",sender];
    NSString *identifier=HFASafeStringGetter(sender,"identifier");if(identifier.length)out[@"identifier"]=identifier;
    if([sender respondsToSelector:@selector(tag)]){@try{NSInteger tag=((NSInteger(*)(id,SEL))objc_msgSend)(sender,@selector(tag));out[@"tag"]=@(tag);}@catch(__unused id ex){}}
    NSMutableArray *fields=[NSMutableArray array];NSUInteger instanceSize=cls?class_getInstanceSize(cls):0;
    for(Class cursor=cls;cursor&&cursor!=[NSObject class];cursor=class_getSuperclass(cursor)){
        unsigned count=0;Ivar *ivars=class_copyIvarList(cursor,&count);if(count>64)count=64;
        for(unsigned i=0;ivars&&i<count;i++){
            Ivar iv=ivars[i];const char *name=ivar_getName(iv),*type=ivar_getTypeEncoding(iv);ptrdiff_t off=ivar_getOffset(iv);NSMutableDictionary *f=[NSMutableDictionary dictionary];f[@"owner"]=[NSString stringWithUTF8String:class_getName(cursor)?:"?"];f[@"name"]=[NSString stringWithUTF8String:name?:"?"];f[@"type"]=[NSString stringWithUTF8String:type?:"?"];f[@"offset"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)off];
            if(type&&type[0]=='@'){
                id value=nil;@try{value=object_getIvar(sender,iv);}@catch(__unused id ex){value=nil;}if(value){f[@"valueClass"]=[NSString stringWithUTF8String:class_getName(object_getClass(value))?:"?"];f[@"pointer"]=[NSString stringWithFormat:@"%p",value];if([value isKindOfClass:[NSString class]])f[@"string"]=value;else if([value isKindOfClass:[NSNumber class]])f[@"number"]=value;}
            }else{
                size_t sz=HFA03137PrimitiveSize(type);if(sz&&off>=0&&(NSUInteger)off+sz<=instanceSize){unsigned char raw[16]={0};if(sz>sizeof(raw))sz=sizeof(raw);memcpy(raw,(const unsigned char *)(__bridge const void*)sender+off,sz);NSString *hex=HFA03137HexBytes(raw,sz);if(hex)f[@"raw"]=hex;if(sz==1)f[@"u64"]=@((unsigned long long)raw[0]);else if(sz==2){uint16_t v=0;memcpy(&v,raw,2);f[@"u64"]=@((unsigned long long)v);}else if(sz==4){uint32_t v=0;memcpy(&v,raw,4);f[@"u64"]=@((unsigned long long)v);float fv=0;memcpy(&fv,raw,4);if(isfinite(fv))f[@"float"]=@(fv);}else if(sz==8){uint64_t v=0;memcpy(&v,raw,8);f[@"u64"]=@(v);double dv=0;memcpy(&dv,raw,8);if(isfinite(dv))f[@"double"]=@(dv);}}
            }
            if(f.count>4)[fields addObject:f];
        }
        free(ivars);
    }
    if(fields.count)out[@"fields"]=fields;return out;
}
'''
    g=g[:pos]+helpers+'\n'+g[pos:]

a,b=function_span(g,'void HFAGenericMenuObserveAction(id sender, id target, SEL action)')
fn=g[a:b]
probe_anchor='NSDictionary *probe=method?HFA03136ProbeImplementation(method):@{};'
if probe_anchor not in fn: raise SystemExit('v03136 action probe anchor missing')
fn=fn.replace(probe_anchor,probe_anchor+'NSDictionary *senderState=HFA03137SenderSnapshot(sender);',1)
log_anchor='HFAGenericLog("[V03136-RUNTIME-VALUE]'
idx=fn.find(log_anchor)
if idx<0: raise SystemExit('runtime value log anchor missing')
insert_stmt='HFAGenericLog("[V03137-SENDER] identifier=%s class=%s tag=%s fields=%u pointer=%s\\n",identifier.UTF8String?:"?",[[senderState objectForKey:@"class"] UTF8String]?:"?",[[[senderState objectForKey:@"tag"] description] UTF8String]?:"?",(unsigned)[[senderState objectForKey:@"fields"] count],[[senderState objectForKey:@"pointer"] UTF8String]?:"?");\n        '
fn=fn[:idx]+insert_stmt+fn[idx:]
json_anchor='@"runtimeValueProbe":probe?:@{}});'
if json_anchor not in fn: raise SystemExit('action JSON anchor missing')
fn=fn.replace(json_anchor,'@"runtimeValueProbe":probe?:@{},@"senderState":senderState?:@{}});',1)
g=g[:a]+fn+g[b:]
GENERIC.write_text(g)

u=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.6 UnifiedRuntimeValueBridge','HFAMap RuntimeAnalyzer v0.3.13.7 UnifiedFeatureTruthSenderDataflow')
UI.write_text(u)

for path,markers in [
    (TRACE,['[V03137-FEATURE-TRUTH]','HFAFeatureDefinitionTitleSnapshot']),
    (EXPORTER,['[V03137-FEATURE-TRUTH-MERGE]','senderState','HFAFeatureDefinitionTitleSnapshot']),
    (GENERIC,['[V03137-SENDER]','HFA03137SenderSnapshot','@"senderState"']),
    (UI,['v0.3.13.7 UnifiedFeatureTruthSenderDataflow'])]:
    text=path.read_text()
    for marker in markers:
        if marker not in text: raise SystemExit('missing v03137 marker '+marker)
print('v0.3.13.7 unified feature truth + sender dataflow applied')

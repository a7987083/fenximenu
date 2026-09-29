from pathlib import Path

PROFILER=Path('hfamap/src/HFAMapJailpatchRuntimeProfiler.m')
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

# ---------------------------------------------------------------------------
# 1) Jailpatch feature definition -> canonical feature-definition bridge.
#    This is intentionally independent from runtime record count: value-only
#    features often have records=0 but still carry the strongest title/id pair.
# ---------------------------------------------------------------------------
p=PROFILER.read_text()
if 'extern void HFARegisterFeatureDefinition' not in p:
    anchor='static const char *kHFAJPVersion'
    pos=p.find(anchor)
    if pos<0: raise SystemExit('jailpatch version anchor missing')
    p=p[:pos]+'extern void HFARegisterFeatureDefinition(const char *label, const char *identifier);\n\n'+p[pos:]
bridge_anchor='                if (!HFAJPFeatureDictionary(feature, &label, &identifier)) continue;\n'
if bridge_anchor not in p: raise SystemExit('jailpatch feature dictionary anchor missing')
if '[V03136-JAILPATCH-DEFINITION-BRIDGE]' not in p:
    p=p.replace(bridge_anchor,bridge_anchor+
'''                if (identifier.length && label.length) {\n                    HFARegisterFeatureDefinition(label.UTF8String, identifier.UTF8String);\n                    HFAJPLog("[V03136-JAILPATCH-DEFINITION-BRIDGE] identifier=%s title=\\"%s\\" source=feature-dictionary\\n",\n                             identifier.UTF8String ?: "?", label.UTF8String ?: "?");\n                }\n''',1)
PROFILER.write_text(p)

# ---------------------------------------------------------------------------
# 2) Observed-runtime parser: retain semantic kind/currentValue/probe instead of
#    collapsing slider->number and allowing transient values to become titles.
# ---------------------------------------------------------------------------
e=EXPORTER.read_text()
a,b=function_span(e,'static NSString *HFAJSONObservedControlKind(NSString *kind)')
e=e[:a]+r'''static NSString *HFAJSONObservedControlKind(NSString *kind) {
    if ([kind isEqualToString:@"switch"]) return @"toggle";
    if ([kind isEqualToString:@"button"]) return @"button";
    if ([kind isEqualToString:@"slider"]) return @"slider";
    if ([kind isEqualToString:@"input"]) return @"input";
    return @"unknown";
}'''+e[b:]

a,b=function_span(e,'static NSArray *HFAJSONObservedFeatures(NSString *path, NSUInteger *recordCountOut)')
e=e[:a]+r'''static BOOL HFA03136ObservedNumeric(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || !s.length) return NO;
    NSScanner *scanner = [NSScanner scannerWithString:s]; double value = 0;
    return [scanner scanDouble:&value] && scanner.isAtEnd;
}

static NSInteger HFA03136ObservedTitleScore(NSString *title, NSString *identifier) {
    if (!title.length) return 0;
    if (identifier.length && [title isEqualToString:identifier]) return 10;
    if (HFA03136ObservedNumeric(title)) return 5;
    NSCharacterSet *letters=[NSCharacterSet letterCharacterSet];
    if ([title rangeOfCharacterFromSet:letters].location != NSNotFound) return 80;
    return 30;
}

static NSArray *HFAJSONObservedFeatures(NSString *path, NSUInteger *recordCountOut) {
    if (recordCountOut) *recordCountOut = 0;
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) return @[];
    NSString *text = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];
    if (!text.length) return @[];
    NSMutableDictionary<NSString *, NSMutableDictionary *> *byID=[NSMutableDictionary dictionary];
    NSMutableArray<NSString *> *order=[NSMutableArray array]; NSUInteger parsed=0;
    for (NSString *line in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        if (!line.length) continue; NSData *ld=[line dataUsingEncoding:NSUTF8StringEncoding]; if(!ld.length)continue;
        id obj=[NSJSONSerialization JSONObjectWithData:ld options:0 error:nil]; if(![obj isKindOfClass:[NSDictionary class]])continue;
        NSDictionary *row=(NSDictionary*)obj; NSString *record=[row[@"record"] isKindOfClass:[NSString class]]?row[@"record"]:@"";
        if(![record isEqualToString:@"menu-item"] && ![record isEqualToString:@"action"])continue;
        NSString *identifier=[row[@"identifier"] isKindOfClass:[NSString class]]?row[@"identifier"]:@""; if(!identifier.length)continue;
        NSString *label=[row[@"label"] isKindOfClass:[NSString class]]?row[@"label"]:@""; parsed++;
        NSMutableDictionary *feature=byID[identifier];
        if(!feature){feature=[NSMutableDictionary dictionary];feature[@"id"]=identifier;feature[@"title"]=label.length?label:identifier;feature[@"group"]=@"Imported";feature[@"analysisKind"]=@"runtime-observed-feature";feature[@"canonicalEligible"]=@NO;feature[@"canonicalReason"]=@"runtime-observed-no-static-mapping";feature[@"normalizedCanonicalReason"]=@"runtime-observed-no-static-mapping";byID[identifier]=feature;[order addObject:identifier];}
        else if(label.length && HFA03136ObservedTitleScore(label,identifier)>HFA03136ObservedTitleScore(feature[@"title"],identifier)) feature[@"title"]=label;
        NSString *kind=[row[@"kind"] isKindOfClass:[NSString class]]?row[@"kind"]:@"";
        NSString *rawKind=[row[@"rawKind"] isKindOfClass:[NSString class]]?row[@"rawKind"]:@"";
        NSString *currentValue=[row[@"currentValue"] isKindOfClass:[NSString class]]?row[@"currentValue"]:@"";
        if(kind.length){NSMutableDictionary *control=[NSMutableDictionary dictionaryWithObject:HFAJSONObservedControlKind(kind) forKey:@"kind"];if(rawKind.length)control[@"rawKind"]=rawKind;if(currentValue.length)control[@"currentValue"]=currentValue;feature[@"control"]=control;}
        NSString *image=[row[@"image"] isKindOfClass:[NSString class]]?row[@"image"]:@"";if(image.length)feature[@"menuImage"]=image;
        if([record isEqualToString:@"action"]){NSString *targetClass=[row[@"targetClass"] isKindOfClass:[NSString class]]?row[@"targetClass"]:@"";NSString *action=[row[@"action"] isKindOfClass:[NSString class]]?row[@"action"]:@"";NSDictionary *implementation=[row[@"implementation"] isKindOfClass:[NSDictionary class]]?row[@"implementation"]:@{};NSDictionary *probe=[row[@"runtimeValueProbe"] isKindOfClass:[NSDictionary class]]?row[@"runtimeValueProbe"]:@{};NSMutableDictionary *runtime=[NSMutableDictionary dictionary];if(targetClass.length)runtime[@"targetClass"]=targetClass;if(action.length)runtime[@"action"]=action;if(implementation.count)runtime[@"implementation"]=implementation;if(probe.count)runtime[@"runtimeValueProbe"]=probe;if(currentValue.length)runtime[@"currentValue"]=currentValue;if(kind.length)runtime[@"kind"]=HFAJSONObservedControlKind(kind);feature[@"runtimeEvidence"]=runtime;feature[@"analysisKind"]=@"runtime-observed-action";feature[@"executionPrimitive"]=@"runtimeAction";feature[@"normalizedExecutionPrimitive"]=@"runtimeAction";feature[@"canonicalReason"]=@"runtime-action-not-static-bytes";feature[@"normalizedCanonicalReason"]=@"runtime-action-not-static-bytes";}
    }
    if(recordCountOut)*recordCountOut=parsed;NSMutableArray *out=[NSMutableArray arrayWithCapacity:order.count];for(NSString *identifier in order){NSDictionary *feature=byID[identifier];if(feature)[out addObject:feature];}return out;
}'''+e[b:]

# Merge is now field-level enrichment, not identifier-only drop. Static patches
# stay authoritative while runtime control/action evidence enriches same feature.
a,b=function_span(e,'static void HFAJSONMergeFeatures(NSMutableArray *destination,')
e=e[:a]+r'''static void HFAJSONMergeFeatures(NSMutableArray *destination,
                                 NSMutableSet<NSString *> *seenIDs,
                                 NSArray *incoming,
                                 NSUInteger *addedOut,
                                 NSUInteger *dedupedOut) {
    NSUInteger added=0,deduped=0;
    for(NSDictionary *feature in incoming){if(![feature isKindOfClass:[NSDictionary class]])continue;NSString *identifier=[feature[@"id"] isKindOfClass:[NSString class]]?feature[@"id"]:@"";if(!identifier.length)continue;
        NSUInteger existingIndex=NSNotFound;for(NSUInteger i=0;i<destination.count;i++){NSDictionary *x=destination[i];if([[x[@"id"] isKindOfClass:[NSString class]]?x[@"id"]:@""] isEqualToString:identifier]){existingIndex=i;break;}}
        if(existingIndex==NSNotFound){[seenIDs addObject:identifier];[destination addObject:[[feature mutableCopy] autorelease]];added++;continue;}
        deduped++;NSMutableDictionary *merged=[[[destination objectAtIndex:existingIndex] mutableCopy] autorelease];
        NSString *oldTitle=[merged[@"title"] isKindOfClass:[NSString class]]?merged[@"title"]:@"";NSString *newTitle=[feature[@"title"] isKindOfClass:[NSString class]]?feature[@"title"]:@"";if(HFA03136ObservedTitleScore(newTitle,identifier)>HFA03136ObservedTitleScore(oldTitle,identifier))merged[@"title"]=newTitle;
        for(NSString *key in @[@"control",@"runtimeEvidence",@"menuImage"]){id value=feature[key];if(value)merged[key]=value;}
        if(![merged[@"patches"] isKindOfClass:[NSArray class]] || ![(NSArray*)merged[@"patches"] count]){for(NSString *key in @[@"analysisKind",@"executionPrimitive",@"normalizedExecutionPrimitive",@"canonicalReason",@"normalizedCanonicalReason",@"backend"]){id value=feature[key];if(value)merged[key]=value;}}
        [destination replaceObjectAtIndex:existingIndex withObject:merged];
        HFAJSONLog([NSString stringWithFormat:@"[V03136-RUNTIME-MERGE] id=%@ title=%@ control=%@ runtime=%@ patches=%lu",identifier,merged[@"title"]?:@"?",merged[@"control"]?:@{},merged[@"runtimeEvidence"]?:@{},(unsigned long)([merged[@"patches"] isKindOfClass:[NSArray class]]?[(NSArray*)merged[@"patches"] count]:0)]);
    }
    if(addedOut)*addedOut=added;if(dedupedOut)*dedupedOut=deduped;
}'''+e[b:]
EXPORTER.write_text(e)

# ---------------------------------------------------------------------------
# 3) Probe v2. Extend evidence beyond direct BL: ADR, LDR literal and BLR.
#    Candidates remain evidence, never automatically claimed as final consumer.
# ---------------------------------------------------------------------------
g=GENERIC.read_text()
a,b=function_span(g,'static NSDictionary *HFA03135ProbeImplementation(Method method)')
probe=r'''static NSDictionary *HFA03136ProbeImplementation(Method method){
    if(!method)return @{};uintptr_t start=(uintptr_t)method_getImplementation(method);if(!start)return @{};NSMutableArray *calls=[NSMutableArray array],*indirect=[NSMutableArray array],*mem=[NSMutableArray array];uintptr_t reg[32]={0};BOOL known[32]={0};unsigned retSeen=0;
    for(unsigned off=0;off<0x300;off+=4){uint32_t ins=0;memcpy(&ins,(void*)(start+off),4);uintptr_t pc=start+off;
        if((ins&0xFC000000u)==0x94000000u){int64_t d=HFA03135SignExtend(ins&0x03FFFFFFu,26)<<2;uintptr_t target=(uintptr_t)((int64_t)pc+d);NSDictionary *ai=HFAAddressInfo((void*)target);if(ai&&calls.count<48){NSMutableDictionary *r=[ai mutableCopy];Dl_info di={0};if(dladdr((void*)target,&di)&&di.dli_sname)r[@"symbol"]=[NSString stringWithUTF8String:di.dli_sname];r[@"callsiteRVA"]=[NSString stringWithFormat:@"0x%X",off];[calls addObject:r];HFAGenericLog("[V03136-RUNTIME-CALL] type=BL off=0x%X image=%s rva=%s symbol=%s\n",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?",di.dli_sname?:"?");}}
        if((ins&0xFFFFFC1Fu)==0xD63F0000u){unsigned rn=(ins>>5)&31;NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObjectsAndKeys:@"BLR",@"type",@(rn),@"register",[NSString stringWithFormat:@"0x%X",off],@"callsiteRVA",nil];if(known[rn]){NSDictionary *ai=HFAAddressInfo((void*)reg[rn]);if(ai)[r addEntriesFromDictionary:ai];}if(indirect.count<48)[indirect addObject:r];HFAGenericLog("[V03136-RUNTIME-CALL] type=BLR off=0x%X reg=x%u resolved=%d\n",off,rn,known[rn]?1:0);}
        if((ins&0x9F000000u)==0x90000000u){unsigned rd=ins&31;uint64_t immhi=(ins>>5)&0x7FFFF,immlo=(ins>>29)&3;int64_t imm=HFA03135SignExtend((immhi<<2)|immlo,21)<<12;reg[rd]=(pc&~0xFFFULL)+imm;known[rd]=YES;continue;}
        if((ins&0x9F000000u)==0x10000000u){unsigned rd=ins&31;uint64_t immhi=(ins>>5)&0x7FFFF,immlo=(ins>>29)&3;int64_t imm=HFA03135SignExtend((immhi<<2)|immlo,21);reg[rd]=(uintptr_t)((int64_t)pc+imm);known[rd]=YES;NSDictionary *ai=HFAAddressInfo((void*)reg[rd]);if(ai&&mem.count<64){NSMutableDictionary *r=[ai mutableCopy];r[@"kind"]=@"adr";r[@"insnRVA"]=[NSString stringWithFormat:@"0x%X",off];[mem addObject:r];}continue;}
        if((ins&0xFF000000u)==0x91000000u){unsigned rd=ins&31,rn=(ins>>5)&31;if(known[rn]){uint64_t imm=(ins>>10)&0xFFF;if((ins>>22)&1)imm<<=12;reg[rd]=reg[rn]+imm;known[rd]=YES;NSDictionary *ai=HFAAddressInfo((void*)reg[rd]);if(ai&&mem.count<64){NSMutableDictionary *r=[ai mutableCopy];r[@"kind"]=@"address";r[@"insnRVA"]=[NSString stringWithFormat:@"0x%X",off];[mem addObject:r];}}continue;}
        if((ins&0x3B000000u)==0x18000000u){unsigned rt=ins&31;int64_t imm=HFA03135SignExtend((ins>>5)&0x7FFFF,19)<<2;uintptr_t addr=(uintptr_t)((int64_t)pc+imm);reg[rt]=addr;known[rt]=YES;NSDictionary *ai=HFAAddressInfo((void*)addr);if(ai&&mem.count<64){NSMutableDictionary *r=[ai mutableCopy];r[@"kind"]=@"literal";r[@"insnRVA"]=[NSString stringWithFormat:@"0x%X",off];[mem addObject:r];}continue;}
        if((ins&0x3B000000u)==0x39000000u){unsigned rn=(ins>>5)&31;if(known[rn]){unsigned size=(ins>>30)&3;uint64_t imm=((ins>>10)&0xFFFULL)<<size;uintptr_t addr=reg[rn]+imm;NSDictionary *ai=HFAAddressInfo((void*)addr);if(ai&&mem.count<64){NSMutableDictionary *r=[ai mutableCopy];r[@"kind"]=((ins>>22)&1)?@"load":@"store";r[@"insnRVA"]=[NSString stringWithFormat:@"0x%X",off];[mem addObject:r];HFAGenericLog("[V03136-RUNTIME-MEM] type=%s off=0x%X image=%s rva=%s\n",[r[@"kind"] UTF8String]?:"?",off,[ai[@"image"] UTF8String]?:"?",[ai[@"rva"] UTF8String]?:"?");}}}
        if(ins==0xD65F03C0u&&++retSeen>=1)break;
    }
    return @{@"implementation":HFAAddressInfo((void*)start)?:@{},@"directCalls":calls,@"indirectCalls":indirect,@"memoryRefs":mem,@"scanBytes":@0x300,@"candidateOnly":@YES};
}'''
g=g[:a]+probe+g[b:]
g=g.replace('HFA03135ProbeImplementation(method)','HFA03136ProbeImplementation(method)')
g=g.replace('[V03135-RUNTIME-VALUE]','[V03136-RUNTIME-VALUE]')
GENERIC.write_text(g)

u=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.5 RuntimeValueResolver','HFAMap RuntimeAnalyzer v0.3.13.6 UnifiedRuntimeValueBridge')
UI.write_text(u)

checks=[(PROFILER,['[V03136-JAILPATCH-DEFINITION-BRIDGE]','HFARegisterFeatureDefinition']),(EXPORTER,['[V03136-RUNTIME-MERGE]','currentValue','runtimeValueProbe','HFA03136ObservedTitleScore']),(GENERIC,['[V03136-RUNTIME-VALUE]','[V03136-RUNTIME-CALL]','[V03136-RUNTIME-MEM]','HFA03136ProbeImplementation','indirectCalls','candidateOnly']),(UI,['v0.3.13.6 UnifiedRuntimeValueBridge'])]
for path,markers in checks:
    text=path.read_text()
    for marker in markers:
        if marker not in text: raise SystemExit('missing v03136 marker '+marker+' in '+str(path))
print('v0.3.13.6 unified runtime value bridge applied')

from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
s=TRACE.read_text()

sig='static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates)'
pos=s.find(sig)
if pos<0: raise SystemExit('object-table recovery bridge anchor missing')

helpers=r'''
static NSArray *HFA03134StaticDataRanges(HFA03134MenuLayout l){
    const struct mach_header_64 *h=(const struct mach_header_64*)l.base;if(!h||h->magic!=MH_MAGIC_64)return @[];NSMutableArray *out=[NSMutableArray array];const uint8_t *cur=(const uint8_t*)(h+1);
    for(uint32_t c=0;c<h->ncmds;c++){const struct load_command *lc=(const struct load_command*)cur;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *seg=(const struct segment_command_64*)cur;const struct section_64 *sec=(const struct section_64*)(seg+1);for(uint32_t q=0;q<seg->nsects;q++){BOOL keep=!strncmp(sec[q].sectname,"__data",16)||!strncmp(sec[q].sectname,"__const",16)||!strncmp(sec[q].sectname,"__data_const",16)||!strncmp(sec[q].sectname,"__objc_const",16);if(!keep)continue;uintptr_t a=(uintptr_t)l.slide+(uintptr_t)sec[q].addr,e=a+(uintptr_t)sec[q].size;if(e<=a||!HFAReadable(a,MIN((size_t)8,(size_t)(e-a))))continue;NSString *sn=[[NSString alloc] initWithBytes:sec[q].sectname length:strnlen(sec[q].sectname,16) encoding:NSUTF8StringEncoding]?:@"";NSString *sg=[[NSString alloc] initWithBytes:seg->segname length:strnlen(seg->segname,16) encoding:NSUTF8StringEncoding]?:@"";[out addObject:@{@"start":@(a),@"end":@(e),@"section":sn,@"segment":sg}];}}cur+=lc->cmdsize;}
    return out;
}
static NSDictionary *HFA03134ObjectTableEvidence(NSDictionary *backend,HFA03134MenuLayout l,NSArray *ranges){
    NSString *dr=[backend[@"descriptorRVA"] description];if(!dr.length||!l.base)return @{};uint64_t rv=strtoull(dr.UTF8String,NULL,0);if(!rv)return @{};uintptr_t descriptor=l.base+(uintptr_t)rv;NSMutableArray *refs=[NSMutableArray array];NSMutableOrderedSet *strings=[NSMutableOrderedSet orderedSet],*keys=[NSMutableOrderedSet orderedSet],*objects=[NSMutableOrderedSet orderedSet];
    for(NSDictionary *range in ranges){uintptr_t a=[range[@"start"] unsignedLongLongValue],e=[range[@"end"] unsignedLongLongValue];if(e<=a)continue;for(uintptr_t p=(a+7u)&~(uintptr_t)7u;p+8<=e;p+=8){uintptr_t v=0;memcpy(&v,(void*)p,8);if(v!=descriptor)continue;NSMutableDictionary *rec=[@{@"tableRefRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(p-l.base)],@"section":range[@"section"]?:@"",@"segment":range[@"segment"]?:@""} mutableCopy];NSMutableArray *near=[NSMutableArray array];uintptr_t lo=p>=0x60?p-0x60:a;if(lo<a)lo=a;uintptr_t hi=MIN(p+0x68,e);for(uintptr_t q=(lo+7u)&~(uintptr_t)7u;q+8<=hi;q+=8){if(q==p)continue;uintptr_t x=0;memcpy(&x,(void*)q,8);if(!x)continue;NSString *str=HFA03134StringAt(x,l);if(str.length){[strings addObject:str];if([str hasSuffix:@"-switch"]&&str.length>7)[keys addObject:str];[near addObject:@{@"slotRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(q-l.base)],@"kind":@"string",@"value":str}];continue;}if(x>=l.base&&x<l.textEnd+0x1000000ULL){NSString *obj=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(x-l.base)];[objects addObject:obj];if(near.count<24)[near addObject:@{@"slotRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(q-l.base)],@"kind":@"pointer",@"value":obj}];}}
        rec[@"nearby"]=near;[refs addObject:rec];if(refs.count>=16)break;}if(refs.count>=16)break;}
    NSMutableDictionary *out=[@{@"descriptorRVA":dr,@"tableRefs":refs,@"tableRefCount":@(refs.count),@"registrationHints":strings.array?:@[],@"exactSwitchKeys":keys.array?:@[],@"nearbyObjectRVAs":objects.array?:@[]} mutableCopy];if(keys.count==1)out[@"exactSwitchKey"]=keys.firstObject;return out;
}
'''
if 'HFA03134ObjectTableEvidence' not in s:
    s=s[:pos]+helpers+'\n'+s[pos:]

anchor='HFA03134MenuLayout registrationLayout={0};BOOL haveRegistrationLayout=HFA03134MenuLayoutLoad(&registrationLayout);\n    NSMutableArray *ordered=[NSMutableArray array];'
replace='HFA03134MenuLayout registrationLayout={0};BOOL haveRegistrationLayout=HFA03134MenuLayoutLoad(&registrationLayout);\n    NSArray *objectTableRanges=haveRegistrationLayout?HFA03134StaticDataRanges(registrationLayout):@[];\n    NSMutableDictionary *objectTableEvidenceByBackend=[NSMutableDictionary dictionary];\n    NSMutableArray *ordered=[NSMutableArray array];'
if anchor not in s: raise SystemExit('object-table declaration anchor missing')
s=s.replace(anchor,replace,1)

anchor='if(haveRegistrationLayout){NSDictionary *ev=HFA03134RegistrationEvidence(backend,registrationLayout);if(ev.count)registrationEvidenceByBackend[[backend[@"backendId"] description]?:@""]=ev;}'
replace='if(haveRegistrationLayout){NSString *otBid=[backend[@"backendId"] description]?:@"";NSDictionary *ev=HFA03134RegistrationEvidence(backend,registrationLayout);if(ev.count)registrationEvidenceByBackend[otBid]=ev;NSDictionary *tev=HFA03134ObjectTableEvidence(backend,registrationLayout,objectTableRanges);if(tev.count)objectTableEvidenceByBackend[otBid]=tev;}'
if anchor not in s: raise SystemExit('object-table backend evidence anchor missing')
s=s.replace(anchor,replace,1)

old='''            NSString *key=nil;NSString *source=nil;if(exactKeys.count==1){key=exactKeys.firstObject;source=@"static-registration-key";}else if(exactKeys.count==0&&callerKeys.count==1){key=callerKeys.firstObject;source=@"static-caller-registration-key";}
            if(key.length){NSString *fid=[key substringToIndex:key.length-7];if(fid.length)recovered=@{@"featureId":fid,@"title":fid,@"key":key,@"descriptorIndex":@(-1),@"source":source,@"clusterId":clusterId,@"ownerFunctions":ownerFunctions.array?:@[],@"registrationHints":allHints.array?:@[],@"callerRegistrationHints":callerHints.array?:@[],@"callerEvidence":callerEvidence?:@[]};}
            if(!recovered&&callerEvidence.count){HFALog("[V03134-CALLER-RECOVERY] cluster=%s status=unresolved callerKeys=%u callers=%u hints=%u values=%s\\n",clusterId.UTF8String?:"?",(unsigned)callerKeys.count,(unsigned)callerEvidence.count,(unsigned)callerHints.count,[[callerHints.array componentsJoinedByString:@"|"] UTF8String]?:"");}
'''
new='''            NSMutableOrderedSet *tableKeys=[NSMutableOrderedSet orderedSet],*tableHints=[NSMutableOrderedSet orderedSet],*tableRefs=[NSMutableOrderedSet orderedSet];NSMutableArray *tableEvidence=[NSMutableArray array];
            if(exactKeys.count==0&&callerKeys.count==0){for(NSUInteger ti=clusterStart;ti<end;ti++){NSDictionary *be=ordered[ti][@"backend"];NSString *tbid=[be[@"backendId"] description]?:@"";NSDictionary *tev=objectTableEvidenceByBackend[tbid];if(!tev.count)continue;[tableEvidence addObject:tev];for(NSString *k in [tev[@"exactSwitchKeys"] isKindOfClass:NSArray.class]?tev[@"exactSwitchKeys"]:@[])if(k.length)[tableKeys addObject:k];for(NSString *h in [tev[@"registrationHints"] isKindOfClass:NSArray.class]?tev[@"registrationHints"]:@[])if(h.length)[tableHints addObject:h];for(NSDictionary *r in [tev[@"tableRefs"] isKindOfClass:NSArray.class]?tev[@"tableRefs"]:@[]){NSString *rr=[r[@"tableRefRVA"] description];if(rr.length)[tableRefs addObject:rr];}}}
            NSString *key=nil;NSString *source=nil;if(exactKeys.count==1){key=exactKeys.firstObject;source=@"static-registration-key";}else if(exactKeys.count==0&&callerKeys.count==1){key=callerKeys.firstObject;source=@"static-caller-registration-key";}else if(exactKeys.count==0&&callerKeys.count==0&&tableKeys.count==1){key=tableKeys.firstObject;source=@"static-object-table-registration-key";}
            if(key.length){NSString *fid=[key substringToIndex:key.length-7];if(fid.length)recovered=@{@"featureId":fid,@"title":fid,@"key":key,@"descriptorIndex":@(-1),@"source":source,@"clusterId":clusterId,@"ownerFunctions":ownerFunctions.array?:@[],@"registrationHints":allHints.array?:@[],@"callerRegistrationHints":callerHints.array?:@[],@"callerEvidence":callerEvidence?:@[],@"objectTableHints":tableHints.array?:@[],@"objectTableRefs":tableRefs.array?:@[],@"objectTableEvidence":tableEvidence?:@[]};}
            if(!recovered&&callerEvidence.count){HFALog("[V03134-CALLER-RECOVERY] cluster=%s status=unresolved callerKeys=%u callers=%u hints=%u values=%s\\n",clusterId.UTF8String?:"?",(unsigned)callerKeys.count,(unsigned)callerEvidence.count,(unsigned)callerHints.count,[[callerHints.array componentsJoinedByString:@"|"] UTF8String]?:"");}
            if(!recovered&&tableEvidence.count){HFALog("[V03134-OBJECT-TABLE] cluster=%s status=unresolved tableKeys=%u refs=%u hints=%u values=%s\\n",clusterId.UTF8String?:"?",(unsigned)tableKeys.count,(unsigned)tableRefs.count,(unsigned)tableHints.count,[[tableHints.array componentsJoinedByString:@"|"] UTF8String]?:"");}
'''
if old not in s: raise SystemExit('object-table recovery decision anchor missing')
s=s.replace(old,new,1)

# Keep the detailed per-backend object/table evidence in the audit ledger.
ledger_anchor='NSDictionary *regEv=registrationEvidenceByBackend[regBid];if(regEv.count)e[@"staticRegistrationEvidence"]=regEv;'
ledger_new='NSDictionary *regEv=registrationEvidenceByBackend[regBid];if(regEv.count)e[@"staticRegistrationEvidence"]=regEv;NSDictionary *tableEv=objectTableEvidenceByBackend[regBid];if(tableEv.count)e[@"staticObjectTableEvidence"]=tableEv;'
if ledger_anchor not in s: raise SystemExit('object-table ledger anchor missing')
s=s.replace(ledger_anchor,ledger_new)

TRACE.write_text(s)
out=TRACE.read_text()
for marker in ['HFA03134ObjectTableEvidence','[V03134-OBJECT-TABLE]','static-object-table-registration-key','staticObjectTableEvidence']:
    if marker not in out: raise SystemExit('missing object-table recovery marker '+marker)
print('v0.3.13.4 generic static object/table recovery applied')

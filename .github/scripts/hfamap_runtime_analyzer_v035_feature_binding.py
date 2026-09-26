from pathlib import Path

ROOT=Path('hfamap')
SEM=ROOT/'src'/'HFARuntimeSemanticAnalyzer.m'
HDR=ROOT/'src'/'HFARuntimeSemanticAnalyzer.h'
SRC=ROOT/'src'/'HFAMapRuntimeAnalyzerV02.m'


def function_span(text,name):
    i=text.find(name+'(')
    if i<0: raise SystemExit(name+' missing')
    start=text.rfind('\n',0,i)+1;b=text.find('{',i);depth=0;instr=False;esc=False
    for j in range(b,len(text)):
        ch=text[j]
        if instr:
            if esc:esc=False
            elif ch=='\\':esc=True
            elif ch=='"':instr=False
            continue
        if ch=='"':instr=True;continue
        if ch=='{':depth+=1
        elif ch=='}':
            depth-=1
            if depth==0:return start,j+1
    raise SystemExit(name+' unterminated')

s=SEM.read_text()
anchor='static BOOL HFASemConditionalTarget(uint32_t w, uintptr_t pc, uintptr_t *target) {'
if anchor not in s: raise SystemExit('feature binding helper anchor missing')
if 'HFASemRecordMaterialized' not in s:
    helpers=r'''
static void HFASemRecordMaterialized(NSMutableArray *out,NSMutableSet *seen,uintptr_t value,NSString *kind,uintptr_t pc,HFASemImage image){
    if(!value||!out||!seen)return;NSNumber *key=@(value);if([seen containsObject:key])return;[seen addObject:key];
    NSMutableDictionary *e=[@{@"runtimeAddress":@((unsigned long long)value),@"source":kind?:@"unknown"} mutableCopy];
    if(value>=image.base)e[@"rva"]=HFASemRVA(value,image);if(pc)e[@"sourceRVA"]=HFASemRVA(pc,image);[out addObject:e];
}
static BOOL HFASemReadExactBytes(uintptr_t address,void *dst,size_t size){if(!address||!dst||!size)return NO;vm_size_t got=0;kern_return_t kr=vm_read_overwrite(mach_task_self(),(vm_address_t)address,(vm_size_t)size,(vm_address_t)dst,&got);return kr==KERN_SUCCESS&&got==(vm_size_t)size;}
static NSArray<NSNumber*> *HFASemIdentifierAddresses(NSString *identifier,uintptr_t anchorAddress){
    if(!identifier.length||!anchorAddress)return @[];HFASemImage image={0};if(!HFASemImageForAddress(anchorAddress,&image))return @[];
    static NSMutableDictionary *cache;static dispatch_once_t once;dispatch_once(&once,^{cache=[NSMutableDictionary dictionary];});
    NSString *ck=[NSString stringWithFormat:@"%llX:%@",(unsigned long long)image.base,identifier];@synchronized(cache){NSArray *hit=cache[ck];if(hit)return hit;}
    NSData *needle=[identifier dataUsingEncoding:NSUTF8StringEncoding];if(!needle.length||needle.length>512)return @[];NSMutableOrderedSet *found=[NSMutableOrderedSet orderedSet];
    const uint8_t *c=(const uint8_t*)(image.header+1);for(uint32_t i=0;i<image.header->ncmds;i++){const struct load_command *lc=(const struct load_command*)c;if(!lc->cmdsize)break;
        if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *g=(const struct segment_command_64*)c;const struct section_64 *sec=(const struct section_64*)(g+1);for(uint32_t j=0;j<g->nsects;j++,sec++){
            if(strncmp(sec->sectname,"__cfstring",16))continue;uintptr_t rs=(uintptr_t)((intptr_t)sec->addr+image.slide);
            for(uint64_t off=0;off+32<=sec->size;off+=32){uintptr_t obj=rs+(uintptr_t)off;uint64_t q[4]={0};if(!HFASemReadExactBytes(obj,q,sizeof(q)))continue;uintptr_t sp=(uintptr_t)q[2];uint64_t n=q[3];if(!sp||n!=needle.length)continue;uint8_t buf[512]={0};if(!HFASemReadExactBytes(sp,buf,(size_t)n))continue;if(!memcmp(buf,needle.bytes,(size_t)n)){[found addObject:@((unsigned long long)obj)];[found addObject:@((unsigned long long)sp)];}}
        }}c+=lc->cmdsize;}
    NSArray *out=found.array?:@[];@synchronized(cache){cache[ck]=out;}return out;
}
NSArray<NSDictionary<NSString*,id>*> *HFASemanticFeatureBindings(NSArray *runtimeEvidence,NSDictionary *semanticEvidence,uintptr_t anchorAddress){
    if(!runtimeEvidence.count||!semanticEvidence.count||!anchorAddress)return @[];NSArray *mat=[semanticEvidence[@"materializedAddresses"] isKindOfClass:NSArray.class]?semanticEvidence[@"materializedAddresses"]:@[];NSMutableSet *loaded=[NSMutableSet set];for(NSDictionary *e in mat){NSNumber *n=[e[@"runtimeAddress"] isKindOfClass:NSNumber.class]?e[@"runtimeAddress"]:nil;if(n)[loaded addObject:n];}if(!loaded.count)return @[];
    NSMutableArray *out=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];for(NSDictionary *f in runtimeEvidence){NSString *identifier=[f[@"identifier"] isKindOfClass:NSString.class]?f[@"identifier"]:nil;if(!identifier.length||[seen containsObject:identifier])continue;NSNumber *match=nil;for(NSNumber *n in HFASemIdentifierAddresses(identifier,anchorAddress))if([loaded containsObject:n]){match=n;break;}if(!match)continue;[seen addObject:identifier];NSMutableDictionary *b=[@{@"identifier":identifier,@"confidence":@"strong",@"evidence":@"cfstring-reference",@"matchedRuntimeAddress":match} mutableCopy];if([f[@"title"] isKindOfClass:NSString.class])b[@"title"]=f[@"title"];if([f[@"type"] isKindOfClass:NSString.class])b[@"controlType"]=f[@"type"];[out addObject:b];}return out;
}
'''
    s=s.replace(anchor,helpers+anchor,1)

a,b=function_span(s,'HFASemanticAnalyzeReplacementBounded');fn=s[a:b]
vars='''    NSMutableArray *helperCalls=[NSMutableArray array];\n    NSMutableSet *seenCapture=[NSMutableSet set];'''
if vars not in fn: raise SystemExit('materialized vars anchor missing')
fn=fn.replace(vars,'''    NSMutableArray *helperCalls=[NSMutableArray array];\n    NSMutableArray *materializedAddresses=[NSMutableArray array];\n    NSMutableSet *seenMaterialized=[NSMutableSet set];\n    NSMutableSet *seenCapture=[NSMutableSet set];''',1)
flow='''        if(HFASemADRP(w,pc,&av)||HFASemADR(w,pc,&av)){rd=w&31u;addr[rd]=av;addrKnown[rd]=YES;continue;}\n        if(HFASemAddImm64(w,&rd,&rn,&imm)){if(addrKnown[rn]){addr[rd]=addr[rn]+imm;addrKnown[rd]=YES;}else addrKnown[rd]=NO;if(receiverTaint[rn]){receiverTaint[rd]=YES;receiverOffset[rd]=receiverOffset[rn]+(uint32_t)imm;}continue;}'''
repl='''        if(HFASemADRP(w,pc,&av)){rd=w&31u;addr[rd]=av;addrKnown[rd]=YES;continue;}\n        if(HFASemADR(w,pc,&av)){rd=w&31u;addr[rd]=av;addrKnown[rd]=YES;HFASemRecordMaterialized(materializedAddresses,seenMaterialized,av,@"ADR",pc,image);continue;}\n        if(HFASemAddImm64(w,&rd,&rn,&imm)){if(addrKnown[rn]){addr[rd]=addr[rn]+imm;addrKnown[rd]=YES;HFASemRecordMaterialized(materializedAddresses,seenMaterialized,addr[rd],@"ADRP/ADD",pc,image);}else addrKnown[rd]=NO;if(receiverTaint[rn]){receiverTaint[rd]=YES;receiverOffset[rd]=receiverOffset[rn]+(uint32_t)imm;}continue;}'''
if flow not in fn: raise SystemExit('materialized flow anchor missing')
fn=fn.replace(flow,repl,1)
safe='else if(eff){uintptr_t p=0;if(HFASemReadPointer(eff,&p)){addr[rd]=p;addrKnown[rd]=p!=0;}else addrKnown[rd]=NO;}'
if safe not in fn: raise SystemExit('materialized ldr anchor missing')
fn=fn.replace(safe,'else if(eff){uintptr_t p=0;if(HFASemReadPointer(eff,&p)){addr[rd]=p;addrKnown[rd]=p!=0;if(p)HFASemRecordMaterialized(materializedAddresses,seenMaterialized,p,@"LDR-pointer",pc,image);}else addrKnown[rd]=NO;}',1)
ret='''        @"helperCalls":helperCalls?:@[]\n    };'''
if ret not in fn: raise SystemExit('materialized return anchor missing')
fn=fn.replace(ret,'''        @"helperCalls":helperCalls?:@[],\n        @"materializedAddresses":materializedAddresses?:@[]\n    };''',1)
s=s[:a]+fn+s[b:];SEM.write_text(s)

h=HDR.read_text()
if 'HFASemanticFeatureBindings' not in h:h+='\nFOUNDATION_EXPORT NSArray<NSDictionary<NSString*,id>*> *HFASemanticFeatureBindings(NSArray *runtimeEvidence,NSDictionary *semanticEvidence,uintptr_t anchorAddress);\n'
HDR.write_text(h)

m=SRC.read_text();anchor='NSArray *runtime=HFA5MDispatcherAllEvidence()?:@[];'
if anchor not in m: raise SystemExit('runtime binding anchor missing')
insert=r'''NSArray *runtime=HFA5MDispatcherAllEvidence()?:@[];
    NSUInteger bindingCount35=0;
    for(NSMutableDictionary *bb in backends){NSString *rv=[bb[@"replacementRVA"] isKindOfClass:NSString.class]?bb[@"replacementRVA"]:nil;BOOL ok=NO;uint64_t off=HFAV032HexValue(rv,&ok);if(!ok)continue;NSDictionary *sev=[bb[@"semanticEvidence"] isKindOfClass:NSDictionary.class]?bb[@"semanticEvidence"]:@{};NSArray *fb=HFASemanticFeatureBindings(runtime,sev,l.base+(uintptr_t)off);if(fb.count){bb[@"featureBindings"]=fb;bindingCount35+=fb.count;HFAV02Log([NSString stringWithFormat:@"[V035-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)fb.count]);}}'''
m=m.replace(anchor,insert,1)
summary='@"orphanPatches":@(orphans.count)'
if summary not in m: raise SystemExit('binding summary anchor missing')
m=m.replace(summary,summary+',@"featureBindings":@(bindingCount35)',1)
SRC.write_text(m)

for req in ['HFASemanticFeatureBindings','materializedAddresses','cfstring-reference']:
    if req not in SEM.read_text():raise SystemExit('missing '+req)
if '[V035-BIND]' not in SRC.read_text():raise SystemExit('binding integration missing')
print('v0.3.5 feature binding evidence applied')

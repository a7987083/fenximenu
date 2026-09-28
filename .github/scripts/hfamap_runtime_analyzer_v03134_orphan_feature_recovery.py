from pathlib import Path

TRACE = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
s = TRACE.read_text()

sig = 'static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates)'
pos = s.find(sig)
if pos < 0:
    raise SystemExit('orphan recovery bridge anchor missing')

helpers = r'''
extern const char *HFAAppLocalPrimaryImage(void);
typedef struct { uintptr_t base; intptr_t slide; uintptr_t textStart,textEnd,cfStart,cfEnd,cstrStart,cstrEnd; } HFA03134MenuLayout;
static BOOL HFA03134MenuLayoutLoad(HFA03134MenuLayout *out){
    if(!out)return NO;memset(out,0,sizeof(*out));const char *want=HFAAppLocalPrimaryImage();if(!want||!*want)return NO;
    uint32_t n=_dyld_image_count();for(uint32_t i=0;i<n;i++){const char *p=_dyld_get_image_name(i);if(!p||strcmp(HFABase(p),want))continue;const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header(i);if(!h||h->magic!=MH_MAGIC_64)return NO;out->base=(uintptr_t)h;out->slide=_dyld_image_vmaddr_slide(i);const uint8_t *cur=(const uint8_t*)(h+1);for(uint32_t c=0;c<h->ncmds;c++){const struct load_command *lc=(const struct load_command*)cur;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *seg=(const struct segment_command_64*)cur;const struct section_64 *sec=(const struct section_64*)(seg+1);for(uint32_t q=0;q<seg->nsects;q++){uintptr_t a=(uintptr_t)out->slide+(uintptr_t)sec[q].addr,e=a+(uintptr_t)sec[q].size;if(e<=a)continue;if(!strncmp(sec[q].sectname,"__text",16)){out->textStart=a;out->textEnd=e;}else if(!strncmp(sec[q].sectname,"__cfstring",16)){out->cfStart=a;out->cfEnd=e;}else if(!strncmp(sec[q].sectname,"__cstring",16)){out->cstrStart=a;out->cstrEnd=e;}}}cur+=lc->cmdsize;}return out->textStart&&out->textEnd>out->textStart;}return NO;
}
static int64_t HFA03134SX(uint64_t v,unsigned bits){uint64_t m=1ULL<<(bits-1);return(int64_t)((v^m)-m);}
static BOOL HFA03134ADR(uint32_t w,uintptr_t pc,unsigned *rd,uintptr_t *addr){if((w&0x9F000000u)!=0x10000000u)return NO;uint64_t imm=((uint64_t)((w>>5)&0x7FFFFu)<<2)|((w>>29)&3u);if(rd)*rd=w&31u;if(addr)*addr=(uintptr_t)((int64_t)pc+HFA03134SX(imm,21));return YES;}
static BOOL HFA03134ADRP(uint32_t w,uintptr_t pc,unsigned *rd,uintptr_t *page){if((w&0x9F000000u)!=0x90000000u)return NO;uint64_t imm=((uint64_t)((w>>5)&0x7FFFFu)<<2)|((w>>29)&3u);if(rd)*rd=w&31u;if(page)*page=(pc&~(uintptr_t)0xFFF)+(HFA03134SX(imm,21)<<12);return YES;}
static BOOL HFA03134ADD(uint32_t w,unsigned *rd,unsigned *rn,uint64_t *imm){if((w&0xFF000000u)!=0x91000000u)return NO;uint64_t x=(w>>10)&0xFFFu;if((w>>22)&1u)x<<=12;if(rd)*rd=w&31u;if(rn)*rn=(w>>5)&31u;if(imm)*imm=x;return YES;}
static BOOL HFA03134FrameStart(uint32_t w){return w==0xD503233Fu||w==0xD503237Fu||((w&0xFFC07FFFu)==0xA9807BFDu);}
static uintptr_t HFA03134GuessOwnerStart(uintptr_t pc,HFA03134MenuLayout l){uintptr_t lo=pc>0x1000?pc-0x1000:l.textStart;if(lo<l.textStart)lo=l.textStart;uintptr_t p=pc&~(uintptr_t)3;while(p>=lo+4){uint32_t w=0,prev=0;memcpy(&w,(void*)p,4);memcpy(&prev,(void*)(p-4),4);if(HFA03134FrameStart(w))return p;if(prev==0xD65F03C0u)return p;if(p<lo+8)break;p-=4;}return 0;}
static NSString *HFA03134StringAt(uintptr_t a,HFA03134MenuLayout l){
    if(a>=l.cfStart&&a<l.cfEnd){@try{id obj=(id)(void*)a;if([obj isKindOfClass:NSString.class]){NSString *v=(NSString*)obj;if(v.length&&v.length<=128)return v;}}@catch(__unused id ex){} }
    if(a>=l.cstrStart&&a<l.cstrEnd&&HFAReadable(a,1)){char b[129]={0};NSUInteger n=0;for(;n<128&&HFAReadable(a+n,1);n++){unsigned char c=*(const unsigned char*)(a+n);if(!c)break;if(c<0x20||c>0x7E)return nil;b[n]=(char)c;}if(n)return [NSString stringWithUTF8String:b];}
    return nil;
}
static NSDictionary *HFA03134RegistrationEvidence(NSDictionary *backend,HFA03134MenuLayout l){
    uint64_t xr=HFA03134FirstXrefRVA(backend);if(!xr||!l.base)return @{};uintptr_t pc=l.base+(uintptr_t)xr;if(pc<l.textStart||pc>=l.textEnd)return @{};uintptr_t start=HFA03134GuessOwnerStart(pc,l);if(!start)return @{};uintptr_t end=MIN(start+0x800u,l.textEnd);NSMutableOrderedSet *strings=[NSMutableOrderedSet orderedSet];NSMutableOrderedSet *keys=[NSMutableOrderedSet orderedSet];
    const uint32_t *w=(const uint32_t*)start;NSUInteger n=(end-start)/4;for(NSUInteger i=0;i<n;i++){uintptr_t ip=start+i*4,target=0;unsigned r=0;BOOL materialized=HFA03134ADR(w[i],ip,&r,&target);if(!materialized){uintptr_t page=0;if(HFA03134ADRP(w[i],ip,&r,&page)){for(NSUInteger q=i+1;q<n&&q<=i+3;q++){unsigned rd=0,rn=0;uint64_t imm=0;if(HFA03134ADD(w[q],&rd,&rn,&imm)&&rn==r){target=page+(uintptr_t)imm;materialized=YES;break;}}}}if(!materialized)continue;NSString *str=HFA03134StringAt(target,l);if(!str.length)continue;[strings addObject:str];if([str hasSuffix:@"-switch"]&&str.length>7)[keys addObject:str];if(strings.count>=32)break;}
    NSMutableDictionary *ev=[@{@"ownerFunctionRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(start-l.base)],@"xrefRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)xr],@"registrationHints":strings.array?:@[],@"exactSwitchKeys":keys.array?:@[]} mutableCopy];if(keys.count==1)ev[@"exactSwitchKey"]=keys.firstObject;return ev;
}
'''

if 'HFA03134RegistrationEvidence' not in s:
    s = s[:pos] + helpers + '\n' + s[pos:]

old = 'NSMutableDictionary *clusterOwnerByBackend=[NSMutableDictionary dictionary];\n    NSMutableDictionary *clusterIdByBackend=[NSMutableDictionary dictionary];'
new = 'NSMutableDictionary *clusterOwnerByBackend=[NSMutableDictionary dictionary];\n    NSMutableDictionary *clusterIdByBackend=[NSMutableDictionary dictionary];\n    NSMutableDictionary *registrationEvidenceByBackend=[NSMutableDictionary dictionary];\n    HFA03134MenuLayout registrationLayout={0};BOOL haveRegistrationLayout=HFA03134MenuLayoutLoad(&registrationLayout);'
if old not in s: raise SystemExit('cluster map anchor missing')
s = s.replace(old,new,1)

old = 'for(NSDictionary *backend in backends){uint64_t xr=HFA03134FirstXrefRVA(backend);if(xr)[ordered addObject:@{@"backend":backend,@"xref":@(xr)}];}'
new = 'for(NSDictionary *backend in backends){uint64_t xr=HFA03134FirstXrefRVA(backend);if(xr){[ordered addObject:@{@"backend":backend,@"xref":@(xr)}];if(haveRegistrationLayout){NSDictionary *ev=HFA03134RegistrationEvidence(backend,registrationLayout);if(ev.count)registrationEvidenceByBackend[[backend[@"backendId"] description]?:@""]=ev;}}}'
if old not in s: raise SystemExit('ordered backend anchor missing')
s = s.replace(old,new,1)

cluster_decl = 'NSString *clusterId=[NSString stringWithFormat:@"xref-cluster-%lu",(unsigned long)clusterNo];'
status_decl = 'NSString *status=owners.count==1?@"anchored":(owners.count?@"ambiguous":@"orphan");'
needle = cluster_decl + status_decl
if needle not in s: raise SystemExit('cluster status small anchor missing')
recovery = cluster_decl + r'''
        NSDictionary *recovered=nil;NSMutableOrderedSet *exactKeys=[NSMutableOrderedSet orderedSet];NSMutableOrderedSet *ownerFunctions=[NSMutableOrderedSet orderedSet];NSMutableOrderedSet *allHints=[NSMutableOrderedSet orderedSet];
        if(owners.count==0){for(NSUInteger i=clusterStart;i<end;i++){NSDictionary *be=ordered[i][@"backend"];NSString *rbid=[be[@"backendId"] description]?:@"";NSDictionary *ev=registrationEvidenceByBackend[rbid];NSString *fn=[ev[@"ownerFunctionRVA"] description];if(fn.length)[ownerFunctions addObject:fn];for(NSString *k in [ev[@"exactSwitchKeys"] isKindOfClass:NSArray.class]?ev[@"exactSwitchKeys"]:@[])if(k.length)[exactKeys addObject:k];for(NSString *h in [ev[@"registrationHints"] isKindOfClass:NSArray.class]?ev[@"registrationHints"]:@[])if(h.length)[allHints addObject:h];}
            if(exactKeys.count==1){NSString *key=exactKeys.firstObject;NSString *fid=[key substringToIndex:key.length-7];if(fid.length)recovered=@{@"featureId":fid,@"title":fid,@"key":key,@"descriptorIndex":@(-1),@"source":@"static-registration-key",@"clusterId":clusterId,@"ownerFunctions":ownerFunctions.array?:@[],@"registrationHints":allHints.array?:@[]};}
        }
        if(recovered){owners[recovered[@"featureId"]]=recovered;HFALog("[V03134-ORPHAN-RECOVERY] cluster=%s status=recovered source=static-registration-key feature=%s key=%s functions=%u hints=%u\n",clusterId.UTF8String?:"?",[recovered[@"featureId"] UTF8String]?:"?",[recovered[@"key"] UTF8String]?:"?",(unsigned)ownerFunctions.count,(unsigned)allHints.count);}else if(owners.count==0){HFALog("[V03134-ORPHAN-RECOVERY] cluster=%s status=unresolved exactKeys=%u functions=%u hints=%u values=%s\n",clusterId.UTF8String?:"?",(unsigned)exactKeys.count,(unsigned)ownerFunctions.count,(unsigned)allHints.count,[[allHints.array componentsJoinedByString:@"|"] UTF8String]?:"");}
        NSString *status=owners.count==1?(recovered?@"recovered":@"anchored"):(owners.count?@"ambiguous":@"orphan");'''
s = s.replace(needle,recovery,1)

# Attach evidence to all ledger rows without depending on whether they matched
# the legacy signature bridge or entered the unowned path.
ev_anchor = 'NSString *cid=clusterIdByBackend[[be[@"backendId"] description]?:@""];if(cid.length)e[@"staticClusterId"]=cid;'
if ev_anchor not in s: raise SystemExit('ledger cluster evidence anchor missing')
ev_new = 'NSString *regBid=[be[@"backendId"] description]?:@"";NSString *cid=clusterIdByBackend[regBid];if(cid.length)e[@"staticClusterId"]=cid;NSDictionary *regEv=registrationEvidenceByBackend[regBid];if(regEv.count)e[@"staticRegistrationEvidence"]=regEv;'
s = s.replace(ev_anchor,ev_new)

TRACE.write_text(s)
out=TRACE.read_text()
for marker in ['HFA03134RegistrationEvidence','[V03134-ORPHAN-RECOVERY]','static-registration-key','staticRegistrationEvidence','exactSwitchKeys']:
    if marker not in out: raise SystemExit('missing orphan recovery marker '+marker)
print('v0.3.13.4 generic static orphan feature recovery applied')

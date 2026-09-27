from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
UI=Path('hfamap/src/HFAMapCyberUI.m')
s=TRACE.read_text()


def function_span(text, signature):
    start=text.find(signature)
    if start<0: raise SystemExit(f'missing function: {signature}')
    brace=text.find('{',start)
    if brace<0: raise SystemExit(f'missing brace: {signature}')
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
    raise SystemExit(f'unterminated function: {signature}')

sig='static BOOL HFA03132CanonicalTarget(NSString *target,NSString *offset,NSString *explicitUUID,NSString **identityOut,uint64_t *rvaOut)'
a,b=function_span(s,sig)
canonical=r'''static BOOL HFA03133CanonicalTarget(NSString *target,NSString *offset,NSString *explicitUUID,NSString **identityOut,uint64_t *rvaOut){
    if(!target.length||!offset.length)return NO;int idx=HFAImageIndexForName(target.UTF8String);if(idx<0)return NO;
    const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header((uint32_t)idx);if(!h||h->magic!=MH_MAGIC_64)return NO;
    char *end=NULL;uint64_t raw=strtoull(offset.UTF8String,&end,16);if(!end||*end)return NO;
    uint64_t minVM=UINT64_MAX;BOOL preferred=NO;const uint8_t *cur=(const uint8_t*)(h+1);
    for(uint32_t i=0;i<h->ncmds;i++){
        const struct load_command *lc=(const struct load_command*)cur;if(!lc->cmdsize)break;
        if(lc->cmd==LC_SEGMENT_64){
            const struct segment_command_64 *seg=(const struct segment_command_64*)cur;
            BOOL realSegment=strcmp(seg->segname,"__PAGEZERO")!=0&&seg->vmsize!=0;
            if(realSegment&&seg->vmaddr<minVM)minVM=seg->vmaddr;
            if(realSegment&&raw>=seg->vmaddr&&(raw-seg->vmaddr)<seg->vmsize)preferred=YES;
        }
        cur+=lc->cmdsize;
    }
    if(minVM==UINT64_MAX)return NO;
    uint64_t rva=preferred?(raw-minVM):raw;
    NSString *runtimeUUID=HFA03131ImageUUIDForIndex(idx);NSString *serialized=[explicitUUID uppercaseString];NSString *identity=runtimeUUID.length?runtimeUUID:serialized;
    if(runtimeUUID.length&&serialized.length&&![runtimeUUID isEqual:serialized])HFALog("[V03132-IDENTITY-OVERRIDE] target=%s serialized=%s runtime=%s\\n",target.UTF8String?:"?",serialized.UTF8String?:"?",runtimeUUID.UTF8String?:"?");
    if(!identity.length){const char *p=_dyld_get_image_name((uint32_t)idx);identity=p?[NSString stringWithUTF8String:HFABase(p)]:target;}
    HFALog("[V03133-RVA-NORMALIZE] target=%s raw=0x%llX minVM=0x%llX mode=%s canonical=0x%llX\\n",target.UTF8String?:"?",(unsigned long long)raw,(unsigned long long)minVM,preferred?"preferred":"rva",(unsigned long long)rva);
    if(identityOut)*identityOut=identity?:@"";if(rvaOut)*rvaOut=rva;return YES;
}'''
s=s[:a]+canonical+s[b:]
s=s.replace('HFA03132CanonicalTarget(', 'HFA03133CanonicalTarget(')

s=s.replace('com.hfa.static-canonical-audit/v0.3.13.2','com.hfa.static-canonical-audit/v0.3.13.3')
s=s.replace('HFAMap_StaticCanonical_v03132.json','HFAMap_StaticCanonical_v03133.json')
s=s.replace('[V03132-MAIN-IMAGE]','[V03133-MAIN-IMAGE]')
s=s.replace('[V03132-ANALYZER-PREPASS]','[V03133-ANALYZER-PREPASS]')
s=s.replace('[V03132-LEDGER-BRIDGE]','[V03133-LEDGER-BRIDGE]')
s=s.replace('[V03132-STATIC-CANONICAL]','[V03133-STATIC-CANONICAL]')
TRACE.write_text(s)

ui=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.2 MainImageIdentityFix','HFAMap RuntimeAnalyzer v0.3.13.3 PageZeroRVAFix')
UI.write_text(ui)

out=TRACE.read_text()
for req in ['HFA03133CanonicalTarget','realSegment=strcmp(seg->segname,"__PAGEZERO")!=0','[V03133-RVA-NORMALIZE]','[V03133-MAIN-IMAGE]','[V03133-ANALYZER-PREPASS]','[V03133-LEDGER-BRIDGE]','[V03133-STATIC-CANONICAL]','uuid+rva+original+enabled','HFAMap_StaticCanonical_v03133.json']:
    if req not in out: raise SystemExit('v03133 generated trace missing '+req)
if 'if(seg->vmsize&&raw>=seg->vmaddr&&raw<seg->vmaddr+seg->vmsize)preferred=YES;' in out:
    raise SystemExit('v03133 stale PAGEZERO-inclusive preferred-range test remains')
print('v0.3.13.3 PAGEZERO-safe canonical RVA fix applied')

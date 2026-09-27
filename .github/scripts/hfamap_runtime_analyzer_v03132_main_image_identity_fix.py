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

# Replace the global image-name resolver so every Class-1 path resolves "main"
# to the actual NSBundle executable image rather than assuming dyld index 0.
a,b=function_span(s,'static int HFAImageIndexForName(const char *value)')
main_resolver=r'''static int HFA03132MainImageIndex(void) {
    NSString *wanted=NSBundle.mainBundle.executablePath.stringByStandardizingPath;
    NSString *wantedResolved=wanted.stringByResolvingSymlinksInPath;
    NSString *wantedBase=wanted.lastPathComponent?:@"";
    uint32_t count=_dyld_image_count();
    int exact=-1,resolved=-1,basenameExecutable=-1,onlyExecutable=-1;unsigned executableCount=0;
    for(uint32_t i=0;i<count;i++){
        const char *raw=_dyld_get_image_name(i);if(!raw)continue;
        NSString *path=[[NSString stringWithUTF8String:raw] stringByStandardizingPath];
        if(wanted.length&&[path isEqualToString:wanted])exact=(int)i;
        if(wantedResolved.length&&[[path stringByResolvingSymlinksInPath] isEqualToString:wantedResolved])resolved=(int)i;
        const struct mach_header *mh=_dyld_get_image_header(i);BOOL isExecutable=mh&&mh->filetype==MH_EXECUTE;
        if(isExecutable){onlyExecutable=(int)i;executableCount++;if(wantedBase.length&&[path.lastPathComponent isEqualToString:wantedBase])basenameExecutable=(int)i;}
    }
    if(exact>=0)return exact;
    if(resolved>=0)return resolved;
    if(basenameExecutable>=0)return basenameExecutable;
    return executableCount==1?onlyExecutable:-1;
}
static BOOL HFA03132IsMainImageIndex(int idx){return idx>=0&&idx==HFA03132MainImageIndex();}
static int HFAImageIndexForName(const char *value) {
    if (!value || !*value) return -1;
    if (strcmp(value, "main") == 0) return HFA03132MainImageIndex();
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *base = HFABase(_dyld_get_image_name(i));
        if (strcmp(value, base) == 0) return (int)i;
        char stem[256]; snprintf(stem, sizeof(stem), "%s", base);
        char *dot = strrchr(stem, '.'); if (dot) *dot = 0;
        if (strcmp(value, stem) == 0) return (int)i;
    }
    return -1;
}'''
s=s[:a]+main_resolver+s[b:]

# Canonical target identity must be derived from the actually loaded target
# image. Runtime UUID is authoritative; serialized UUID is only a fallback.
a,b=function_span(s,'static BOOL HFA03131CanonicalTarget(NSString *target,NSString *offset,NSString *explicitUUID,NSString **identityOut,uint64_t *rvaOut)')
canonical=r'''static BOOL HFA03132CanonicalTarget(NSString *target,NSString *offset,NSString *explicitUUID,NSString **identityOut,uint64_t *rvaOut){
    if(!target.length||!offset.length)return NO;int idx=HFAImageIndexForName(target.UTF8String);if(idx<0)return NO;
    const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header((uint32_t)idx);if(!h||h->magic!=MH_MAGIC_64)return NO;
    char *end=NULL;uint64_t raw=strtoull(offset.UTF8String,&end,16);if(!end||*end)return NO;
    uint64_t minVM=UINT64_MAX;BOOL preferred=NO;const uint8_t *cur=(const uint8_t*)(h+1);
    for(uint32_t i=0;i<h->ncmds;i++){
        const struct load_command *lc=(const struct load_command*)cur;if(!lc->cmdsize)break;
        if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *seg=(const struct segment_command_64*)cur;if(strcmp(seg->segname,"__PAGEZERO")&&seg->vmsize&&seg->vmaddr<minVM)minVM=seg->vmaddr;if(seg->vmsize&&raw>=seg->vmaddr&&raw<seg->vmaddr+seg->vmsize)preferred=YES;}
        cur+=lc->cmdsize;
    }
    if(minVM==UINT64_MAX)return NO;uint64_t rva=preferred?(raw-minVM):raw;
    NSString *runtimeUUID=HFA03131ImageUUIDForIndex(idx);NSString *serialized=[explicitUUID uppercaseString];NSString *identity=runtimeUUID.length?runtimeUUID:serialized;
    if(runtimeUUID.length&&serialized.length&&![runtimeUUID isEqual:serialized])HFALog("[V03132-IDENTITY-OVERRIDE] target=%s serialized=%s runtime=%s\\n",target.UTF8String?:"?",serialized.UTF8String?:"?",runtimeUUID.UTF8String?:"?");
    if(!identity.length){const char *p=_dyld_get_image_name((uint32_t)idx);identity=p?[NSString stringWithUTF8String:HFABase(p)]:target;}
    if(identityOut)*identityOut=identity?:@"";if(rvaOut)*rvaOut=rva;return YES;
}'''
s=s[:a]+canonical+s[b:]
s=s.replace('HFA03131CanonicalTarget(', 'HFA03132CanonicalTarget(')
s=s.replace('@"identity+rva+original+enabled"', '@"uuid+rva+original+enabled"')
s=s.replace('matchKey=identity+rva+original+enabled', 'matchKey=uuid+rva+original+enabled')

# v0.3.12 used imageIndex==0 as a synonym for main. Preserve target="main"
# using the real executable image index instead.
old='NSString *fid=ident[@"id"],*tid=imageIndex==0?@"main":[NSString stringWithUTF8String:d->module],*image=imageIndex==0?@"@main":[NSString stringWithUTF8String:HFABase(_dyld_get_image_name((uint32_t)imageIndex))];'
new='BOOL isMainImage=HFA03132IsMainImageIndex(imageIndex);NSString *fid=ident[@"id"],*tid=isMainImage?@"main":[NSString stringWithUTF8String:d->module],*image=isMainImage?@"@main":[NSString stringWithUTF8String:HFABase(_dyld_get_image_name((uint32_t)imageIndex))];'
if old not in s: raise SystemExit('v03132 legacy main-target classification anchor missing')
s=s.replace(old,new,1)

# Architecture identity must also use the true executable header.
old='const struct mach_header *header=_dyld_get_image_header(0);cpu_subtype_t subtype=header?(header->cpusubtype&~CPU_SUBTYPE_MASK):0;'
new='int mainImageIndex=HFA03132MainImageIndex();const struct mach_header *header=mainImageIndex>=0?_dyld_get_image_header((uint32_t)mainImageIndex):NULL;cpu_subtype_t subtype=header?(header->cpusubtype&~CPU_SUBTYPE_MASK):0;'
if old in s:s=s.replace(old,new,1)

# Emit one explicit identity record per export before the analyzer prepass.
anchor='HFAAnalyzerV02BeginExportEpoch();unsigned analyzerNative=HFAAnalyzerV02ScanSelectedImage();'
insert='int v03132MainIndex=HFA03132MainImageIndex();NSString *v03132MainUUID=HFA03131ImageUUIDForIndex(v03132MainIndex);const char *v03132MainPath=v03132MainIndex>=0?_dyld_get_image_name((uint32_t)v03132MainIndex):NULL;HFALog("[V03132-MAIN-IMAGE] index=%d path=%s bundleExecutable=%s uuid=%s\\n",v03132MainIndex,v03132MainPath?:"?",NSBundle.mainBundle.executablePath.UTF8String?:"?",v03132MainUUID.UTF8String?:"?");HFAAnalyzerV02BeginExportEpoch();unsigned analyzerNative=HFAAnalyzerV02ScanSelectedImage();'
if anchor not in s: raise SystemExit('v03132 analyzer prepass anchor missing')
s=s.replace(anchor,insert,1)

# Version markers/audit while retaining the v0.3.13.1 analyzer guard implementation.
s=s.replace('com.hfa.static-canonical-audit/v0.3.13.1','com.hfa.static-canonical-audit/v0.3.13.2')
s=s.replace('HFAMap_StaticCanonical_v03131.json','HFAMap_StaticCanonical_v03132.json')
s=s.replace('[V03131-ANALYZER-PREPASS]','[V03132-ANALYZER-PREPASS]')
s=s.replace('[V03131-LEDGER-BRIDGE]','[V03132-LEDGER-BRIDGE]')
s=s.replace('[V03131-STATIC-CANONICAL]','[V03132-STATIC-CANONICAL]')
TRACE.write_text(s)

ui=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.1 SinglePassLedgerBridge','HFAMap RuntimeAnalyzer v0.3.13.2 MainImageIdentityFix')
UI.write_text(ui)

out=TRACE.read_text()
for req in ['HFA03132MainImageIndex','MH_EXECUTE','HFA03132CanonicalTarget','[V03132-MAIN-IMAGE]','[V03132-ANALYZER-PREPASS]','[V03132-LEDGER-BRIDGE]','[V03132-STATIC-CANONICAL]','uuid+rva+original+enabled','HFAMap_StaticCanonical_v03132.json']:
    if req not in out: raise SystemExit('v03132 generated trace missing '+req)
if 'strcmp(value, "main") == 0) return 0;' in out:
    raise SystemExit('v03132 stale main->dyld-index-0 assumption remains')
print('v0.3.13.2 main executable identity fix applied')

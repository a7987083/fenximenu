from pathlib import Path

GENERIC=Path('hfamap/src/HFAMapGenericMenuResolver.m')
EXPORTER=Path('hfamap/src/HFAMapJSONExport.m')
MAKEFILE=Path('hfamap/Makefile')
CROSS=Path('hfamap/src/HFAMapCrossImageResolver.m')
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
if '#import "HFAMapCrossImageResolver.h"' not in g:
    g=g.replace('#import "HFAMapIL2CPPRuntimeResolver.h"','#import "HFAMapIL2CPPRuntimeResolver.h"\n#import "HFAMapCrossImageResolver.h"',1)

a,b=function_span(g,'static NSDictionary *HFAAddressInfo(const void *address)')
new=r'''static NSDictionary *HFAAddressInfo(const void *address) {
    if (!address) return nil;
    Dl_info info = {0};
    if (!dladdr(address, &info) || !info.dli_fbase || !info.dli_fname) return nil;
    uintptr_t value = (uintptr_t)address;
    uintptr_t base = (uintptr_t)info.dli_fbase;
    NSMutableDictionary *out=[NSMutableDictionary dictionaryWithObjectsAndKeys:
        [NSString stringWithUTF8String:HFABaseName(info.dli_fname)] ?: @"?", @"image",
        [NSString stringWithFormat:@"0x%llX", (unsigned long long)(value - base)], @"rva", nil];
    NSDictionary *cross=HFACrossImageResolveTarget(address);
    const void *semanticAddress=address;
    if([cross isKindOfClass:[NSDictionary class]]&&cross.count){
        [out setObject:cross forKey:@"crossImage"];
        uintptr_t finalAddress=(uintptr_t)[[cross objectForKey:@"finalAddressValue"] unsignedLongLongValue];
        if(finalAddress)semanticAddress=(const void *)finalAddress;
        NSDictionary *finalInfo=[cross objectForKey:@"final"];
        HFAGenericLog("[V031312-CROSSIMAGE] from=%s+%s to=%s+%s hops=%lu crossed=%u\n",
                      [[out objectForKey:@"image"] UTF8String]?:"?",
                      [[out objectForKey:@"rva"] UTF8String]?:"?",
                      [[finalInfo objectForKey:@"image"] UTF8String]?:"?",
                      [[finalInfo objectForKey:@"rva"] UTF8String]?:"?",
                      (unsigned long)[[cross objectForKey:@"hops"] count],
                      [[cross objectForKey:@"crossImage"] boolValue]);
    }
    NSDictionary *il2cpp=HFAIL2CPPResolveNativeAddress(semanticAddress);
    if([il2cpp isKindOfClass:[NSDictionary class]]&&il2cpp.count){
        [out setObject:il2cpp forKey:@"il2cpp"];
        HFAGenericLog("[V031311-HYBRID] image=%s rva=%s il2cpp=%s\n",
                      [[out objectForKey:@"image"] UTF8String]?:"?",
                      [[out objectForKey:@"rva"] UTF8String]?:"?",
                      [[il2cpp objectForKey:@"canonical"] UTF8String]?:"?");
    }
    return out;
}'''
g=g[:a]+new+g[b:]

blr_anchor='if((ins&0xFFFFFC1Fu)==0xD63F0000u){unsigned targetReg=(ins>>5)&31;BOOL hasTaintedArg=NO;'
blr_repl='''if((ins&0xFFFFFC1Fu)==0xD63F0000u){unsigned targetReg=(ins>>5)&31;NSDictionary *crossCall=HFACrossImageResolveBLRCallsite((void*)start,off,targetReg);if([crossCall isKindOfClass:[NSDictionary class]]&&crossCall.count){NSMutableDictionary *cc=[NSMutableDictionary dictionaryWithDictionary:crossCall];uintptr_t finalAddress=(uintptr_t)[[cc objectForKey:@"finalAddressValue"] unsignedLongLongValue];NSDictionary *semantic=finalAddress?HFAAddressInfo((void*)finalAddress):nil;if(semantic)[cc setObject:semantic forKey:@"semanticTarget"];crossCall=cc;NSDictionary *fi=[crossCall objectForKey:@"final"];HFAGenericLog("[V031312-BLR] off=0x%X target=x%u via=%s to=%s+%s\\n",off,targetReg,[[crossCall objectForKey:@"via"] UTF8String]?:"?",[[fi objectForKey:@"image"] UTF8String]?:"?",[[fi objectForKey:@"rva"] UTF8String]?:"?");}BOOL hasTaintedArg=NO;'''
if blr_anchor not in g: raise SystemExit('BLR anchor missing')
g=g.replace(blr_anchor,blr_repl,1)

de_anchor='NSDictionary *de=@{@"type":@"indirect-call-return",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"targetRegister":@(targetReg),@"argumentMask":@(argMask),@"depth":@(nd),@"candidateOnly":@YES};'
de_repl='NSMutableDictionary *de=[NSMutableDictionary dictionaryWithDictionary:@{@"type":@"indirect-call-return",@"insnRVA":[NSString stringWithFormat:@"0x%X",off],@"targetRegister":@(targetReg),@"argumentMask":@(argMask),@"depth":@(nd),@"candidateOnly":@YES}];if(crossCall)[de setObject:crossCall forKey:@"crossImageCall"];'
if de_anchor not in g: raise SystemExit('BLR derived-event anchor missing')
g=g.replace(de_anchor,de_repl,1)
GENERIC.write_text(g)

x=EXPORTER.read_text()
if '#import "HFAMapCrossImageResolver.h"' not in x:
    x=x.replace('#import "HFAMapIL2CPPRuntimeResolver.h"','#import "HFAMapIL2CPPRuntimeResolver.h"\n#import "HFAMapCrossImageResolver.h"',1)
needle='root[@"il2cppRuntime"] = HFAIL2CPPResolverStatus();'
if needle not in x: raise SystemExit('IL2CPP exporter anchor missing')
x=x.replace(needle,needle+'\n        root[@"crossImageRuntime"] = HFACrossImageResolverStatus();',1)
EXPORTER.write_text(x)

m=MAKEFILE.read_text()
needle='src/HFAMapIL2CPPRuntimeResolver.m'
if 'src/HFAMapCrossImageResolver.m' not in m:
    if needle not in m: raise SystemExit('Makefile IL2CPP anchor missing')
    m=m.replace(needle,'src/HFAMapCrossImageResolver.m '+needle,1)
MAKEFILE.write_text(m)

c=CROSS.read_text()
c=c.replace('#import <mach/mach.h>\n#import <mach/mach_vm.h>\n#import <mach-o/dyld.h>', '#import <mach-o/dyld.h>\n#import <mach-o/loader.h>\n#import <mach/vm_prot.h>', 1)
a,b=function_span(c,'static BOOL HFAXReadable(uintptr_t address, size_t size)')
readable=r'''static BOOL HFAXReadable(uintptr_t address, size_t size) {
    if(!address||!size)return NO;
    uint64_t end=(uint64_t)address+(uint64_t)size;
    uint32_t count=_dyld_image_count();
    for(uint32_t i=0;i<count;i++){
        const struct mach_header *mh0=_dyld_get_image_header(i);
        if(!mh0||mh0->magic!=MH_MAGIC_64)continue;
        const struct mach_header_64 *mh=(const struct mach_header_64 *)mh0;
        intptr_t slide=_dyld_get_image_vmaddr_slide(i);
        const uint8_t *cursor=(const uint8_t *)(mh+1),*limit=cursor+mh->sizeofcmds;
        for(uint32_t n=0;n<mh->ncmds;n++){
            if(cursor+sizeof(struct load_command)>limit)break;
            const struct load_command *lc=(const struct load_command *)cursor;
            if(lc->cmdsize<sizeof(*lc)||cursor+lc->cmdsize>limit)break;
            if(lc->cmd==LC_SEGMENT_64&&lc->cmdsize>=sizeof(struct segment_command_64)){
                const struct segment_command_64 *seg=(const struct segment_command_64 *)cursor;
                if(seg->initprot&VM_PROT_READ){
                    uint64_t start=(uint64_t)((int64_t)seg->vmaddr+(int64_t)slide);
                    uint64_t finish=start+seg->vmsize;
                    if((uint64_t)address>=start&&end<=finish)return YES;
                }
            }
            cursor+=lc->cmdsize;
        }
    }
    return NO;
}'''
c=c[:a]+readable+c[b:]
CROSS.write_text(c)

u=UI.read_text()
u=u.replace('HFAMap RuntimeAnalyzer v0.3.13.11 HybridIL2CPPRuntimeResolver','HFAMap RuntimeAnalyzer v0.3.13.12 CrossImageCallResolver')
UI.write_text(u)
print('v0.3.13.12 cross-image call resolver applied')

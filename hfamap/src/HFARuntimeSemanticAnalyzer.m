#import "HFARuntimeSemanticAnalyzer.h"

#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>

#include <string.h>

// This module intentionally fails closed. Every emitted semantic is evidence,
// not a request to patch bytes. Canonical patch promotion remains a separate
// stage owned by the main analyzer.

typedef struct {
    const struct mach_header_64 *header;
    uintptr_t base;
    intptr_t slide;
    uintptr_t textStart;
    uintptr_t textEnd;
    uintptr_t writableStart;
    uintptr_t writableEnd;
} HFASemImage;

static BOOL HFASemReadable(uintptr_t address, size_t size) {
    if (!address || !size || address + size < address) return NO;
    mach_vm_address_t region = (mach_vm_address_t)address;
    mach_vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &region, &regionSize,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &count, &object);
    return kr == KERN_SUCCESS && (info.protection & VM_PROT_READ) &&
           region <= address && address + size <= region + (uintptr_t)regionSize;
}

static BOOL HFASemImageForAddress(uintptr_t address, HFASemImage *out) {
    if (!address || !out) return NO;
    Dl_info di = {0};
    if (!dladdr((void *)address, &di) || !di.dli_fbase) return NO;
    const struct mach_header_64 *h = (const struct mach_header_64 *)di.dli_fbase;
    if (h->magic != MH_MAGIC_64) return NO;
    HFASemImage x = {0};
    x.header = h; x.base = (uintptr_t)h;
    const uint8_t *c = (const uint8_t *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)c;
        if (lc->cmdsize < sizeof(*lc)) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *g = (const struct segment_command_64 *)c;
            uintptr_t rs = x.base + (uintptr_t)g->vmaddr;
            // dladdr base is the runtime Mach-O header. For ordinary iOS dylibs
            // __TEXT vmaddr is zero; calculate slide explicitly for non-zero VMs.
            if (!strncmp(g->segname, SEG_TEXT, 16)) x.slide = (intptr_t)x.base - (intptr_t)g->vmaddr;
        }
        c += lc->cmdsize;
    }
    c = (const uint8_t *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)c;
        if (lc->cmdsize < sizeof(*lc)) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *g = (const struct segment_command_64 *)c;
            uintptr_t rs = (uintptr_t)((intptr_t)g->vmaddr + x.slide);
            uintptr_t re = rs + (uintptr_t)g->vmsize;
            if (g->initprot & VM_PROT_EXECUTE) {
                if (!x.textStart || rs < x.textStart) x.textStart = rs;
                if (re > x.textEnd) x.textEnd = re;
            }
            if (g->initprot & VM_PROT_WRITE) {
                if (!x.writableStart || rs < x.writableStart) x.writableStart = rs;
                if (re > x.writableEnd) x.writableEnd = re;
            }
        }
        c += lc->cmdsize;
    }
    if (!x.textStart || address < x.textStart || address >= x.textEnd) return NO;
    *out = x;
    return YES;
}

static BOOL HFASemWritable(uintptr_t address, HFASemImage image) {
    if (!address) return NO;
    // Fast path covers the common contiguous __DATA/__DATA_CONST envelope.
    if (image.writableStart && address >= image.writableStart && address < image.writableEnd) return YES;
    mach_vm_address_t region = (mach_vm_address_t)address;
    mach_vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    return mach_vm_region(mach_task_self(), &region, &regionSize, VM_REGION_BASIC_INFO_64,
                          (vm_region_info_t)&info, &count, &object) == KERN_SUCCESS &&
           (info.protection & VM_PROT_WRITE) != 0 && region <= address && address < region + regionSize;
}

static NSString *HFASemRVA(uintptr_t address, HFASemImage image) {
    return address >= image.base ? [NSString stringWithFormat:@"0x%llX", (unsigned long long)(address - image.base)] : @"";
}

static int64_t HFASemSignExtend(uint64_t value, unsigned bits) {
    uint64_t m = UINT64_C(1) << (bits - 1);
    return (int64_t)((value ^ m) - m);
}

static BOOL HFASemADRP(uint32_t w, uintptr_t pc, uintptr_t *value) {
    if ((w & 0x9F000000u) != 0x90000000u) return NO;
    uint64_t imm21 = ((uint64_t)((w >> 29) & 3u)) | ((uint64_t)((w >> 5) & 0x7FFFFu) << 2);
    int64_t imm = HFASemSignExtend(imm21, 21) << 12;
    if (value) *value = (uintptr_t)(((int64_t)(pc & ~(uintptr_t)0xFFF)) + imm);
    return YES;
}

static BOOL HFASemADR(uint32_t w, uintptr_t pc, uintptr_t *value) {
    if ((w & 0x9F000000u) != 0x10000000u) return NO;
    uint64_t imm21 = ((uint64_t)((w >> 29) & 3u)) | ((uint64_t)((w >> 5) & 0x7FFFFu) << 2);
    int64_t imm = HFASemSignExtend(imm21, 21);
    if (value) *value = (uintptr_t)((int64_t)pc + imm);
    return YES;
}

static BOOL HFASemAddImm64(uint32_t w, unsigned *rd, unsigned *rn, uint64_t *imm) {
    if ((w & 0xFF000000u) != 0x91000000u) return NO;
    if (rd) *rd = w & 31u;
    if (rn) *rn = (w >> 5) & 31u;
    uint64_t v = (w >> 10) & 0xFFFu;
    if ((w >> 22) & 1u) v <<= 12;
    if (imm) *imm = v;
    return YES;
}

static BOOL HFASemLdrX(uint32_t w, unsigned *rt, unsigned *rn, uint64_t *off) {
    if ((w & 0xFFC00000u) != 0xF9400000u) return NO;
    if (rt) *rt = w & 31u;
    if (rn) *rn = (w >> 5) & 31u;
    if (off) *off = ((w >> 10) & 0xFFFu) * 8u;
    return YES;
}

static BOOL HFASemStrX(uint32_t w, unsigned *rt, unsigned *rn, uint64_t *off) {
    if ((w & 0xFFC00000u) != 0xF9000000u) return NO;
    if (rt) *rt = w & 31u;
    if (rn) *rn = (w >> 5) & 31u;
    if (off) *off = ((w >> 10) & 0xFFFu) * 8u;
    return YES;
}

static BOOL HFASemMovReg(uint32_t w, unsigned *rd, unsigned *rm) {
    uint32_t p = w & 0xFFE0FFE0u;
    if (p != 0xAA0003E0u && p != 0x2A0003E0u) return NO;
    if (rd) *rd = w & 31u;
    if (rm) *rm = (w >> 16) & 31u;
    return YES;
}

static BOOL HFASemMovWide(uint32_t w, unsigned *rd, uint64_t *value, BOOL *is64) {
    uint32_t p = w & 0x7F800000u;
    if (p != 0x52800000u) return NO; // MOVZ W/X; sf is outside mask.
    unsigned r = w & 31u, sh = ((w >> 21) & 3u) * 16u;
    uint64_t v = ((uint64_t)((w >> 5) & 0xFFFFu)) << sh;
    if (rd) *rd = r; if (value) *value = v; if (is64) *is64 = (w & 0x80000000u) != 0;
    return YES;
}

static BOOL HFASemBTarget(uint32_t w, uintptr_t pc, uintptr_t *target) {
    if ((w & 0xFC000000u) != 0x14000000u) return NO;
    int64_t imm = HFASemSignExtend(w & 0x03FFFFFFu, 26) << 2;
    if (target) *target = (uintptr_t)((int64_t)pc + imm);
    return YES;
}

static BOOL HFASemConditional(uint32_t w) {
    return (w & 0xFF000010u) == 0x54000000u ||
           (w & 0x7E000000u) == 0x34000000u ||
           (w & 0x7E000000u) == 0x36000000u;
}

static BOOL HFASemRET(uint32_t w) { return (w & 0xFFFFFC1Fu) == 0xD65F0000u; }
static BOOL HFASemBR(uint32_t w, unsigned *rn) { if ((w & 0xFFFFFC1Fu) != 0xD61F0000u) return NO; if (rn) *rn=(w>>5)&31u; return YES; }
static BOOL HFASemBLR(uint32_t w, unsigned *rn) { if ((w & 0xFFFFFC1Fu) != 0xD63F0000u) return NO; if (rn) *rn=(w>>5)&31u; return YES; }

static BOOL HFASemMUL(uint32_t w, unsigned *rd, unsigned *rn, unsigned *rm) {
    uint32_t p = w & 0xFFE0FC00u;
    if (p != 0x1B007C00u && p != 0x9B007C00u) return NO;
    if (rd) *rd=w&31u; if (rn) *rn=(w>>5)&31u; if (rm) *rm=(w>>16)&31u; return YES;
}

static NSString *HFASemFPOp(uint32_t w, unsigned *rd, unsigned *rn, unsigned *rm) {
    uint32_t p = w & 0xFFE0FC00u;
    NSString *op = nil;
    if (p==0x1E200800u||p==0x1E600800u) op=@"FMUL";
    else if (p==0x1E201800u||p==0x1E601800u) op=@"FDIV";
    else if (p==0x1E203800u||p==0x1E603800u) op=@"FSUB";
    if (!op) return nil;
    if(rd)*rd=w&31u;if(rn)*rn=(w>>5)&31u;if(rm)*rm=(w>>16)&31u;return op;
}

static BOOL HFASemFCSEL(uint32_t w, unsigned *rd, unsigned *rn, unsigned *rm) {
    if ((w & 0xFF200C00u) != 0x1E200C00u) return NO;
    if(rd)*rd=w&31u;if(rn)*rn=(w>>5)&31u;if(rm)*rm=(w>>16)&31u;return YES;
}

static BOOL HFASemPathToRet(const uint32_t *words, NSUInteger count, uintptr_t start,
                            HFASemImage image, NSUInteger fromIndex) {
    NSUInteger i = fromIndex;
    for (NSUInteger step=0; step<20 && i<count; step++) {
        uint32_t w=words[i];
        if (HFASemRET(w)) return YES;
        uintptr_t t=0;
        if (HFASemBTarget(w,start+i*4,&t)) {
            if (t<start || t>=start+count*4 || ((t-start)&3u)) return NO;
            i=(NSUInteger)((t-start)/4); continue;
        }
        if (HFASemConditional(w) || ((w & 0xFC000000u)==0x94000000u)) return NO;
        i++;
    }
    (void)image;
    return NO;
}

NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacement(uintptr_t replacement, uintptr_t originalSlot) {
    HFASemImage image={0};
    if (!HFASemImageForAddress(replacement,&image)) return @{@"status":@"image-unavailable",@"semanticType":@"unknown-runtime"};
    NSUInteger count=MIN((NSUInteger)256,(NSUInteger)((image.textEnd-replacement)/4));
    const uint32_t *words=(const uint32_t *)replacement;
    uintptr_t addr[32]={0}; BOOL addrKnown[32]={0}; BOOL originalReg[32]={0};
    BOOL intReturnTaint[32]={0}; BOOL fpReturnTaint[32]={0};
    BOOL receiverTaint[32]={0}; uint32_t receiverOffset[32]={0}; receiverTaint[0]=YES;
    BOOL constKnown[32]={0}; uint64_t constValue[32]={0};
    BOOL conditional=NO,callsOriginal=NO,returnMul=NO,returnDiv=NO,returnSelect=NO,argMul=NO,argDiv=NO;
    NSMutableArray *constantReturns=[NSMutableArray array];
    NSMutableArray *captures=[NSMutableArray array];
    NSMutableArray *callbacks=[NSMutableArray array];
    NSMutableArray *ops=[NSMutableArray array];
    NSMutableSet *seenCapture=[NSMutableSet set];

    for(NSUInteger i=0;i<count;i++){
        uintptr_t pc=replacement+i*4;uint32_t w=words[i];
        if(HFASemConditional(w))conditional=YES;

        unsigned rd=0,rn=0,rm=0;uintptr_t av=0;uint64_t imm=0;BOOL i64=NO;
        if(HFASemADRP(w,pc,&av)||HFASemADR(w,pc,&av)){rd=w&31u;addr[rd]=av;addrKnown[rd]=YES;continue;}
        if(HFASemAddImm64(w,&rd,&rn,&imm)){if(addrKnown[rn]){addr[rd]=addr[rn]+imm;addrKnown[rd]=YES;}else addrKnown[rd]=NO;if(receiverTaint[rn]){receiverTaint[rd]=YES;receiverOffset[rd]=receiverOffset[rn]+(uint32_t)imm;}continue;}
        if(HFASemMovReg(w,&rd,&rm)){addrKnown[rd]=addrKnown[rm];addr[rd]=addr[rm];originalReg[rd]=originalReg[rm];receiverTaint[rd]=receiverTaint[rm];receiverOffset[rd]=receiverOffset[rm];intReturnTaint[rd]=intReturnTaint[rm];fpReturnTaint[rd]=fpReturnTaint[rm];constKnown[rd]=constKnown[rm];constValue[rd]=constValue[rm];continue;}
        if(HFASemMovWide(w,&rd,&imm,&i64)){constKnown[rd]=YES;constValue[rd]=imm;addrKnown[rd]=NO;receiverTaint[rd]=NO;intReturnTaint[rd]=NO;if(rd==0&&imm<=1&&HFASemPathToRet(words,count,replacement,image,i+1)){[constantReturns addObject:@{@"value":@(imm),@"sourceRVA":HFASemRVA(pc,image),@"path":@"branch-aware"}];}continue;}
        uint64_t off=0;
        if(HFASemLdrX(w,&rd,&rn,&off)){
            uintptr_t eff=addrKnown[rn]?addr[rn]+off:0;
            if(eff&&eff==originalSlot){originalReg[rd]=YES;addrKnown[rd]=NO;}
            else if(eff&&HFASemReadable(eff,sizeof(uintptr_t))){uintptr_t p=0;memcpy(&p,(void*)eff,sizeof(p));addr[rd]=p;addrKnown[rd]=p!=0;}
            else addrKnown[rd]=NO;
            if(receiverTaint[rn]){receiverTaint[rd]=YES;receiverOffset[rd]=receiverOffset[rn]+(uint32_t)off;}else receiverTaint[rd]=NO;
            continue;
        }
        if(HFASemStrX(w,&rd,&rn,&off)){
            uintptr_t dst=addrKnown[rn]?addr[rn]+off:0;
            if(dst&&dst!=originalSlot&&HFASemWritable(dst,image)&&receiverTaint[rd]){
                NSString *key=[NSString stringWithFormat:@"%u:%llX",receiverOffset[rd],(unsigned long long)(dst-image.base)];
                if(![seenCapture containsObject:key]){[seenCapture addObject:key];[captures addObject:@{@"source":receiverOffset[rd]?@"subobject":@"receiver",@"fieldOffset":[NSString stringWithFormat:@"0x%X",receiverOffset[rd]],@"storeRVA":HFASemRVA(dst,image)}];}
            }
            continue;
        }
        if(HFASemMUL(w,&rd,&rn,&rm)){
            BOOL ret=intReturnTaint[rn]||intReturnTaint[rm];
            BOOL arg=(rn<8||rm<8)&&!callsOriginal;
            intReturnTaint[rd]=ret;if(ret){returnMul=YES;[ops addObject:@{@"op":@"MUL",@"phase":@"after-original",@"rva":HFASemRVA(pc,image)}];}else if(arg){argMul=YES;[ops addObject:@{@"op":@"MUL",@"phase":@"before-original",@"rva":HFASemRVA(pc,image)}];}continue;
        }
        NSString *fp=HFASemFPOp(w,&rd,&rn,&rm);
        if(fp){BOOL ret=fpReturnTaint[rn]||fpReturnTaint[rm];BOOL arg=(rn<8||rm<8)&&!callsOriginal;fpReturnTaint[rd]=ret;if(ret){if([fp isEqual:@"FMUL"])returnMul=YES;if([fp isEqual:@"FDIV"])returnDiv=YES;[ops addObject:@{@"op":fp,@"phase":@"after-original",@"rva":HFASemRVA(pc,image)}];}else if(arg){if([fp isEqual:@"FMUL"])argMul=YES;if([fp isEqual:@"FDIV"])argDiv=YES;[ops addObject:@{@"op":fp,@"phase":@"before-original",@"rva":HFASemRVA(pc,image)}];}continue;}
        if(HFASemFCSEL(w,&rd,&rn,&rm)){BOOL ret=fpReturnTaint[rn]||fpReturnTaint[rm];fpReturnTaint[rd]=ret;if(ret){returnSelect=YES;[ops addObject:@{@"op":@"FCSEL",@"phase":@"after-original",@"rva":HFASemRVA(pc,image)}];}continue;}
        unsigned br=0;
        if(HFASemBLR(w,&br)){
            if(originalReg[br]){callsOriginal=YES;memset(intReturnTaint,0,sizeof(intReturnTaint));memset(fpReturnTaint,0,sizeof(fpReturnTaint));intReturnTaint[0]=YES;fpReturnTaint[0]=YES;[ops addObject:@{@"op":@"CALL_ORIGINAL",@"rva":HFASemRVA(pc,image)}];}
            else {NSMutableArray *a=[NSMutableArray array];for(unsigned r=0;r<8;r++)if(constKnown[r]&&constValue[r]<=1)[a addObject:@{@"index":@(r),@"value":@(constValue[r])}];if(a.count)[callbacks addObject:@{@"branchRegister":@(br),@"constantArguments":a,@"rva":HFASemRVA(pc,image)}];}
            continue;
        }
        if(HFASemBR(w,&br)){
            NSMutableArray *a=[NSMutableArray array];for(unsigned r=0;r<8;r++)if(constKnown[r]&&constValue[r]<=1)[a addObject:@{@"index":@(r),@"value":@(constValue[r])}];if(a.count)[callbacks addObject:@{@"branchRegister":@(br),@"constantArguments":a,@"rva":HFASemRVA(pc,image)}];continue;
        }
        if(HFASemRET(w)) break;
    }

    NSString *semantic=@"unknown-runtime";
    BOOL sub=NO,direct=NO;for(NSDictionary *c in captures){if([c[@"source"] isEqual:@"subobject"])sub=YES;else direct=YES;}
    if(constantReturns.count&&conditional)semantic=@"conditional-return";
    else if(callsOriginal&&returnMul)semantic=@"return-multiplier";
    else if(callsOriginal&&returnDiv)semantic=@"return-divider";
    else if(callsOriginal&&returnSelect)semantic=@"return-select";
    else if(argMul)semantic=@"argument-multiplier";
    else if(argDiv)semantic=@"argument-divider";
    else if(sub)semantic=@"subobject-receiver-capture";
    else if(direct)semantic=@"receiver-capture";
    else if(callbacks.count)semantic=@"callback-constant-argument";

    return @{
        @"status":@"ok",
        @"semanticType":semantic,
        @"boundedInstructionCount":@(count),
        @"hasConditionalBranch":@(conditional),
        @"callsOriginal":@(callsOriginal),
        @"constantReturns":constantReturns,
        @"receiverCaptures":captures,
        @"callbackEvidence":callbacks,
        @"operations":ops,
        @"staticOnly":@YES
    };
}

#pragma mark - IL2CPP owning-method / ABI enrichment

typedef void *(*HFADomainGetFn)(void);
typedef const void **(*HFADomainGetAssembliesFn)(const void *, size_t *);
typedef const void *(*HFAAssemblyGetImageFn)(const void *);
typedef const char *(*HFAImageGetNameFn)(const void *);
typedef size_t (*HFAImageGetClassCountFn)(const void *);
typedef void *(*HFAImageGetClassFn)(const void *, size_t);
typedef const char *(*HFAClassGetNameFn)(void *);
typedef const char *(*HFAClassGetNamespaceFn)(void *);
typedef const void *(*HFAClassGetMethodsFn)(void *, void **);
typedef const char *(*HFAMethodGetNameFn)(const void *);
typedef uint32_t (*HFAMethodGetParamCountFn)(const void *);
typedef void *(*HFAMethodGetPointerFn)(const void *);
typedef const void *(*HFAMethodGetReturnTypeFn)(const void *);
typedef const void *(*HFAMethodGetParamFn)(const void *, uint32_t);
typedef const char *(*HFAMethodGetParamNameFn)(const void *, uint32_t);
typedef bool (*HFAMethodBoolFn)(const void *);
typedef char *(*HFATypeGetNameFn)(const void *);
typedef void (*HFAFreeFn)(void *);

typedef struct {
    void *handle;
    uintptr_t execStart[16], execEnd[16]; unsigned execCount;
    HFADomainGetFn domainGet; HFADomainGetAssembliesFn domainGetAssemblies;
    HFAAssemblyGetImageFn assemblyGetImage; HFAImageGetNameFn imageGetName;
    HFAImageGetClassCountFn imageGetClassCount; HFAImageGetClassFn imageGetClass;
    HFAClassGetNameFn classGetName; HFAClassGetNamespaceFn classGetNamespace;
    HFAClassGetMethodsFn classGetMethods; HFAMethodGetNameFn methodGetName;
    HFAMethodGetParamCountFn methodGetParamCount; HFAMethodGetPointerFn methodGetPointer;
    HFAMethodGetReturnTypeFn methodGetReturnType; HFAMethodGetParamFn methodGetParam;
    HFAMethodGetParamNameFn methodGetParamName; HFAMethodBoolFn methodIsGeneric;
    HFAMethodBoolFn methodIsInflated; HFAMethodBoolFn methodIsInstance;
    HFATypeGetNameFn typeGetName; HFAFreeFn freeFn;
} HFAIL2Runtime;

static void *HFAIL2Sym(void *h,const char *n){void *p=h?dlsym(h,n):NULL;return p?:dlsym(RTLD_DEFAULT,n);}
static NSString *HFAIL2S(const char *s){return s?([NSString stringWithUTF8String:s]?:@""):@"";}
static BOOL HFAIL2Exec(HFAIL2Runtime *r,uintptr_t p){for(unsigned i=0;i<r->execCount;i++)if(p>=r->execStart[i]&&p<r->execEnd[i])return YES;return NO;}

static BOOL HFAIL2Load(HFAIL2Runtime *r){
    memset(r,0,sizeof(*r));const struct mach_header_64 *h=NULL;NSString *path=@"";
    for(uint32_t i=0;i<_dyld_image_count();i++){const char *cp=_dyld_get_image_name(i);if(!cp)continue;NSString *p=HFAIL2S(cp);if(![p.lastPathComponent isEqual:@"UnityFramework"])continue;h=(const struct mach_header_64*)_dyld_get_image_header(i);path=p;break;}
    if(!h||h->magic!=MH_MAGIC_64)return NO;intptr_t slide=0;const uint8_t *c=(const uint8_t*)(h+1);for(uint32_t i=0;i<h->ncmds;i++){const struct load_command *lc=(const struct load_command*)c;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *g=(const struct segment_command_64*)c;if(!strncmp(g->segname,SEG_TEXT,16)){slide=(intptr_t)h-(intptr_t)g->vmaddr;break;}}c+=lc->cmdsize;}
    c=(const uint8_t*)(h+1);for(uint32_t i=0;i<h->ncmds&&r->execCount<16;i++){const struct load_command *lc=(const struct load_command*)c;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *g=(const struct segment_command_64*)c;if(g->initprot&VM_PROT_EXECUTE){r->execStart[r->execCount]=(uintptr_t)((intptr_t)g->vmaddr+slide);r->execEnd[r->execCount]=r->execStart[r->execCount]+(uintptr_t)g->vmsize;r->execCount++;}}c+=lc->cmdsize;}
#ifdef RTLD_NOLOAD
    r->handle=dlopen(path.fileSystemRepresentation,RTLD_LAZY|RTLD_NOLOAD);
#else
    r->handle=dlopen(path.fileSystemRepresentation,RTLD_LAZY);
#endif
#define L(field,type,name) r->field=(type)HFAIL2Sym(r->handle,name)
    L(domainGet,HFADomainGetFn,"il2cpp_domain_get");L(domainGetAssemblies,HFADomainGetAssembliesFn,"il2cpp_domain_get_assemblies");L(assemblyGetImage,HFAAssemblyGetImageFn,"il2cpp_assembly_get_image");L(imageGetName,HFAImageGetNameFn,"il2cpp_image_get_name");L(imageGetClassCount,HFAImageGetClassCountFn,"il2cpp_image_get_class_count");L(imageGetClass,HFAImageGetClassFn,"il2cpp_image_get_class");L(classGetName,HFAClassGetNameFn,"il2cpp_class_get_name");L(classGetNamespace,HFAClassGetNamespaceFn,"il2cpp_class_get_namespace");L(classGetMethods,HFAClassGetMethodsFn,"il2cpp_class_get_methods");L(methodGetName,HFAMethodGetNameFn,"il2cpp_method_get_name");L(methodGetParamCount,HFAMethodGetParamCountFn,"il2cpp_method_get_param_count");L(methodGetPointer,HFAMethodGetPointerFn,"il2cpp_method_get_pointer");L(methodGetReturnType,HFAMethodGetReturnTypeFn,"il2cpp_method_get_return_type");L(methodGetParam,HFAMethodGetParamFn,"il2cpp_method_get_param");L(methodGetParamName,HFAMethodGetParamNameFn,"il2cpp_method_get_param_name");L(methodIsGeneric,HFAMethodBoolFn,"il2cpp_method_is_generic");L(methodIsInflated,HFAMethodBoolFn,"il2cpp_method_is_inflated");L(methodIsInstance,HFAMethodBoolFn,"il2cpp_method_is_instance");L(typeGetName,HFATypeGetNameFn,"il2cpp_type_get_name");L(freeFn,HFAFreeFn,"il2cpp_free");
#undef L
    return r->domainGet&&r->domainGetAssemblies&&r->assemblyGetImage&&r->imageGetName&&r->imageGetClassCount&&r->imageGetClass&&r->classGetName&&r->classGetNamespace&&r->classGetMethods&&r->methodGetName&&r->methodGetParamCount&&r->execCount;
}

static uintptr_t HFAIL2MethodPointer(HFAIL2Runtime *r,const void *m){if(r->methodGetPointer){uintptr_t p=(uintptr_t)r->methodGetPointer(m);if(HFAIL2Exec(r,p))return p;}uintptr_t q[2]={0};if(HFASemReadable((uintptr_t)m,sizeof(q)))memcpy(q,m,sizeof(q));for(unsigned i=0;i<2;i++)if(HFAIL2Exec(r,q[i]))return q[i];return 0;}
static NSString *HFAIL2TypeName(HFAIL2Runtime *r,const void *t){if(!t||!r->typeGetName)return @"?";char *raw=r->typeGetName(t);if(!raw)return @"?";NSString *s=HFAIL2S(raw);if(r->freeFn)r->freeFn(raw);return s.length?s:@"?";}
static NSString *HFAIL2Kind(NSString *n){NSString *s=n.lowercaseString;if([s containsString:@"boolean"]||[s isEqual:@"bool"])return @"bool";if([s containsString:@"single"]||[s isEqual:@"float"])return @"float32";if([s containsString:@"double"])return @"float64";if([s containsString:@"int64"]||[s isEqual:@"long"])return @"signed64";if([s containsString:@"uint64"]||[s isEqual:@"ulong"])return @"unsigned64";if([s containsString:@"int32"]||[s containsString:@"int16"]||[s containsString:@"sbyte"]||[s isEqual:@"int"])return @"signed32";if([s containsString:@"uint32"]||[s containsString:@"uint16"]||[s containsString:@"byte"]||[s isEqual:@"uint"])return @"unsigned32";if([s containsString:@"void"])return @"void";if([s hasSuffix:@"*"]||[s hasSuffix:@"&"]||[s containsString:@"intptr"])return @"pointer";return @"managed-or-complex";}

NSDictionary<NSString *, id> *HFAIL2CPPDescribeOwningMethod(uintptr_t target) {
    if(!target)return @{@"status":@"no-target"};HFAIL2Runtime r;if(!HFAIL2Load(&r))return @{@"status":@"runtime-api-unavailable"};
    void *domain=r.domainGet();size_t ac=0;const void **assemblies=domain?r.domainGetAssemblies(domain,&ac):NULL;if(!assemblies||!ac){if(r.handle)dlclose(r.handle);return @{@"status":@"no-assemblies"};}
    const void *bestMethod=NULL;uintptr_t bestPtr=0,upper=UINTPTR_MAX;NSString *ba=@"",*bn=@"",*bc=@"",*bm=@"";NSUInteger classes=0,methods=0;BOOL timed=NO;CFAbsoluteTime deadline=CFAbsoluteTimeGetCurrent()+1.75;
    for(size_t ai=0;ai<ac&&!timed;ai++){@autoreleasepool{const void *img=r.assemblyGetImage(assemblies[ai]);if(!img)continue;NSString *an=HFAIL2S(r.imageGetName(img));size_t cc=r.imageGetClassCount(img);for(size_t ci=0;ci<cc;ci++){if(++classes>12000||CFAbsoluteTimeGetCurrent()>deadline){timed=YES;break;}void *cl=r.imageGetClass(img,ci);if(!cl)continue;NSString *cn=HFAIL2S(r.classGetName(cl)),*ns=HFAIL2S(r.classGetNamespace(cl));void *it=NULL;const void *m=NULL;while((m=r.classGetMethods(cl,&it))){methods++;uintptr_t p=HFAIL2MethodPointer(&r,m);if(!p)continue;if(p<=target&&p>=bestPtr){bestPtr=p;bestMethod=m;ba=an;bn=ns;bc=cn;bm=HFAIL2S(r.methodGetName(m));}else if(p>target&&p<upper)upper=p;}}}}
    if(!bestMethod){if(r.handle)dlclose(r.handle);return @{@"status":timed?@"timeout-no-owner":@"not-found",@"classesScanned":@(classes),@"methodsScanned":@(methods)};}
    uint64_t delta=(uint64_t)(target-bestPtr);BOOL bounded=upper!=UINTPTR_MAX&&target<upper;NSMutableArray *params=[NSMutableArray array];uint32_t pc=r.methodGetParamCount(bestMethod);for(uint32_t i=0;i<pc;i++){const void *t=r.methodGetParam?r.methodGetParam(bestMethod,i):NULL;NSString *tn=HFAIL2TypeName(&r,t);NSString *pn=r.methodGetParamName?HFAIL2S(r.methodGetParamName(bestMethod,i)):@"";[params addObject:@{@"index":@(i),@"name":pn,@"type":tn,@"kind":HFAIL2Kind(tn)}];}
    NSString *rt=HFAIL2TypeName(&r,r.methodGetReturnType?r.methodGetReturnType(bestMethod):NULL);NSMutableArray *sig=[NSMutableArray array];for(NSDictionary *p in params)[sig addObject:p[@"type"]?:@"?"];NSString *classPath=bn.length?[NSString stringWithFormat:@"%@.%@",bn,bc]:bc;NSString *canonical=[NSString stringWithFormat:@"%@!%@::%@( %@ )",ba.length?ba:@"?",classPath.length?classPath:@"?",bm.length?bm:@"?",[sig componentsJoinedByString:@", "]];
    NSDictionary *result=@{@"status":bounded?@"bounded-owner":@"lower-bound-only",@"assembly":ba,@"namespace":bn,@"class":bc,@"method":bm,@"canonical":canonical,@"methodInfo":@((uintptr_t)bestMethod),@"methodRuntimeAddress":@(bestPtr),@"intraMethodOffset":@(delta),@"parameterCount":@(pc),@"parameters":params,@"return":@{@"type":rt,@"kind":HFAIL2Kind(rt)},@"instance":@(r.methodIsInstance?r.methodIsInstance(bestMethod):NO),@"generic":@(r.methodIsGeneric?r.methodIsGeneric(bestMethod):NO),@"inflated":@(r.methodIsInflated?r.methodIsInflated(bestMethod):NO),@"classesScanned":@(classes),@"methodsScanned":@(methods),@"timedOut":@(timed)};
    if(r.handle)dlclose(r.handle);return result;
}

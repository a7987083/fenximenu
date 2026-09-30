#import "HFAMapCrossImageResolver.h"
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t gCrossResolveCount;
static uint64_t gCrossResolvedCount;
static uint64_t gCrossBLRResolveCount;
static uint64_t gCrossBLRResolvedCount;

static int64_t HFAXSignExtend(uint64_t value, unsigned bits) {
    uint64_t sign=1ULL<<(bits-1); return (int64_t)((value^sign)-sign);
}

static NSString *HFAXBaseName(const char *path) {
    if(!path)return @"?"; const char *s=strrchr(path,'/');
    return [NSString stringWithUTF8String:s?s+1:path]?:@"?";
}

static NSDictionary *HFAXAddressInfo(uintptr_t address) {
    if(!address)return @{}; Dl_info d={0};
    if(!dladdr((void *)address,&d)||!d.dli_fbase||!d.dli_fname)return @{};
    uintptr_t base=(uintptr_t)d.dli_fbase;
    return @{ @"image":HFAXBaseName(d.dli_fname),
              @"rva":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(address-base)],
              @"address":[NSString stringWithFormat:@"0x%llX",(unsigned long long)address] };
}

static BOOL HFAXReadable(uintptr_t address, size_t size) {
    if(!address||!size)return NO;
    mach_vm_address_t region=(mach_vm_address_t)address; mach_vm_size_t regionSize=0;
    natural_t depth=0; vm_region_submap_info_data_64_t info={0};
    mach_msg_type_number_t count=VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr=mach_vm_region_recurse(mach_task_self(),&region,&regionSize,&depth,(vm_region_recurse_info_t)&info,&count);
    if(kr!=KERN_SUCCESS||!(info.protection&VM_PROT_READ))return NO;
    uint64_t end=(uint64_t)address+(uint64_t)size;
    return address>=(uintptr_t)region && end<=((uint64_t)region+(uint64_t)regionSize);
}

static BOOL HFAXRead32(uintptr_t address,uint32_t *out) {
    if(!out||!HFAXReadable(address,4))return NO; memcpy(out,(void *)address,4); return YES;
}
static BOOL HFAXRead64(uintptr_t address,uint64_t *out) {
    if(!out||!HFAXReadable(address,8))return NO; memcpy(out,(void *)address,8); return YES;
}

static BOOL HFAXDecodeADRP(uint32_t ins,uintptr_t pc,unsigned *rdOut,uintptr_t *pageOut) {
    if((ins&0x9F000000u)!=0x90000000u)return NO;
    unsigned rd=ins&31; uint64_t immlo=(ins>>29)&3, immhi=(ins>>5)&0x7FFFF;
    int64_t imm=HFAXSignExtend((immhi<<2)|immlo,21)<<12;
    uintptr_t page=(uintptr_t)((int64_t)(pc&~(uintptr_t)0xFFF)+imm);
    if(rdOut)*rdOut=rd; if(pageOut)*pageOut=page; return YES;
}

static BOOL HFAXDecodeADR(uint32_t ins,uintptr_t pc,unsigned *rdOut,uintptr_t *valueOut) {
    if((ins&0x9F000000u)!=0x10000000u)return NO;
    unsigned rd=ins&31; uint64_t immlo=(ins>>29)&3,immhi=(ins>>5)&0x7FFFF;
    int64_t imm=HFAXSignExtend((immhi<<2)|immlo,21);
    if(rdOut)*rdOut=rd; if(valueOut)*valueOut=(uintptr_t)((int64_t)pc+imm); return YES;
}

static BOOL HFAXDecodeAddImm(uint32_t ins,unsigned *rdOut,unsigned *rnOut,uint64_t *immOut) {
    if((ins&0xFF000000u)!=0x91000000u)return NO;
    unsigned rd=ins&31,rn=(ins>>5)&31; uint64_t imm=(ins>>10)&0xFFF; if((ins>>22)&1)imm<<=12;
    if(rdOut)*rdOut=rd;if(rnOut)*rnOut=rn;if(immOut)*immOut=imm;return YES;
}

static BOOL HFAXDecodeLDR64Unsigned(uint32_t ins,unsigned *rtOut,unsigned *rnOut,uint64_t *immOut) {
    if((ins&0xFFC00000u)!=0xF9400000u)return NO;
    unsigned rt=ins&31,rn=(ins>>5)&31; uint64_t imm=((ins>>10)&0xFFFULL)<<3;
    if(rtOut)*rtOut=rt;if(rnOut)*rnOut=rn;if(immOut)*immOut=imm;return YES;
}

static BOOL HFAXDecodeLDR64Literal(uint32_t ins,uintptr_t pc,unsigned *rtOut,uintptr_t *slotOut) {
    if((ins&0xFF000000u)!=0x58000000u)return NO;
    unsigned rt=ins&31; int64_t imm=HFAXSignExtend((ins>>5)&0x7FFFF,19)<<2;
    if(rtOut)*rtOut=rt;if(slotOut)*slotOut=(uintptr_t)((int64_t)pc+imm);return YES;
}

static BOOL HFAXDecodeBR(uint32_t ins,unsigned *rnOut) {
    if((ins&0xFFFFFC1Fu)!=0xD61F0000u)return NO;
    if(rnOut)*rnOut=(ins>>5)&31;return YES;
}

static BOOL HFAXDecodeB(uint32_t ins,uintptr_t pc,uintptr_t *targetOut) {
    if((ins&0xFC000000u)!=0x14000000u)return NO;
    int64_t d=HFAXSignExtend(ins&0x03FFFFFFu,26)<<2;
    if(targetOut)*targetOut=(uintptr_t)((int64_t)pc+d);return YES;
}

static NSDictionary *HFAXHop(NSString *type,uintptr_t from,uintptr_t to,uintptr_t slot) {
    NSMutableDictionary *d=[NSMutableDictionary dictionaryWithObjectsAndKeys:type?:@"?",@"type",HFAXAddressInfo(from),@"from",HFAXAddressInfo(to),@"to",nil];
    if(slot)d[@"pointerSlot"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)slot];
    return d;
}

NSDictionary *HFACrossImageResolveTarget(const void *target) {
    gCrossResolveCount++;
    uintptr_t original=(uintptr_t)target,cur=original;if(!cur)return nil;
    NSMutableArray *hops=[NSMutableArray array]; NSMutableSet *seen=[NSMutableSet set];
    for(unsigned depth=0;depth<8;depth++){
        NSString *key=[NSString stringWithFormat:@"%llX",(unsigned long long)cur]; if([seen containsObject:key])break;[seen addObject:key];
        uint32_t a=0,b=0,c=0,d=0;if(!HFAXRead32(cur,&a))break;HFAXRead32(cur+4,&b);HFAXRead32(cur+8,&c);HFAXRead32(cur+12,&d);
        uintptr_t next=0,slot=0;NSString *via=nil;
        if(HFAXDecodeB(a,cur,&next)){via=@"B";}
        else {
            unsigned ar=0;uintptr_t page=0;
            if(HFAXDecodeADRP(a,cur,&ar,&page)){
                unsigned rd=0,rn=0,br=0,rt=0;uint64_t imm=0;
                if(HFAXDecodeAddImm(b,&rd,&rn,&imm)&&rn==ar&&HFAXDecodeBR(c,&br)&&br==rd){next=page+imm;via=@"ADRP+ADD+BR";}
                else if(HFAXDecodeLDR64Unsigned(b,&rt,&rn,&imm)&&rn==ar&&HFAXDecodeBR(c,&br)&&br==rt){slot=page+imm;uint64_t p=0;if(HFAXRead64(slot,&p)){next=(uintptr_t)p;via=@"ADRP+LDR+BR";}}
                else if(HFAXDecodeAddImm(b,&rd,&rn,&imm)&&rn==ar){uintptr_t base=page+imm;unsigned rt2=0,rn2=0,br2=0;uint64_t imm2=0;if(HFAXDecodeLDR64Unsigned(c,&rt2,&rn2,&imm2)&&rn2==rd&&HFAXDecodeBR(d,&br2)&&br2==rt2){slot=base+imm2;uint64_t p=0;if(HFAXRead64(slot,&p)){next=(uintptr_t)p;via=@"ADRP+ADD+LDR+BR";}}}
            }
            if(!next){unsigned rt=0,br=0;uintptr_t lit=0;if(HFAXDecodeLDR64Literal(a,cur,&rt,&lit)&&HFAXDecodeBR(b,&br)&&br==rt){slot=lit;uint64_t p=0;if(HFAXRead64(slot,&p)){next=(uintptr_t)p;via=@"LDR-literal+BR";}}}
        }
        if(!next||next==cur)break;[hops addObject:HFAXHop(via,cur,next,slot)];cur=next;
    }
    if(cur==original||!hops.count)return nil;
    gCrossResolvedCount++;
    NSDictionary *oi=HFAXAddressInfo(original),*fi=HFAXAddressInfo(cur);
    return @{ @"resolved":@YES,@"original":oi?:@{},@"final":fi?:@{},@"finalAddressValue":@(cur),@"hops":hops,@"hopCount":@(hops.count),@"crossImage":@(![[oi objectForKey:@"image"] isEqual:[fi objectForKey:@"image"]]) };
}

static NSDictionary *HFAXResolveBLRPattern(uintptr_t start,unsigned off,unsigned targetReg) {
    if(off<4)return nil;
    uint32_t i1=0;if(!HFAXRead32(start+off-4,&i1))return nil;
    unsigned rt=0,rn=0;uint64_t imm=0;uintptr_t slot=0;
    if(HFAXDecodeLDR64Literal(i1,start+off-4,&rt,&slot)&&rt==targetReg){uint64_t p=0;if(HFAXRead64(slot,&p))return @{ @"via":@"LDR-literal+BLR",@"finalAddressValue":@((uintptr_t)p),@"pointerSlot":[NSString stringWithFormat:@"0x%llX",(unsigned long long)slot] };}
    if(HFAXDecodeLDR64Unsigned(i1,&rt,&rn,&imm)&&rt==targetReg){
        for(unsigned back=2;back<=5&&off>=back*4;back++){
            uint32_t x=0;if(!HFAXRead32(start+off-back*4,&x))continue;unsigned ar=0;uintptr_t page=0;
            if(HFAXDecodeADRP(x,start+off-back*4,&ar,&page)&&ar==rn){slot=page+imm;uint64_t p=0;if(HFAXRead64(slot,&p))return @{ @"via":@"ADRP+LDR+BLR",@"finalAddressValue":@((uintptr_t)p),@"pointerSlot":[NSString stringWithFormat:@"0x%llX",(unsigned long long)slot] };}
            unsigned rd=0,base=0;uint64_t add=0;if(HFAXDecodeAddImm(x,&rd,&base,&add)&&rd==rn&&base==rn&&back<5&&off>=(back+1)*4){uint32_t y=0;unsigned ar2=0;uintptr_t page2=0;if(HFAXRead32(start+off-(back+1)*4,&y)&&HFAXDecodeADRP(y,start+off-(back+1)*4,&ar2,&page2)&&ar2==rn){slot=page2+add+imm;uint64_t p=0;if(HFAXRead64(slot,&p))return @{ @"via":@"ADRP+ADD+LDR+BLR",@"finalAddressValue":@((uintptr_t)p),@"pointerSlot":[NSString stringWithFormat:@"0x%llX",(unsigned long long)slot] };}}
        }
    }
    unsigned rd=0,base=0;uint64_t add=0;if(HFAXDecodeAddImm(i1,&rd,&base,&add)&&rd==targetReg&&base==targetReg&&off>=8){uint32_t i2=0;unsigned ar=0;uintptr_t page=0;if(HFAXRead32(start+off-8,&i2)&&HFAXDecodeADRP(i2,start+off-8,&ar,&page)&&ar==targetReg)return @{ @"via":@"ADRP+ADD+BLR",@"finalAddressValue":@(page+add) };}
    return nil;
}

NSDictionary *HFACrossImageResolveBLRCallsite(const void *functionStart,unsigned callsiteOffset,unsigned targetRegister) {
    gCrossBLRResolveCount++;uintptr_t start=(uintptr_t)functionStart;if(!start||targetRegister>31)return nil;
    NSDictionary *p=HFAXResolveBLRPattern(start,callsiteOffset,targetRegister);if(!p)return nil;
    uintptr_t raw=(uintptr_t)[p[@"finalAddressValue"] unsignedLongLongValue];if(!raw)return nil;
    NSDictionary *chain=HFACrossImageResolveTarget((void *)raw);uintptr_t final=chain?(uintptr_t)[chain[@"finalAddressValue"] unsignedLongLongValue]:raw;
    gCrossBLRResolvedCount++;
    NSMutableDictionary *out=[NSMutableDictionary dictionaryWithDictionary:p];out[@"resolved"]=@YES;out[@"callsiteRVA"]=[NSString stringWithFormat:@"0x%X",callsiteOffset];out[@"targetRegister"]=@(targetRegister);out[@"rawTarget"]=HFAXAddressInfo(raw);out[@"final"]=HFAXAddressInfo(final);out[@"finalAddressValue"]=@(final);if(chain)out[@"trampoline"]=chain;
    return out;
}

NSDictionary *HFACrossImageResolverStatus(void) {
    return @{ @"resolveCount":@(gCrossResolveCount),@"resolvedCount":@(gCrossResolvedCount),@"blrResolveCount":@(gCrossBLRResolveCount),@"blrResolvedCount":@(gCrossBLRResolvedCount),@"analysisOnly":@YES };
}

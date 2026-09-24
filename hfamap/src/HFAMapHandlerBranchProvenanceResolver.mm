#import "HFAMapHandlerBranchProvenanceResolver.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static const NSUInteger kHFABPMaxInstructions = 1536;
static const NSUInteger kHFABPMaxBlocks = 64;
static const NSUInteger kHFABPMaxDepth = 10;
static const NSUInteger kHFABPMaxPerBlock = 96;
static const NSUInteger kHFABPMaxCalls = 96;
static const NSUInteger kHFABPMaxBranches = 128;

typedef NS_ENUM(uint8_t, HFABPKind) {
    HFABPUnknown = 0,
    HFABPEntryTarget,
    HFABPEntrySelector,
    HFABPEntrySender,
    HFABPImmediate,
    HFABPAddress,
    HFABPLoadedPointer,
    HFABPCallResult,
};

typedef struct {
    HFABPKind kind;
    uint64_t value;
    uint64_t originRVA;
    uint64_t sourceRVA;
} HFABPReg;

typedef struct {
    BOOL valid;
    NSString *kind;
    HFABPReg lhs;
    HFABPReg rhs;
    BOOL rhsImmediate;
    uint64_t immediate;
    uint64_t sourceRVA;
} HFABPCondition;

static int64_t HFABPSignExtend(uint64_t v, unsigned bits) {
    uint64_t s = 1ULL << (bits - 1);
    return (int64_t)((v ^ s) - s);
}
static HFABPReg HFABPUnknownReg(uint64_t rva) { return { HFABPUnknown, 0, rva, rva }; }
static HFABPReg HFABPConcrete(HFABPKind kind, uint64_t value, uint64_t rva) { return { kind, value, rva, rva }; }
static BOOL HFABPConcreteValue(HFABPReg r) {
    return r.kind == HFABPEntryTarget || r.kind == HFABPEntrySelector || r.kind == HFABPEntrySender ||
           r.kind == HFABPImmediate || r.kind == HFABPAddress || r.kind == HFABPLoadedPointer;
}
static NSString *HFABPKindName(HFABPKind k) {
    switch (k) {
        case HFABPEntryTarget: return @"entry-target";
        case HFABPEntrySelector: return @"entry-selector";
        case HFABPEntrySender: return @"entry-sender";
        case HFABPImmediate: return @"immediate";
        case HFABPAddress: return @"address";
        case HFABPLoadedPointer: return @"loaded-pointer";
        case HFABPCallResult: return @"call-result";
        default: return @"unknown";
    }
}
static NSDictionary *HFABPRegEvidence(HFABPReg r) {
    if (r.kind == HFABPUnknown) return @{};
    NSMutableDictionary *d = [@{ @"kind": HFABPKindName(r.kind),
                                  @"originRVA": @(r.originRVA),
                                  @"sourceRVA": @(r.sourceRVA) } mutableCopy];
    if (HFABPConcreteValue(r)) {
        d[@"value"] = @(r.value);
        d[@"valueHex"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)r.value];
    }
    d[@"entryDerived"] = @((r.kind == HFABPEntryTarget || r.kind == HFABPEntrySelector || r.kind == HFABPEntrySender) || r.originRVA == 0);
    return [d autorelease];
}
static NSData *HFABPRegsData(HFABPReg regs[31]) { return [NSData dataWithBytes:regs length:sizeof(HFABPReg)*31]; }
static void HFABPRestoreRegs(NSData *d, HFABPReg regs[31]) {
    memset(regs, 0, sizeof(HFABPReg)*31);
    if (d.length == sizeof(HFABPReg)*31) memcpy(regs, d.bytes, sizeof(HFABPReg)*31);
}
static uint64_t HFABPTarget26(uint64_t pc, uint32_t i) { return (uint64_t)((int64_t)pc + (HFABPSignExtend(i & 0x03ffffffU,26)<<2)); }
static uint64_t HFABPTarget19(uint64_t pc, uint32_t i) { return (uint64_t)((int64_t)pc + (HFABPSignExtend((i>>5)&0x7ffffU,19)<<2)); }
static uint64_t HFABPTarget14(uint64_t pc, uint32_t i) { return (uint64_t)((int64_t)pc + (HFABPSignExtend((i>>5)&0x3fffU,14)<<2)); }
static BOOL HFABPReadPointer(uint64_t addr, uint64_t *out) {
    if (!addr || !out) return NO;
    vm_size_t copied = 0; uint64_t value = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)addr, sizeof(value), (vm_address_t)&value, &copied) != KERN_SUCCESS || copied != sizeof(value)) return NO;
    *out = value; return YES;
}
static BOOL HFABPSameImage(uint64_t address, const void *base) {
    if (!address || !base) return NO;
    Dl_info info = {}; return dladdr((const void *)(uintptr_t)address, &info) && info.dli_fbase == base;
}
static NSDictionary *HFABPTargetContext(uint64_t target, uint64_t base) {
    NSMutableDictionary *d = [@{ @"runtimeVA": @(target),
                                  @"runtimeVAHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)target],
                                  @"sameImageRVA": target >= base ? @(target-base) : @0 } mutableCopy];
    Dl_info info = {};
    if (dladdr((const void *)(uintptr_t)target, &info)) {
        if (info.dli_fname) { NSString *p=[NSString stringWithUTF8String:info.dli_fname]?:@""; d[@"image"]=p.lastPathComponent?:@""; d[@"path"]=p; }
        if (info.dli_sname) d[@"symbol"]=[NSString stringWithUTF8String:info.dli_sname]?:@"";
        if (info.dli_fbase) d[@"offsetFromLoadBase"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(target-(uint64_t)(uintptr_t)info.dli_fbase)];
    }
    return [d autorelease];
}
static NSDictionary *HFABPConditionEvidence(HFABPCondition c) {
    if (!c.valid) return @{};
    NSMutableDictionary *d=[@{ @"kind": c.kind?:@"condition", @"sourceRVA": @(c.sourceRVA), @"lhs": HFABPRegEvidence(c.lhs) } mutableCopy];
    if (c.rhsImmediate) { d[@"rhsImmediate"]=@(c.immediate); d[@"rhsImmediateHex"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)c.immediate]; }
    else d[@"rhs"]=HFABPRegEvidence(c.rhs);
    return [d autorelease];
}
static void HFABPEnqueue(NSMutableArray *q, NSMutableSet *scheduled, uint64_t pc, NSUInteger depth,
                         HFABPReg regs[31], HFABPCondition condition, const void *imageBase) {
    if (!pc || depth > kHFABPMaxDepth || q.count >= kHFABPMaxBlocks || !HFABPSameImage(pc,imageBase)) return;
    NSNumber *k=@(pc); if ([scheduled containsObject:k]) return; [scheduled addObject:k];
    NSDictionary *cond=@{ @"valid":@(condition.valid), @"kind":condition.kind?:@"", @"lhs":[NSData dataWithBytes:&condition.lhs length:sizeof(HFABPReg)],
                          @"rhs":[NSData dataWithBytes:&condition.rhs length:sizeof(HFABPReg)], @"rhsImmediate":@(condition.rhsImmediate),
                          @"immediate":@(condition.immediate), @"sourceRVA":@(condition.sourceRVA) };
    [q addObject:@{ @"pc":k, @"depth":@(depth), @"regs":HFABPRegsData(regs), @"condition":cond }];
}
static HFABPCondition HFABPConditionFromDictionary(NSDictionary *d) {
    HFABPCondition c={}; c.valid=[d[@"valid"] boolValue]; c.kind=d[@"kind"];
    NSData *lhs=d[@"lhs"], *rhs=d[@"rhs"]; if (lhs.length==sizeof(HFABPReg)) memcpy(&c.lhs,lhs.bytes,sizeof(HFABPReg)); if (rhs.length==sizeof(HFABPReg)) memcpy(&c.rhs,rhs.bytes,sizeof(HFABPReg));
    c.rhsImmediate=[d[@"rhsImmediate"] boolValue]; c.immediate=[d[@"immediate"] unsignedLongLongValue]; c.sourceRVA=[d[@"sourceRVA"] unsignedLongLongValue]; return c;
}
static BOOL HFABPApply(uint32_t insn, uint64_t pc, uint64_t base, HFABPReg regs[31], HFABPCondition *condition) {
    uint64_t rva=pc-base;
    if ((insn & 0x9f000000U)==0x90000000U) {
        unsigned rd=insn&31U; int64_t imm=HFABPSignExtend(((((uint64_t)insn>>5)&0x7ffffULL)<<2)|((insn>>29)&3U),21)<<12;
        if (rd<31) regs[rd]=HFABPConcrete(HFABPAddress,(pc&~0xfffULL)+imm,rva); return YES;
    }
    if ((insn & 0x9f000000U)==0x10000000U) {
        unsigned rd=insn&31U; int64_t imm=HFABPSignExtend(((((uint64_t)insn>>5)&0x7ffffULL)<<2)|((insn>>29)&3U),21);
        if (rd<31) regs[rd]=HFABPConcrete(HFABPAddress,pc+imm,rva); return YES;
    }
    if ((insn & 0xffe0ffe0U)==0xaa0003e0U) {
        unsigned rd=insn&31U, rm=(insn>>16)&31U; if (rd<31&&rm<31) { regs[rd]=regs[rm]; regs[rd].sourceRVA=rva; } return YES;
    }
    if ((insn & 0xffc00000U)==0x91000000U) {
        unsigned rd=insn&31U,rn=(insn>>5)&31U; uint64_t imm=(insn>>10)&0xfffU; if (insn&(1U<<22)) imm<<=12;
        if (rd<31&&rn<31&&HFABPConcreteValue(regs[rn])) { HFABPReg n=regs[rn]; n.value+=imm; n.sourceRVA=rva; regs[rd]=n; } return YES;
    }
    if ((insn & 0xff800000U)==0xd2800000U) { unsigned rd=insn&31U; uint64_t imm=((insn>>5)&0xffffU)<<(((insn>>21)&3U)*16U); if (rd<31) regs[rd]=HFABPConcrete(HFABPImmediate,imm,rva); return YES; }
    if ((insn & 0xffc00000U)==0xf9400000U) {
        unsigned rt=insn&31U,rn=(insn>>5)&31U; uint64_t imm=((insn>>10)&0xfffU)<<3; if (rt<31&&rn<31&&HFABPConcreteValue(regs[rn])) { uint64_t v=0; if(HFABPReadPointer(regs[rn].value+imm,&v)) { HFABPReg n=HFABPConcrete(HFABPLoadedPointer,v,rva); n.originRVA=regs[rn].originRVA; regs[rt]=n; } } return YES;
    }
    if ((insn & 0xff00001fU)==0xf100001fU) {
        unsigned rn=(insn>>5)&31U; uint64_t imm=(insn>>10)&0xfffU; if(insn&(1U<<22)) imm<<=12;
        if(condition){condition->valid=rn<31;condition->kind=@"cmp-immediate";condition->lhs=rn<31?regs[rn]:HFABPUnknownReg(rva);condition->rhs=HFABPUnknownReg(rva);condition->rhsImmediate=YES;condition->immediate=imm;condition->sourceRVA=rva;} return YES;
    }
    if ((insn & 0xffe0fc1fU)==0xeb00001fU) {
        unsigned rn=(insn>>5)&31U,rm=(insn>>16)&31U; if(condition){condition->valid=rn<31&&rm<31;condition->kind=@"cmp-register";condition->lhs=rn<31?regs[rn]:HFABPUnknownReg(rva);condition->rhs=rm<31?regs[rm]:HFABPUnknownReg(rva);condition->rhsImmediate=NO;condition->immediate=0;condition->sourceRVA=rva;} return YES;
    }
    return NO;
}

NSDictionary *HFAMapResolveHandlerBranchProvenance(const void *implementation, NSString *implementationPath, NSDictionary *entryContext) {
    if (!implementation || !implementationPath.length) return @{ @"schema":@"com.hfa.handler-branch-provenance/v1", @"status":@"missing-input", @"analysisOnly":@YES };
    Dl_info info={}; if(!dladdr(implementation,&info)||!info.dli_fbase) return @{ @"schema":@"com.hfa.handler-branch-provenance/v1", @"status":@"dladdr-failed", @"analysisOnly":@YES };
    uint64_t base=(uint64_t)(uintptr_t)info.dli_fbase, start=(uint64_t)(uintptr_t)implementation;
    HFABPReg initial[31]={};
    uint64_t target=strtoull([entryContext[@"targetToken"] UTF8String]?:"0",NULL,0);
    uint64_t sender=strtoull([entryContext[@"senderToken"] UTF8String]?:"0",NULL,0);
    NSString *selectorName=entryContext[@"selector"]?:@""; SEL selector=selectorName.length?NSSelectorFromString(selectorName):NULL;
    if(target) initial[0]=HFABPConcrete(HFABPEntryTarget,target,0);
    if(selector) initial[1]=HFABPConcrete(HFABPEntrySelector,(uint64_t)(uintptr_t)selector,0);
    if(sender) initial[2]=HFABPConcrete(HFABPEntrySender,sender,0);
    NSMutableArray *queue=[NSMutableArray array],*calls=[NSMutableArray array],*branches=[NSMutableArray array],*blocks=[NSMutableArray array]; NSMutableSet *scheduled=[NSMutableSet set],*visited=[NSMutableSet set];
    HFABPCondition c0={}; HFABPEnqueue(queue,scheduled,start,0,initial,c0,info.dli_fbase);
    NSUInteger decoded=0;
    while(queue.count&&blocks.count<kHFABPMaxBlocks&&decoded<kHFABPMaxInstructions){
        NSDictionary *item=[[queue objectAtIndex:0] retain];[queue removeObjectAtIndex:0]; uint64_t bs=[item[@"pc"] unsignedLongLongValue]; if([visited containsObject:@(bs)]){[item release];continue;}[visited addObject:@(bs)]; NSUInteger depth=[item[@"depth"] unsignedIntegerValue]; HFABPReg regs[31]={}; HFABPRestoreRegs(item[@"regs"],regs); HFABPCondition cond=HFABPConditionFromDictionary(item[@"condition"]); [blocks addObject:@{ @"startRVA":@(bs-base), @"depth":@(depth)}]; [item release];
        for(NSUInteger idx=0;idx<kHFABPMaxPerBlock&&decoded<kHFABPMaxInstructions;++idx){ uint64_t pc=bs+idx*4ULL; if(!HFABPSameImage(pc,info.dli_fbase))break; uint32_t insn=0;vm_size_t copied=0;if(vm_read_overwrite(mach_task_self(),(vm_address_t)pc,sizeof(insn),(vm_address_t)&insn,&copied)!=KERN_SUCCESS||copied!=sizeof(insn))break;++decoded;uint64_t rva=pc-base;
            if(HFABPApply(insn,pc,base,regs,&cond))continue;
            if((insn&0xfc000000U)==0x94000000U){uint64_t t=HFABPTarget26(pc,insn);NSMutableDictionary *args=[NSMutableDictionary dictionary];for(unsigned r=0;r<=7;++r){NSDictionary *e=HFABPRegEvidence(regs[r]);if(e.count)args[[NSString stringWithFormat:@"x%u",r]]=e;}if(calls.count<kHFABPMaxCalls)[calls addObject:@{ @"kind":@"bl-direct",@"callsiteRVA":@(rva),@"target":HFABPTargetContext(t,base),@"arguments":args,@"entryDerivedArgumentCount":@([[args allValues] filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDictionary *e,__unused NSDictionary *b){return [e[@"entryDerived"] boolValue];}]].count)}];HFABPEnqueue(queue,scheduled,t,depth+1,regs,cond,info.dli_fbase);for(unsigned r=0;r<=18;++r)regs[r]=HFABPUnknownReg(rva);regs[0].kind=HFABPCallResult;regs[0].originRVA=rva;regs[0].sourceRVA=rva;cond.valid=NO;continue;}
            if((insn&0x7e000000U)==0x34000000U){uint64_t t=HFABPTarget19(pc,insn);unsigned rt=insn&31U;BOOL nz=(insn&0x01000000U)!=0;NSDictionary *test=rt<31?HFABPRegEvidence(regs[rt]):@{};if(branches.count<kHFABPMaxBranches)[branches addObject:@{ @"kind":nz?@"cbnz":@"cbz",@"fromRVA":@(rva),@"targetRVA":@(t-base),@"testedRegister":[NSString stringWithFormat:@"x%u",rt],@"testedValue":test,@"entryDerived":@([test[@"entryDerived"] boolValue])}];HFABPEnqueue(queue,scheduled,t,depth+1,regs,cond,info.dli_fbase);HFABPEnqueue(queue,scheduled,pc+4,depth+1,regs,cond,info.dli_fbase);break;}
            if((insn&0x7e000000U)==0x36000000U){uint64_t t=HFABPTarget14(pc,insn);unsigned rt=insn&31U;unsigned bit=((insn>>19)&0x1fU)|((insn>>26)&0x20U);BOOL nz=(insn&0x01000000U)!=0;NSDictionary *test=rt<31?HFABPRegEvidence(regs[rt]):@{};if(branches.count<kHFABPMaxBranches)[branches addObject:@{ @"kind":nz?@"tbnz":@"tbz",@"fromRVA":@(rva),@"targetRVA":@(t-base),@"testedBit":@(bit),@"testedRegister":[NSString stringWithFormat:@"x%u",rt],@"testedValue":test,@"entryDerived":@([test[@"entryDerived"] boolValue])}];HFABPEnqueue(queue,scheduled,t,depth+1,regs,cond,info.dli_fbase);HFABPEnqueue(queue,scheduled,pc+4,depth+1,regs,cond,info.dli_fbase);break;}
            if((insn&0xff000010U)==0x54000000U){uint64_t t=HFABPTarget19(pc,insn);NSDictionary *ce=HFABPConditionEvidence(cond);if(branches.count<kHFABPMaxBranches)[branches addObject:@{ @"kind":@"b-cond",@"condition":@((insn&0xfU)),@"fromRVA":@(rva),@"targetRVA":@(t-base),@"conditionProvenance":ce,@"entryDerived":@([ce[@"lhs"][@"entryDerived"] boolValue]||[ce[@"rhs"][@"entryDerived"] boolValue])}];HFABPEnqueue(queue,scheduled,t,depth+1,regs,cond,info.dli_fbase);HFABPEnqueue(queue,scheduled,pc+4,depth+1,regs,cond,info.dli_fbase);break;}
            if((insn&0xfc000000U)==0x14000000U){uint64_t t=HFABPTarget26(pc,insn);HFABPEnqueue(queue,scheduled,t,depth+1,regs,cond,info.dli_fbase);break;}
            if((insn&0xfffffc1fU)==0xd65f0000U)break;
        }
    }
    NSUInteger entryBranches=0,entryCalls=0;for(NSDictionary *b in branches)if([b[@"entryDerived"] boolValue])++entryBranches;for(NSDictionary *c in calls)if([c[@"entryDerivedArgumentCount"] unsignedIntegerValue])++entryCalls;
    return @{ @"schema":@"com.hfa.handler-branch-provenance/v1",@"status":decoded?@"cfg-decoded":@"no-readable-code",@"implementationRVA":@(start-base),@"decodedInstructionCount":@(decoded),@"blockCount":@(blocks.count),@"entryContext":entryContext?:@{},@"entryABI":@{ @"x0":@"target/self",@"x1":@"_cmd",@"x2":@"sender/control" },@"entryDerivedBranchCount":@(entryBranches),@"entryDerivedCallCount":@(entryCalls),@"branches":branches,@"calls":calls,@"blocks":blocks,@"analysisOnly":@YES,@"canonicalEligible":@NO,@"safety":@{ @"actionInvoked":@NO,@"selectorInvoked":@NO,@"memoryWritten":@NO,@"hookInstalled":@NO } };
}

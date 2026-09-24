#import "HFAMapSenderDerivedProvenanceResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const NSUInteger kHFASDMaxInstructions = 2048;
static const NSUInteger kHFASDMaxBlocks = 96;
static const NSUInteger kHFASDMaxDepth = 12;
static const NSUInteger kHFASDMaxPerBlock = 96;
static const NSUInteger kHFASDMaxCalls = 128;
static const NSUInteger kHFASDMaxBranches = 192;
static const NSUInteger kHFASDMaxStackSlots = 64;

typedef NS_ENUM(uint8_t, HFASDRoot) {
    HFASDRootNone = 0,
    HFASDRootTarget,
    HFASDRootSelector,
    HFASDRootSender,
};

typedef NS_ENUM(uint8_t, HFASDKind) {
    HFASDUnknown = 0,
    HFASDEntry,
    HFASDImmediate,
    HFASDAddress,
    HFASDFieldLoad,
    HFASDCallResult,
};

typedef NS_ENUM(uint8_t, HFASDConfidence) {
    HFASDConfidenceNone = 0,
    HFASDConfidenceDirect,
    HFASDConfidenceDerived,
    HFASDConfidenceCandidate,
};

typedef struct {
    HFASDKind kind;
    HFASDRoot root;
    HFASDConfidence confidence;
    uint64_t value;
    uint64_t originRVA;
    uint64_t sourceRVA;
    int64_t fieldOffset;
} HFASDReg;

typedef struct {
    BOOL valid;
    HFASDReg lhs;
    HFASDReg rhs;
    BOOL rhsImmediate;
    uint64_t immediate;
    uint64_t sourceRVA;
    uint8_t kind;
} HFASDCondition;

static int64_t HFASDSignExtend(uint64_t v, unsigned bits) {
    uint64_t s = 1ULL << (bits - 1);
    return (int64_t)((v ^ s) - s);
}
static HFASDReg HFASDUnknownReg(uint64_t rva) { return { HFASDUnknown, HFASDRootNone, HFASDConfidenceNone, 0, rva, rva, 0 }; }
static HFASDReg HFASDEntryReg(HFASDRoot root, uint64_t value) { return { HFASDEntry, root, HFASDConfidenceDirect, value, 0, 0, 0 }; }
static HFASDReg HFASDConcrete(HFASDKind kind, uint64_t value, uint64_t rva) { return { kind, HFASDRootNone, HFASDConfidenceNone, value, rva, rva, 0 }; }
static BOOL HFASDHasValue(HFASDReg r) { return r.kind != HFASDUnknown && r.kind != HFASDCallResult; }
static BOOL HFASDSenderDerived(HFASDReg r) { return r.root == HFASDRootSender; }
static NSString *HFASDRootName(HFASDRoot r) {
    if (r == HFASDRootTarget) return @"entry-target";
    if (r == HFASDRootSelector) return @"entry-selector";
    if (r == HFASDRootSender) return @"entry-sender";
    return @"none";
}
static NSString *HFASDKindName(HFASDKind k) {
    switch (k) {
        case HFASDEntry: return @"entry";
        case HFASDImmediate: return @"immediate";
        case HFASDAddress: return @"address";
        case HFASDFieldLoad: return @"field-load";
        case HFASDCallResult: return @"call-result";
        default: return @"unknown";
    }
}
static NSString *HFASDConfidenceName(HFASDConfidence c) {
    if (c == HFASDConfidenceDirect) return @"direct";
    if (c == HFASDConfidenceDerived) return @"derived";
    if (c == HFASDConfidenceCandidate) return @"candidate";
    return @"none";
}
static NSDictionary *HFASDRegEvidence(HFASDReg r) {
    if (r.kind == HFASDUnknown) return @{};
    NSMutableDictionary *d = [@{ @"kind": HFASDKindName(r.kind),
                                  @"root": HFASDRootName(r.root),
                                  @"confidence": HFASDConfidenceName(r.confidence),
                                  @"sourceRVA": @(r.sourceRVA),
                                  @"originRVA": @(r.originRVA),
                                  @"senderDerived": @(HFASDSenderDerived(r)) } mutableCopy];
    if (HFASDHasValue(r)) {
        d[@"value"] = @(r.value);
        d[@"valueHex"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)r.value];
    }
    if (r.fieldOffset) {
        d[@"fieldOffset"] = @(r.fieldOffset);
        d[@"fieldOffsetHex"] = [NSString stringWithFormat:@"%+lld", (long long)r.fieldOffset];
    }
    return [d autorelease];
}
static NSData *HFASDRegsData(HFASDReg regs[31]) { return [NSData dataWithBytes:regs length:sizeof(HFASDReg)*31U]; }
static void HFASDRestoreRegs(NSData *d, HFASDReg regs[31]) {
    memset(regs, 0, sizeof(HFASDReg)*31U);
    if (d.length == sizeof(HFASDReg)*31U) memcpy(regs, d.bytes, sizeof(HFASDReg)*31U);
}
static NSData *HFASDConditionData(HFASDCondition c) { return [NSData dataWithBytes:&c length:sizeof(c)]; }
static HFASDCondition HFASDConditionFromData(NSData *d) { HFASDCondition c={}; if (d.length==sizeof(c)) memcpy(&c,d.bytes,sizeof(c)); return c; }

static uint64_t HFASDTarget26(uint64_t pc, uint32_t i) { return (uint64_t)((int64_t)pc + (HFASDSignExtend(i & 0x03ffffffU,26)<<2)); }
static uint64_t HFASDTarget19(uint64_t pc, uint32_t i) { return (uint64_t)((int64_t)pc + (HFASDSignExtend((i>>5)&0x7ffffU,19)<<2)); }
static uint64_t HFASDTarget14(uint64_t pc, uint32_t i) { return (uint64_t)((int64_t)pc + (HFASDSignExtend((i>>5)&0x3fffU,14)<<2)); }
static BOOL HFASDSameImage(uint64_t address, const void *base) { Dl_info info={}; return address && base && dladdr((const void *)(uintptr_t)address,&info) && info.dli_fbase==base; }
static BOOL HFASDRead64(uint64_t address, uint64_t *out) {
    if (!address || !out) return NO; vm_size_t copied=0; uint64_t value=0;
    if (vm_read_overwrite(mach_task_self(),(vm_address_t)address,sizeof(value),(vm_address_t)&value,&copied)!=KERN_SUCCESS || copied!=sizeof(value)) return NO;
    *out=value; return YES;
}
static BOOL HFASDRead32(uint64_t address, uint32_t *out) {
    if (!address || !out) return NO; vm_size_t copied=0; uint32_t value=0;
    if (vm_read_overwrite(mach_task_self(),(vm_address_t)address,sizeof(value),(vm_address_t)&value,&copied)!=KERN_SUCCESS || copied!=sizeof(value)) return NO;
    *out=value; return YES;
}
static NSDictionary *HFASDTargetContext(uint64_t target, uint64_t base) {
    NSMutableDictionary *d=[@{ @"runtimeVA":@(target), @"runtimeVAHex":[NSString stringWithFormat:@"0x%llX",(unsigned long long)target],
                                @"sameImageRVA": target>=base ? @(target-base) : @0 } mutableCopy];
    Dl_info info={}; if(dladdr((const void *)(uintptr_t)target,&info)) {
        if(info.dli_fname){NSString *p=[NSString stringWithUTF8String:info.dli_fname]?:@"";d[@"image"]=p.lastPathComponent?:@"";d[@"path"]=p;}
        if(info.dli_sname)d[@"symbol"]=[NSString stringWithUTF8String:info.dli_sname]?:@"";
        if(info.dli_fbase)d[@"offsetFromLoadBase"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(target-(uint64_t)(uintptr_t)info.dli_fbase)];
    }
    return [d autorelease];
}
static NSDictionary *HFASDConditionEvidence(HFASDCondition c) {
    if(!c.valid)return @{}; NSMutableDictionary *d=[@{ @"sourceRVA":@(c.sourceRVA), @"lhs":HFASDRegEvidence(c.lhs),
                                                       @"kind": c.kind==1 ? @"cmp-immediate" : @"cmp-register",
                                                       @"senderDerived":@(HFASDSenderDerived(c.lhs)||HFASDSenderDerived(c.rhs)) } mutableCopy];
    if(c.rhsImmediate){d[@"rhsImmediate"]=@(c.immediate);d[@"rhsImmediateHex"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)c.immediate];}
    else d[@"rhs"]=HFASDRegEvidence(c.rhs);
    return [d autorelease];
}
static void HFASDEnqueue(NSMutableArray *q, NSMutableSet *scheduled, uint64_t pc, NSUInteger depth, HFASDReg regs[31], NSDictionary *stack, HFASDCondition cond, const void *imageBase) {
    if(!pc||depth>kHFASDMaxDepth||q.count>=kHFASDMaxBlocks||!HFASDSameImage(pc,imageBase))return;
    NSString *key=[NSString stringWithFormat:@"%llx:%u:%u:%u",(unsigned long long)pc,(unsigned)regs[0].root,(unsigned)regs[1].root,(unsigned)regs[2].root];
    if([scheduled containsObject:key])return;[scheduled addObject:key];
    [q addObject:@{ @"pc":@(pc), @"depth":@(depth), @"regs":HFASDRegsData(regs), @"stack":stack?:@{}, @"condition":HFASDConditionData(cond) }];
}
static NSString *HFASDCondName(unsigned c) {
    static NSString *names[]={@"eq",@"ne",@"cs",@"cc",@"mi",@"pl",@"vs",@"vc",@"hi",@"ls",@"ge",@"lt",@"gt",@"le",@"al",@"nv"};
    return c<16?names[c]:@"?";
}

static BOOL HFASDApply(uint32_t insn,uint64_t pc,uint64_t base,HFASDReg regs[31],NSMutableDictionary *stack,HFASDCondition *condition) {
    uint64_t rva=pc-base;
    if((insn&0x9f000000U)==0x90000000U){unsigned rd=insn&31U;int64_t imm=HFASDSignExtend(((((uint64_t)insn>>5)&0x7ffffULL)<<2)|((insn>>29)&3U),21)<<12;if(rd<31)regs[rd]=HFASDConcrete(HFASDAddress,(pc&~0xfffULL)+imm,rva);return YES;}
    if((insn&0x9f000000U)==0x10000000U){unsigned rd=insn&31U;int64_t imm=HFASDSignExtend(((((uint64_t)insn>>5)&0x7ffffULL)<<2)|((insn>>29)&3U),21);if(rd<31)regs[rd]=HFASDConcrete(HFASDAddress,pc+imm,rva);return YES;}
    if((insn&0xffe0ffe0U)==0xaa0003e0U){unsigned rd=insn&31U,rm=(insn>>16)&31U;if(rd<31&&rm<31){regs[rd]=regs[rm];regs[rd].sourceRVA=rva;}return YES;}
    if((insn&0xffc00000U)==0x91000000U){unsigned rd=insn&31U,rn=(insn>>5)&31U;uint64_t imm=(insn>>10)&0xfffU;if(insn&(1U<<22))imm<<=12;if(rd<31&&rn<31&&HFASDHasValue(regs[rn])){HFASDReg n=regs[rn];n.value+=imm;n.sourceRVA=rva;n.fieldOffset+=(int64_t)imm;regs[rd]=n;}return YES;}
    if((insn&0xff800000U)==0xd2800000U){unsigned rd=insn&31U;uint64_t imm=((insn>>5)&0xffffU)<<(((insn>>21)&3U)*16U);if(rd<31)regs[rd]=HFASDConcrete(HFASDImmediate,imm,rva);return YES;}
    if((insn&0xff800000U)==0xf2800000U){unsigned rd=insn&31U;uint64_t imm16=(insn>>5)&0xffffU;unsigned shift=((insn>>21)&3U)*16U;uint64_t prior=(rd<31&&regs[rd].kind==HFASDImmediate)?regs[rd].value:0;if(rd<31){regs[rd]=HFASDConcrete(HFASDImmediate,(prior&~(0xffffULL<<shift))|(imm16<<shift),rva);}return YES;}
    if((insn&0xff000000U)==0x58000000U){unsigned rt=insn&31U;uint64_t slot=HFASDTarget19(pc,insn),v=0;if(rt<31&&HFASDRead64(slot,&v))regs[rt]=HFASDConcrete(HFASDAddress,v,rva);return YES;}
    if((insn&0xffc00000U)==0xf9400000U){unsigned rt=insn&31U,rn=(insn>>5)&31U;uint64_t imm=((insn>>10)&0xfffU)<<3;if(rt<31&&rn<31&&HFASDHasValue(regs[rn])){uint64_t v=0;if(HFASDRead64(regs[rn].value+imm,&v)){HFASDReg n=HFASDConcrete(HFASDFieldLoad,v,rva);n.root=regs[rn].root;n.confidence=n.root?HFASDConfidenceDerived:HFASDConfidenceNone;n.originRVA=regs[rn].originRVA;n.fieldOffset=regs[rn].fieldOffset+(int64_t)imm;regs[rt]=n;}}return YES;}
    if((insn&0xffc00000U)==0xb9400000U){unsigned rt=insn&31U,rn=(insn>>5)&31U;uint64_t imm=((insn>>10)&0xfffU)<<2;if(rt<31&&rn<31&&HFASDHasValue(regs[rn])){uint32_t v=0;if(HFASDRead32(regs[rn].value+imm,&v)){HFASDReg n=HFASDConcrete(HFASDFieldLoad,v,rva);n.root=regs[rn].root;n.confidence=n.root?HFASDConfidenceDerived:HFASDConfidenceNone;n.originRVA=regs[rn].originRVA;n.fieldOffset=regs[rn].fieldOffset+(int64_t)imm;regs[rt]=n;}}return YES;}
    if((insn&0xffe00c00U)==0xf8400000U){unsigned rt=insn&31U,rn=(insn>>5)&31U;int64_t imm=HFASDSignExtend((insn>>12)&0x1ffU,9);if(rt<31&&rn<31&&HFASDHasValue(regs[rn])){uint64_t v=0;if(HFASDRead64((uint64_t)((int64_t)regs[rn].value+imm),&v)){HFASDReg n=HFASDConcrete(HFASDFieldLoad,v,rva);n.root=regs[rn].root;n.confidence=n.root?HFASDConfidenceDerived:HFASDConfidenceNone;n.originRVA=regs[rn].originRVA;n.fieldOffset=regs[rn].fieldOffset+imm;regs[rt]=n;}}return YES;}
    if((insn&0xffe00c00U)==0xb8400000U){unsigned rt=insn&31U,rn=(insn>>5)&31U;int64_t imm=HFASDSignExtend((insn>>12)&0x1ffU,9);if(rt<31&&rn<31&&HFASDHasValue(regs[rn])){uint32_t v=0;if(HFASDRead32((uint64_t)((int64_t)regs[rn].value+imm),&v)){HFASDReg n=HFASDConcrete(HFASDFieldLoad,v,rva);n.root=regs[rn].root;n.confidence=n.root?HFASDConfidenceDerived:HFASDConfidenceNone;n.originRVA=regs[rn].originRVA;n.fieldOffset=regs[rn].fieldOffset+imm;regs[rt]=n;}}return YES;}
    if((insn&0xffc00000U)==0xf9000000U){unsigned rt=insn&31U,rn=(insn>>5)&31U;uint64_t imm=((insn>>10)&0xfffU)<<3;if(rn==31&&rt<31&&stack.count<kHFASDMaxStackSlots)stack[@((int64_t)imm)]=[NSData dataWithBytes:&regs[rt] length:sizeof(HFASDReg)];return YES;}
    if((insn&0xffc00000U)==0xf9400000U){return YES;}
    if((insn&0xff00001fU)==0xf100001fU){unsigned rn=(insn>>5)&31U;uint64_t imm=(insn>>10)&0xfffU;if(insn&(1U<<22))imm<<=12;if(condition){condition->valid=rn<31;condition->lhs=rn<31?regs[rn]:HFASDUnknownReg(rva);condition->rhs=HFASDUnknownReg(rva);condition->rhsImmediate=YES;condition->immediate=imm;condition->sourceRVA=rva;condition->kind=1;}return YES;}
    if((insn&0xffe0fc1fU)==0xeb00001fU){unsigned rn=(insn>>5)&31U,rm=(insn>>16)&31U;if(condition){condition->valid=rn<31&&rm<31;condition->lhs=rn<31?regs[rn]:HFASDUnknownReg(rva);condition->rhs=rm<31?regs[rm]:HFASDUnknownReg(rva);condition->rhsImmediate=NO;condition->immediate=0;condition->sourceRVA=rva;condition->kind=2;}return YES;}
    return NO;
}

static NSArray *HFASDSenderArgumentNames(HFASDReg regs[31]) {
    NSMutableArray *a=[NSMutableArray array]; for(unsigned r=0;r<=7;++r)if(HFASDSenderDerived(regs[r]))[a addObject:[NSString stringWithFormat:@"x%u",r]]; return a;
}
static HFASDReg HFASDCallResultFromArgs(HFASDReg regs[31], uint64_t rva) {
    BOOL sender=NO,target=NO,selector=NO; for(unsigned r=0;r<=7;++r){sender|=regs[r].root==HFASDRootSender;target|=regs[r].root==HFASDRootTarget;selector|=regs[r].root==HFASDRootSelector;}
    HFASDReg out={HFASDCallResult,HFASDRootNone,HFASDConfidenceNone,0,rva,rva,0};
    if(sender){out.root=HFASDRootSender;out.confidence=(target||selector)?HFASDConfidenceCandidate:HFASDConfidenceDerived;}
    else if(target){out.root=HFASDRootTarget;out.confidence=HFASDConfidenceCandidate;}
    return out;
}
static void HFASDClobberCallerSaved(HFASDReg regs[31], HFASDReg ret) { for(unsigned r=0;r<=18;++r)regs[r]=HFASDUnknownReg(ret.sourceRVA); regs[0]=ret; }

NSDictionary *HFAMapResolveSenderDerivedProvenance(const void *implementation, NSString *implementationPath, NSDictionary *entryContext) {
    if(!implementation||!implementationPath.length)return @{ @"schema":@"com.hfa.sender-derived-provenance/v1",@"status":@"missing-input",@"analysisOnly":@YES };
    Dl_info info={};if(!dladdr(implementation,&info)||!info.dli_fbase)return @{ @"schema":@"com.hfa.sender-derived-provenance/v1",@"status":@"dladdr-failed",@"analysisOnly":@YES };
    uint64_t base=(uint64_t)(uintptr_t)info.dli_fbase,start=(uint64_t)(uintptr_t)implementation;
    uint64_t target=strtoull([entryContext[@"targetToken"] UTF8String]?:"0",NULL,0),sender=strtoull([entryContext[@"senderToken"] UTF8String]?:"0",NULL,0);
    NSString *selName=entryContext[@"selector"]?:@"";SEL sel=selName.length?NSSelectorFromString(selName):NULL;
    HFASDReg initial[31]={};if(target)initial[0]=HFASDEntryReg(HFASDRootTarget,target);if(sel)initial[1]=HFASDEntryReg(HFASDRootSelector,(uint64_t)(uintptr_t)sel);if(sender)initial[2]=HFASDEntryReg(HFASDRootSender,sender);
    NSMutableArray *queue=[NSMutableArray array],*blocks=[NSMutableArray array],*calls=[NSMutableArray array],*branches=[NSMutableArray array],*senderBranches=[NSMutableArray array],*senderCalls=[NSMutableArray array];
    NSMutableSet *scheduled=[NSMutableSet set],*visited=[NSMutableSet set];HFASDCondition c0={};HFASDEnqueue(queue,scheduled,start,0,initial,@{},c0,info.dli_fbase);NSUInteger decoded=0;
    while(queue.count&&blocks.count<kHFASDMaxBlocks&&decoded<kHFASDMaxInstructions){NSDictionary *item=[[queue objectAtIndex:0] retain];[queue removeObjectAtIndex:0];uint64_t bs=[item[@"pc"] unsignedLongLongValue];NSString *visit=[NSString stringWithFormat:@"%llx:%@",(unsigned long long)bs,item[@"regs"]];if([visited containsObject:visit]){[item release];continue;}[visited addObject:visit];NSUInteger depth=[item[@"depth"] unsignedIntegerValue];HFASDReg regs[31]={};HFASDRestoreRegs(item[@"regs"],regs);NSMutableDictionary *stack=[item[@"stack"] mutableCopy]?:[NSMutableDictionary new];HFASDCondition cond=HFASDConditionFromData(item[@"condition"]);[blocks addObject:@{ @"startRVA":@(bs-base),@"depth":@(depth)}];[item release];
        for(NSUInteger idx=0;idx<kHFASDMaxPerBlock&&decoded<kHFASDMaxInstructions;++idx){uint64_t pc=bs+idx*4ULL;if(!HFASDSameImage(pc,info.dli_fbase))break;uint32_t insn=0;vm_size_t copied=0;if(vm_read_overwrite(mach_task_self(),(vm_address_t)pc,sizeof(insn),(vm_address_t)&insn,&copied)!=KERN_SUCCESS||copied!=sizeof(insn))break;++decoded;uint64_t rva=pc-base;
            if(HFASDApply(insn,pc,base,regs,stack,&cond))continue;
            if((insn&0xfc000000U)==0x94000000U){uint64_t t=HFASDTarget26(pc,insn);NSMutableDictionary *args=[NSMutableDictionary dictionary];for(unsigned r=0;r<=7;++r){NSDictionary *e=HFASDRegEvidence(regs[r]);if(e.count)args[[NSString stringWithFormat:@"x%u",r]]=e;}NSArray *senderArgs=HFASDSenderArgumentNames(regs);NSMutableDictionary *rec=[@{ @"kind":@"bl-direct",@"callsiteRVA":@(rva),@"target":HFASDTargetContext(t,base),@"arguments":args,@"senderDerivedArguments":senderArgs,@"senderDerived":@(senderArgs.count>0),@"analysisOnly":@YES } mutableCopy];if(calls.count<kHFASDMaxCalls)[calls addObject:rec];if(senderArgs.count&&senderCalls.count<kHFASDMaxCalls)[senderCalls addObject:rec];HFASDEnqueue(queue,scheduled,t,depth+1,regs,stack,cond,info.dli_fbase);HFASDReg ret=HFASDCallResultFromArgs(regs,rva);HFASDClobberCallerSaved(regs,ret);cond.valid=NO;[rec release];continue;}
            if((insn&0x7e000000U)==0x34000000U){uint64_t t=HFASDTarget19(pc,insn);unsigned rt=insn&31U;BOOL nz=(insn&0x01000000U)!=0;HFASDReg tested=rt<31?regs[rt]:HFASDUnknownReg(rva);NSDictionary *rec=@{ @"kind":@"cbz-cbnz",@"variant":nz?@"cbnz":@"cbz",@"fromRVA":@(rva),@"targetRVA":t>=base?@(t-base):@0,@"testedRegister":[NSString stringWithFormat:@"x%u",rt],@"testedValue":HFASDRegEvidence(tested),@"senderDerived":@(HFASDSenderDerived(tested)),@"analysisOnly":@YES };if(branches.count<kHFASDMaxBranches)[branches addObject:rec];if(HFASDSenderDerived(tested)&&senderBranches.count<kHFASDMaxBranches)[senderBranches addObject:rec];HFASDEnqueue(queue,scheduled,t,depth+1,regs,stack,cond,info.dli_fbase);HFASDEnqueue(queue,scheduled,pc+4,depth+1,regs,stack,cond,info.dli_fbase);break;}
            if((insn&0x7e000000U)==0x36000000U){uint64_t t=HFASDTarget14(pc,insn);unsigned rt=insn&31U;unsigned bit=((insn>>19)&0x1fU)|((insn>>26)&0x20U);BOOL nz=(insn&0x01000000U)!=0;HFASDReg tested=rt<31?regs[rt]:HFASDUnknownReg(rva);NSDictionary *rec=@{ @"kind":@"tbz-tbnz",@"variant":nz?@"tbnz":@"tbz",@"fromRVA":@(rva),@"targetRVA":t>=base?@(t-base):@0,@"testedRegister":[NSString stringWithFormat:@"x%u",rt],@"testedBit":@(bit),@"testedValue":HFASDRegEvidence(tested),@"senderDerived":@(HFASDSenderDerived(tested)),@"analysisOnly":@YES };if(branches.count<kHFASDMaxBranches)[branches addObject:rec];if(HFASDSenderDerived(tested)&&senderBranches.count<kHFASDMaxBranches)[senderBranches addObject:rec];HFASDEnqueue(queue,scheduled,t,depth+1,regs,stack,cond,info.dli_fbase);HFASDEnqueue(queue,scheduled,pc+4,depth+1,regs,stack,cond,info.dli_fbase);break;}
            if((insn&0xff000010U)==0x54000000U){uint64_t t=HFASDTarget19(pc,insn);NSDictionary *ce=HFASDConditionEvidence(cond);BOOL sd=[ce[@"senderDerived"] boolValue];NSDictionary *rec=@{ @"kind":@"b-cond",@"condition":HFASDCondName(insn&0xfU),@"fromRVA":@(rva),@"targetRVA":t>=base?@(t-base):@0,@"conditionProvenance":ce,@"senderDerived":@(sd),@"analysisOnly":@YES };if(branches.count<kHFASDMaxBranches)[branches addObject:rec];if(sd&&senderBranches.count<kHFASDMaxBranches)[senderBranches addObject:rec];HFASDEnqueue(queue,scheduled,t,depth+1,regs,stack,cond,info.dli_fbase);HFASDEnqueue(queue,scheduled,pc+4,depth+1,regs,stack,cond,info.dli_fbase);break;}
            if((insn&0xfc000000U)==0x14000000U){uint64_t t=HFASDTarget26(pc,insn);HFASDEnqueue(queue,scheduled,t,depth+1,regs,stack,cond,info.dli_fbase);break;}
            if((insn&0xfffffc1fU)==0xd65f0000U)break;
        }[stack release];
    }
    return @{ @"schema":@"com.hfa.sender-derived-provenance/v1",@"buildVersion":@"2.5.16-dev",@"status":decoded?@"cfg-decoded":@"no-readable-code",@"implementationPath":implementationPath,@"implementationRVA":@(start-base),@"entryContext":entryContext?:@{},@"decodedInstructionCount":@(decoded),@"blockCount":@(blocks.count),@"blocks":blocks,@"callCount":@(calls.count),@"calls":calls,@"senderDerivedCallCount":@(senderCalls.count),@"senderDerivedCalls":senderCalls,@"branchCount":@(branches.count),@"branches":branches,@"senderDerivedBranchCount":@(senderBranches.count),@"senderDerivedBranches":senderBranches,@"policy":@"READ-ONLY-SENDER-FIELD-CALL-BRANCH-PROVENANCE",@"analysisOnly":@YES,@"canonicalEligible":@NO,@"safety":@{ @"unknownSelectorInvoked":@NO,@"actionInvoked":@NO,@"memoryWritten":@NO,@"inlineHookInstalled":@NO } };
}

BOOL HFAMapPersistSenderDerivedProvenance(NSDictionary *result, NSError **error) {
    if(!result)return NO;NSData *data=[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:error];if(!data)return NO;NSString *documents=[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES) firstObject];NSString *path=[documents stringByAppendingPathComponent:HFAOutputFileName(@"SenderDerivedProvenance.json")];return [data writeToFile:path options:NSDataWritingAtomic error:error];
}

static void HFASDProcessInventory(void) {
    static NSString *lastDigest;NSString *documents=[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES) firstObject];NSString *inventoryPath=[documents stringByAppendingPathComponent:HFAOutputFileName(@"LoadedMenuFeatureInventory.json")];NSData *data=[NSData dataWithContentsOfFile:inventoryPath];if(!data.length)return;NSDictionary *attrs=[[NSFileManager defaultManager] attributesOfItemAtPath:inventoryPath error:nil];NSString *digest=[NSString stringWithFormat:@"%lu:%@",(unsigned long)data.length,attrs.fileModificationDate?:@""];if([digest isEqualToString:lastDigest])return;NSDictionary *inventory=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil];if(![inventory isKindOfClass:NSDictionary.class])return;NSString *menuPath=inventory[@"menuPath"]?:@"";if(!menuPath.length)return;
    NSMutableDictionary *controlByToken=[NSMutableDictionary dictionary];for(NSDictionary *c in inventory[@"controls"]?:@[])if([c[@"controlToken"] length])controlByToken[c[@"controlToken"]]=c;
    NSMutableArray *featureResults=[NSMutableArray array];NSUInteger actionCount=0,senderCallCount=0,senderBranchCount=0;
    for(NSDictionary *feature in inventory[@"featureCandidates"]?:@[]){NSMutableArray *actionsOut=[NSMutableArray array];for(NSDictionary *ref in feature[@"controls"]?:@[]){NSString *senderToken=ref[@"token"]?:@"";NSDictionary *control=controlByToken[senderToken]?:@{};for(NSDictionary *action in control[@"actions"]?:@[]){NSString *runtimeVA=action[@"implementation"][@"runtimeVA"]?:@"";uintptr_t ptr=(uintptr_t)strtoull(runtimeVA.UTF8String,NULL,0);if(!ptr)continue;NSDictionary *ctx=@{ @"featureTitle":feature[@"title"]?:@"",@"senderToken":senderToken,@"targetToken":action[@"targetToken"]?:@"",@"selector":action[@"selector"]?:@"",@"event":action[@"event"]?:@"" };NSDictionary *prov=HFAMapResolveSenderDerivedProvenance((const void *)ptr,menuPath,ctx);[actionsOut addObject:@{ @"event":action[@"event"]?:@"",@"selector":action[@"selector"]?:@"",@"implementation":action[@"implementation"]?:@{},@"provenance":prov?:@{} }];++actionCount;senderCallCount+=[prov[@"senderDerivedCallCount"] unsignedIntegerValue];senderBranchCount+=[prov[@"senderDerivedBranchCount"] unsignedIntegerValue];}}
        [featureResults addObject:@{ @"title":feature[@"title"]?:@"",@"identifiers":feature[@"identifiers"]?:@[],@"actions":actionsOut }];}
    NSDictionary *result=@{ @"schema":@"com.hfa.sender-derived-feature-report/v1",@"buildVersion":@"2.5.16-dev",@"componentVersion":@"2.5.16-dev-sender-derived-provenance",@"menuImage":menuPath.lastPathComponent?:@"",@"menuPath":menuPath,@"summary":@{ @"featureCount":@(featureResults.count),@"actionCount":@(actionCount),@"senderDerivedCallCount":@(senderCallCount),@"senderDerivedBranchCount":@(senderBranchCount) },@"features":featureResults,@"policy":@"READ-ONLY-SENDER-FIELD-CALL-BRANCH-PROVENANCE",@"safety":@{ @"unknownSelectorInvoked":@NO,@"actionInvoked":@NO,@"memoryWritten":@NO,@"inlineHookInstalled":@NO } };
    NSError *error=nil;if(HFAMapPersistSenderDerivedProvenance(result,&error)){[lastDigest release];lastDigest=[digest copy];HFADiagnosticsLog(@"sender-derived-provenance",@"persisted",result[@"summary"]);}else HFADiagnosticsLog(@"sender-derived-provenance",@"failed",@{ @"error":error.localizedDescription?:@"unknown" });
}
static void HFASDSchedule(void) { static dispatch_source_t timer;static dispatch_once_t once;dispatch_once(&once,^{dispatch_queue_t q=dispatch_get_global_queue(QOS_CLASS_UTILITY,0);timer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,q);dispatch_source_set_timer(timer,dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),(uint64_t)(1.0*NSEC_PER_SEC),(uint64_t)(0.1*NSEC_PER_SEC));dispatch_source_set_event_handler(timer,^{HFASDProcessInventory();});dispatch_resume(timer);}); }
__attribute__((constructor)) static void HFASDConstructor(void){HFASDSchedule();}

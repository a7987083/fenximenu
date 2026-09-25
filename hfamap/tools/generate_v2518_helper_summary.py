from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
subprocess.run([sys.executable, str(ROOT / "tools/generate_v2517_sender_resolver.py")], check=True)
src = ROOT / "src/HFAMapSenderDerivedProvenanceResolver2517.mm"
out = ROOT / "src/HFAMapSenderDerivedProvenanceResolver2518.mm"
text = src.read_text()

anchor = '''static void HFASDClobberCallerSaved(HFASDReg regs[31], HFASDReg ret) { for(unsigned r=0;r<=18;++r)regs[r]=HFASDUnknownReg(ret.sourceRVA); regs[0]=ret; }\n'''
helper = r'''
static NSString *HFASDHelperSignature(uint64_t target, HFASDReg regs[31]) {
    return [NSString stringWithFormat:@"%llx:%u:%u:%u:%u:%u:%u:%lld:%lld:%lld",
            (unsigned long long)target,
            (unsigned)regs[0].root,(unsigned)regs[1].root,(unsigned)regs[2].root,
            (unsigned)regs[0].kind,(unsigned)regs[1].kind,(unsigned)regs[2].kind,
            (long long)regs[0].fieldOffset,(long long)regs[1].fieldOffset,(long long)regs[2].fieldOffset];
}

static HFASDReg HFASDSummarizeHelperReturn(uint64_t start,
                                           uint64_t base,
                                           const void *imageBase,
                                           HFASDReg callerRegs[31],
                                           NSUInteger interprocDepth,
                                           NSMutableDictionary *memo,
                                           NSMutableArray *summaryLog) {
    uint64_t entryRVA = start >= base ? start - base : 0;
    if (!start || !HFASDSameImage(start,imageBase) || interprocDepth > 2) return HFASDUnknownReg(entryRVA);
    NSString *sig = HFASDHelperSignature(start, callerRegs);
    NSDictionary *cached = memo[sig];
    if (cached) {
        HFASDReg r = HFASDUnknownReg(entryRVA);
        NSData *d = cached[@"returnReg"];
        if (d.length == sizeof(HFASDReg)) memcpy(&r,d.bytes,sizeof(r));
        return r;
    }
    NSMutableArray *q=[NSMutableArray array];
    NSMutableSet *seen=[NSMutableSet set];
    HFASDReg init[31]={}; memcpy(init,callerRegs,sizeof(init));
    HFASDCondition c0={};
    [q addObject:@{ @"pc":@(start), @"regs":HFASDRegsData(init), @"stack":@{}, @"condition":HFASDConditionData(c0), @"depth":@0 }];
    HFASDReg best=HFASDUnknownReg(entryRVA);
    NSUInteger decoded=0, returns=0;
    while(q.count && decoded<768 && seen.count<48) {
        NSDictionary *item=[[q objectAtIndex:0] retain]; [q removeObjectAtIndex:0];
        uint64_t bs=[item[@"pc"] unsignedLongLongValue];
        HFASDReg regs[31]={}; HFASDRestoreRegs(item[@"regs"],regs);
        NSMutableDictionary *stack=[item[@"stack"] mutableCopy]?:[NSMutableDictionary new];
        HFASDCondition cond=HFASDConditionFromData(item[@"condition"]);
        NSUInteger depth=[item[@"depth"] unsignedIntegerValue];
        NSString *key=[NSString stringWithFormat:@"%llx:%u:%u:%u:%u:%u:%lld:%lld",
                       (unsigned long long)bs,(unsigned)regs[0].root,(unsigned)regs[2].root,
                       (unsigned)regs[19].root,(unsigned)regs[20].root,(unsigned)regs[0].kind,
                       (long long)regs[19].fieldOffset,(long long)regs[20].fieldOffset];
        [item release];
        if([seen containsObject:key]){[stack release];continue;} [seen addObject:key];
        for(NSUInteger idx=0; idx<96 && decoded<768; ++idx) {
            uint64_t pc=bs+idx*4ULL; if(!HFASDSameImage(pc,imageBase)) break;
            uint32_t insn=0; vm_size_t copied=0;
            if(vm_read_overwrite(mach_task_self(),(vm_address_t)pc,sizeof(insn),(vm_address_t)&insn,&copied)!=KERN_SUCCESS||copied!=sizeof(insn)) break;
            ++decoded; uint64_t rva=pc-base;
            if(HFASDApply(insn,pc,base,regs,stack,&cond)) continue;
            if((insn&0xfc000000U)==0x94000000U) {
                uint64_t t=HFASDTarget26(pc,insn);
                HFASDReg ret=HFASDCallResultFromArgs(regs,rva);
                if(HFASDSameImage(t,imageBase) && interprocDepth<2) {
                    HFASDReg nested=HFASDSummarizeHelperReturn(t,base,imageBase,regs,interprocDepth+1,memo,summaryLog);
                    if(nested.kind!=HFASDUnknown) ret=nested;
                }
                HFASDClobberCallerSaved(regs,ret); cond.valid=NO; continue;
            }
            if((insn&0x7e000000U)==0x34000000U || (insn&0xff000010U)==0x54000000U || (insn&0x7e000000U)==0x36000000U) {
                uint64_t t=((insn&0x7e000000U)==0x36000000U)?HFASDTarget14(pc,insn):HFASDTarget19(pc,insn);
                if(depth<8) {
                    [q addObject:@{ @"pc":@(t), @"regs":HFASDRegsData(regs), @"stack":stack?:@{}, @"condition":HFASDConditionData(cond), @"depth":@(depth+1) }];
                    [q addObject:@{ @"pc":@(pc+4), @"regs":HFASDRegsData(regs), @"stack":stack?:@{}, @"condition":HFASDConditionData(cond), @"depth":@(depth+1) }];
                }
                break;
            }
            if((insn&0xfc000000U)==0x14000000U) {
                uint64_t t=HFASDTarget26(pc,insn);
                if(depth<8)[q addObject:@{ @"pc":@(t), @"regs":HFASDRegsData(regs), @"stack":stack?:@{}, @"condition":HFASDConditionData(cond), @"depth":@(depth+1) }];
                break;
            }
            if((insn&0xfffffc1fU)==0xd65f0000U) {
                ++returns;
                HFASDReg r=regs[0];
                if(HFASDSenderDerived(r) && (!HFASDSenderDerived(best) || r.confidence<best.confidence)) best=r;
                else if(best.kind==HFASDUnknown && r.kind!=HFASDUnknown) best=r;
                break;
            }
        }
        [stack release];
    }
    NSData *retData=[NSData dataWithBytes:&best length:sizeof(best)];
    memo[sig]=@{ @"returnReg":retData,
                 @"entryRVA":@(entryRVA),
                 @"decodedInstructionCount":@(decoded),
                 @"returnCount":@(returns),
                 @"senderDerivedReturn":@(HFASDSenderDerived(best)) };
    if(summaryLog.count<128) [summaryLog addObject:@{ @"entryRVA":@(entryRVA),
                                                      @"signature":sig,
                                                      @"decodedInstructionCount":@(decoded),
                                                      @"returnCount":@(returns),
                                                      @"returnValue":HFASDRegEvidence(best),
                                                      @"senderDerivedReturn":@(HFASDSenderDerived(best)),
                                                      @"interprocDepth":@(interprocDepth),
                                                      @"analysisOnly":@YES }];
    return best;
}
'''
if anchor not in text:
    raise SystemExit("v2518: clobber anchor missing")
text=text.replace(anchor,anchor+helper,1)

old_decl='''NSMutableArray *queue=[NSMutableArray array],*blocks=[NSMutableArray array],*calls=[NSMutableArray array],*branches=[NSMutableArray array],*senderBranches=[NSMutableArray array],*senderCalls=[NSMutableArray array];'''
new_decl='''NSMutableArray *queue=[NSMutableArray array],*blocks=[NSMutableArray array],*calls=[NSMutableArray array],*branches=[NSMutableArray array],*senderBranches=[NSMutableArray array],*senderCalls=[NSMutableArray array],*helperSummaries=[NSMutableArray array];NSMutableDictionary *helperMemo=[NSMutableDictionary dictionary];'''
if old_decl not in text:
    raise SystemExit("v2518: local arrays anchor missing")
text=text.replace(old_decl,new_decl,1)

old_bl='''HFASDEnqueue(queue,scheduled,t,depth+1,regs,stack,cond,info.dli_fbase);HFASDReg ret=HFASDCallResultFromArgs(regs,rva);HFASDClobberCallerSaved(regs,ret);cond.valid=NO;'''
new_bl='''HFASDEnqueue(queue,scheduled,t,depth+1,regs,stack,cond,info.dli_fbase);HFASDReg ret=HFASDCallResultFromArgs(regs,rva);if(HFASDSameImage(t,info.dli_fbase)){HFASDReg summarized=HFASDSummarizeHelperReturn(t,base,info.dli_fbase,regs,0,helperMemo,helperSummaries);if(summarized.kind!=HFASDUnknown)ret=summarized;}HFASDClobberCallerSaved(regs,ret);cond.valid=NO;'''
if old_bl not in text:
    raise SystemExit("v2518: direct BL anchor missing")
text=text.replace(old_bl,new_bl,1)

old_return='''@"senderDerivedBranchCount":@(senderBranches.count),@"senderDerivedBranches":senderBranches,@"policy":@"READ-ONLY-SENDER-FIELD-STACK-CALLRESULT-BRANCH-PROVENANCE"'''
new_return='''@"senderDerivedBranchCount":@(senderBranches.count),@"senderDerivedBranches":senderBranches,@"helperSummaryCount":@(helperSummaries.count),@"helperSummaries":helperSummaries,@"senderDerivedHelperReturnCount":@([[helperSummaries filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDictionary *x, NSDictionary *_) { return [x[@"senderDerivedReturn"] boolValue]; }]] count]),@"policy":@"READ-ONLY-INTERPROCEDURAL-HELPER-RETURN-PROVENANCE"'''
if old_return not in text:
    raise SystemExit("v2518: result anchor missing")
text=text.replace(old_return,new_return,1)

text=text.replace('@"2.5.17-dev"','@"2.5.18-dev"')
text=text.replace('@"2.5.17-dev-sender-field-callresult"','@"2.5.18-dev-interprocedural-helper-summary"')
text=text.replace('@"READ-ONLY-SENDER-FIELD-STACK-CALLRESULT-BRANCH-PROVENANCE"','@"READ-ONLY-INTERPROCEDURAL-HELPER-RETURN-PROVENANCE"')

banner='// GENERATED BY tools/generate_v2518_helper_summary.py — do not edit directly.\n'
out.write_text(banner+text)
print(out)

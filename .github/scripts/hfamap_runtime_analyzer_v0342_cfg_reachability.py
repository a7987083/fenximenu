from pathlib import Path

ROOT = Path('hfamap')
SRC = ROOT / 'src' / 'HFAMapRuntimeAnalyzerV02.m'
SEM = ROOT / 'src' / 'HFARuntimeSemanticAnalyzer.m'
HDR = ROOT / 'src' / 'HFARuntimeSemanticAnalyzer.h'
UI = ROOT / 'src' / 'HFAMapCyberUI.m'


def function_span(text, name):
    needle = name + '('
    pos = 0
    while True:
        i = text.find(needle, pos)
        if i < 0:
            raise SystemExit(f'{name}: function not found')
        start = text.rfind('\n', 0, i) + 1
        brace = text.find('{', i)
        semi = text.find(';', i)
        if brace >= 0 and (semi < 0 or brace < semi):
            depth = 0
            in_str = False
            esc = False
            for j in range(brace, len(text)):
                ch = text[j]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == '\\':
                        esc = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                    continue
                if ch == '{': depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return start, j + 1
        pos = i + len(needle)


sem = SEM.read_text()
anchor = 'NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacement(uintptr_t replacement, uintptr_t originalSlot) {'
if anchor not in sem:
    raise SystemExit('v0342 semantic function anchor missing')

helpers = r'''
static BOOL HFASemConditionalTarget(uint32_t w, uintptr_t pc, uintptr_t *target) {
    if ((w & 0xFF000010u) == 0x54000000u || (w & 0x7E000000u) == 0x34000000u) {
        int64_t imm = HFASemSignExtend((w >> 5) & 0x7FFFFu, 19) << 2;
        if (target) *target = (uintptr_t)((int64_t)pc + imm);
        return YES;
    }
    if ((w & 0x7E000000u) == 0x36000000u) {
        int64_t imm = HFASemSignExtend((w >> 5) & 0x3FFFu, 14) << 2;
        if (target) *target = (uintptr_t)((int64_t)pc + imm);
        return YES;
    }
    return NO;
}

static BOOL HFASemIndexForTarget(uintptr_t target, uintptr_t start, NSUInteger count, NSUInteger *index) {
    if (target < start || target >= start + count * sizeof(uint32_t) || ((target - start) & 3u)) return NO;
    if (index) *index = (NSUInteger)((target - start) / sizeof(uint32_t));
    return YES;
}

static NSDictionary *HFASemBuildReachability(const uint32_t *words,
                                              NSUInteger count,
                                              uintptr_t start,
                                              BOOL *reachable) {
    if (!words || !count || !reachable) return @{@"status":@"invalid"};
    BOOL blockSeen[256] = {0};
    NSUInteger work[64] = {0};
    NSUInteger head = 0, tail = 0, blocks = 0, edges = 0, marked = 0;
    BOOL incomplete = NO, hitInstructionCap = NO, hitBlockCap = NO, hitEdgeCap = NO;
    work[tail++] = 0;

    while (head < tail) {
        NSUInteger bi = work[head++];
        if (bi >= count || blockSeen[bi]) continue;
        if (blocks >= 64) { incomplete = YES; hitBlockCap = YES; break; }
        blockSeen[bi] = YES;
        blocks++;
        BOOL terminated = NO;

        for (NSUInteger i = bi; i < count; i++) {
            if (reachable[i] && i != bi) { terminated = YES; break; }
            if (!reachable[i]) { reachable[i] = YES; marked++; }
            uint32_t w = words[i];
            uintptr_t pc = start + i * 4;

            if (HFASemRET(w)) { terminated = YES; break; }
            unsigned br = 0;
            if (HFASemBR(w, &br)) { (void)br; terminated = YES; break; }

            uintptr_t t = 0;
            if (HFASemBTarget(w, pc, &t)) {
                NSUInteger ti = 0;
                edges++;
                if (edges > 128) { incomplete = YES; hitEdgeCap = YES; terminated = YES; break; }
                if (HFASemIndexForTarget(t, start, count, &ti)) {
                    if (!blockSeen[ti] && tail < 64) work[tail++] = ti;
                    else if (!blockSeen[ti] && tail >= 64) { incomplete = YES; hitBlockCap = YES; }
                } else incomplete = YES;
                terminated = YES;
                break;
            }

            if (HFASemConditionalTarget(w, pc, &t)) {
                NSUInteger ti = 0;
                edges += 2;
                if (edges > 128) { incomplete = YES; hitEdgeCap = YES; terminated = YES; break; }
                if (HFASemIndexForTarget(t, start, count, &ti)) {
                    if (!blockSeen[ti] && tail < 64) work[tail++] = ti;
                    else if (!blockSeen[ti] && tail >= 64) { incomplete = YES; hitBlockCap = YES; }
                } else incomplete = YES;
                if (i + 1 < count) {
                    if (!blockSeen[i + 1] && tail < 64) work[tail++] = i + 1;
                    else if (!blockSeen[i + 1] && tail >= 64) { incomplete = YES; hitBlockCap = YES; }
                }
                terminated = YES;
                break;
            }
        }
        if (!terminated && bi < count) { incomplete = YES; hitInstructionCap = YES; }
    }

    return @{
        @"status": incomplete ? @"bounded-incomplete" : @"complete",
        @"basicBlocks": @(blocks),
        @"edges": @(edges),
        @"reachableInstructions": @(marked),
        @"hitInstructionCap": @(hitInstructionCap),
        @"hitBlockCap": @(hitBlockCap),
        @"hitEdgeCap": @(hitEdgeCap)
    };
}

'''
sem = sem.replace(anchor, helpers + anchor, 1)

a, b = function_span(sem, 'HFASemanticAnalyzeReplacement')
old_fn = sem[a:b]
old_sig = 'NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacement(uintptr_t replacement, uintptr_t originalSlot) {'
new_sig = 'NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacementBounded(uintptr_t replacement, uintptr_t originalSlot, uintptr_t hardEnd) {'
if old_sig not in old_fn:
    raise SystemExit('v0342 bounded signature anchor missing')
fn = old_fn.replace(old_sig, new_sig, 1)

count_anchor = '    NSUInteger count=MIN((NSUInteger)256,(NSUInteger)((image.textEnd-replacement)/4));\n    uint32_t snapshot[256]={0};'
count_repl = r'''    NSUInteger count=MIN((NSUInteger)256,(NSUInteger)((image.textEnd-replacement)/4));
    BOOL hardEndApplied=NO;
    if(hardEnd>replacement&&hardEnd<=image.textEnd){
        NSUInteger bounded=(NSUInteger)((hardEnd-replacement)/4);
        if(bounded<count){count=bounded;hardEndApplied=YES;}
    }
    if(!count){return @{@"status":@"empty-boundary",@"semanticType":@"unknown-runtime"};}
    uint32_t snapshot[256]={0};'''
if count_anchor not in fn:
    raise SystemExit('v0342 count/boundary anchor missing')
fn = fn.replace(count_anchor, count_repl, 1)

snap_end = '    HFASemStageLog(@"V0341-SNAPSHOT-END", [NSString stringWithFormat:@"instructions=%lu",(unsigned long)count]);'
snap_new = r'''    HFASemStageLog(@"V0341-SNAPSHOT-END", [NSString stringWithFormat:@"instructions=%lu hardEnd=%@",(unsigned long)count,hardEndApplied?[NSString stringWithFormat:@"0x%llX",(unsigned long long)hardEnd]:@"none"]);
    BOOL reachable[256]={0};
    NSDictionary *cfg=HFASemBuildReachability(words,count,replacement,reachable);
    HFASemStageLog(@"V0342-CFG-END", [NSString stringWithFormat:@"status=%@ blocks=%@ edges=%@ reachable=%@",cfg[@"status"]?:@"?",cfg[@"basicBlocks"]?:@0,cfg[@"edges"]?:@0,cfg[@"reachableInstructions"]?:@0]);'''
if snap_end not in fn:
    raise SystemExit('v0342 snapshot-end anchor missing')
fn = fn.replace(snap_end, snap_new, 1)

loop_anchor = '    for(NSUInteger i=0;i<count;i++){\n        if((i&15u)==0u && (CFAbsoluteTimeGetCurrent()-semStarted)>0.25){budgetExceeded=YES;break;}\n        uintptr_t pc=replacement+i*4;uint32_t w=words[i];'
loop_repl = r'''    for(NSUInteger i=0;i<count;i++){
        if(!reachable[i])continue;
        if((i&15u)==0u && (CFAbsoluteTimeGetCurrent()-semStarted)>0.25){budgetExceeded=YES;break;}
        uintptr_t pc=replacement+i*4;uint32_t w=words[i];'''
if loop_anchor not in fn:
    raise SystemExit('v0342 reachable loop anchor missing')
fn = fn.replace(loop_anchor, loop_repl, 1)

flag_old = '    BOOL conditional=NO,callsOriginal=NO,returnMul=NO,returnDiv=NO,returnSelect=NO,argMul=NO,argDiv=NO;'
flag_new = '    BOOL conditional=NO,callsOriginal=NO,tailCallsOriginal=NO,returnMul=NO,returnDiv=NO,returnSelect=NO,argMul=NO,argDiv=NO;'
if flag_old not in fn:
    raise SystemExit('v0342 flags anchor missing')
fn = fn.replace(flag_old, flag_new, 1)

br_old = '''        if(HFASemBR(w,&br)){
            NSMutableArray *a=[NSMutableArray array];for(unsigned r=0;r<8;r++)if(constKnown[r]&&constValue[r]<=1)[a addObject:@{@"index":@(r),@"value":@(constValue[r])}];if(a.count)[callbacks addObject:@{@"branchRegister":@(br),@"constantArguments":a,@"rva":HFASemRVA(pc,image)}];continue;
        }'''
br_new = '''        if(HFASemBR(w,&br)){
            if(originalReg[br]){tailCallsOriginal=YES;[ops addObject:@{@"op":@"TAILCALL_ORIGINAL",@"rva":HFASemRVA(pc,image)}];continue;}
            NSMutableArray *a=[NSMutableArray array];for(unsigned r=0;r<8;r++)if(constKnown[r]&&constValue[r]<=1)[a addObject:@{@"index":@(r),@"value":@(constValue[r])}];if(a.count)[callbacks addObject:@{@"branchRegister":@(br),@"constantArguments":a,@"rva":HFASemRVA(pc,image)}];continue;
        }'''
if br_old not in fn:
    raise SystemExit('v0342 BR semantic anchor missing')
fn = fn.replace(br_old, br_new, 1)

class_old = '''    if(constantReturns.count&&conditional)semantic=@"conditional-return";
    else if(callsOriginal&&returnMul)semantic=@"return-multiplier";
    else if(callsOriginal&&returnDiv)semantic=@"return-divider";
    else if(callsOriginal&&returnSelect)semantic=@"return-select";
    else if(argMul)semantic=@"argument-multiplier";
    else if(argDiv)semantic=@"argument-divider";
    else if(sub)semantic=@"subobject-receiver-capture";
    else if(direct)semantic=@"receiver-capture";
    else if(callbacks.count)semantic=@"callback-constant-argument";'''
class_new = '''    unsigned returnTransforms=(returnMul?1u:0u)+(returnDiv?1u:0u)+(returnSelect?1u:0u);
    if(constantReturns.count&&conditional)semantic=@"conditional-return";
    else if(callsOriginal&&returnTransforms>1)semantic=@"return-transform";
    else if(callsOriginal&&returnMul)semantic=@"return-multiplier";
    else if(callsOriginal&&returnDiv)semantic=@"return-divider";
    else if(callsOriginal&&returnSelect)semantic=@"return-select";
    else if(argMul)semantic=@"argument-multiplier";
    else if(argDiv)semantic=@"argument-divider";
    else if(sub)semantic=@"subobject-receiver-capture";
    else if(direct)semantic=@"receiver-capture";
    else if(callbacks.count)semantic=@"callback-constant-argument";
    else if(tailCallsOriginal)semantic=@"support-thunk";'''
if class_old not in fn:
    raise SystemExit('v0342 classification anchor missing')
fn = fn.replace(class_old, class_new, 1)

ret_static = '        @"staticOnly":@YES\n    };'
ret_aug = '''        @"staticOnly":@YES,
        @"cfg":cfg?:@{},
        @"hardEndApplied":@(hardEndApplied),
        @"hardEndRuntimeAddress":hardEndApplied?@(hardEnd):@0,
        @"tailCallsOriginal":@(tailCallsOriginal)
    };'''
if ret_static not in fn:
    raise SystemExit('v0342 semantic return augmentation anchor missing')
fn = fn.replace(ret_static, ret_aug, 1)

wrapper = r'''

NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacement(uintptr_t replacement, uintptr_t originalSlot) {
    return HFASemanticAnalyzeReplacementBounded(replacement, originalSlot, 0);
}
'''
sem = sem[:a] + fn + wrapper + sem[b:]
sem = sem.replace('HFAMap_RuntimeAnalyzer_v0341_stage.log', 'HFAMap_RuntimeAnalyzer_v0342_stage.log')
sem = sem.replace('V0341-SNAPSHOT', 'V0342-SNAPSHOT').replace('V0341-SEM-', 'V0342-SEM-').replace('V0341-IL2CPP-', 'V0342-IL2CPP-')
SEM.write_text(sem)

hdr = HDR.read_text()
if 'HFASemanticAnalyzeReplacementBounded' not in hdr:
    marker = 'FOUNDATION_EXPORT NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacement(\n    uintptr_t replacement,\n    uintptr_t originalSlot);'
    repl = marker + '\n\nFOUNDATION_EXPORT NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacementBounded(\n    uintptr_t replacement,\n    uintptr_t originalSlot,\n    uintptr_t hardEndRuntimeAddress);'
    if marker not in hdr:
        raise SystemExit('v0342 header anchor missing')
    hdr = hdr.replace(marker, repl, 1)
HDR.write_text(hdr)

s = SRC.read_text()
scan_anchor = 'unsigned HFAAnalyzerV02ScanSelectedImage(void)'
idx = s.find(scan_anchor)
if idx < 0:
    raise SystemExit('v0342 scan anchor missing')
if 'HFAV0342NextReplacementBoundary' not in s:
    boundary_helper = r'''
static uintptr_t HFAV0342NextReplacementBoundary(uintptr_t repl, NSArray *records, HFAV02Layout l) {
    if(!repl||!records.count)return 0;
    uintptr_t next=0;
    for(NSDictionary *r in records){
        NSString *rv=[r[@"replacementRVA"] isKindOfClass:NSString.class]?r[@"replacementRVA"]:nil;
        if(!rv.length)continue;
        BOOL ok=NO;uint64_t off=HFAV032HexValue(rv,&ok);if(!ok)continue;
        uintptr_t cand=l.base+(uintptr_t)off;
        if(cand>repl&&(!next||cand<next))next=cand;
    }
    return next;
}

'''
    s = s[:idx] + boundary_helper + s[idx:]

call_old = '@try{sem34=HFASemanticAnalyzeReplacement(repl,slot);}'
call_new = '''uintptr_t semanticEnd=HFAV0342NextReplacementBoundary(repl,records,l);
            HFAV02Log([NSString stringWithFormat:@"[V0342-BOUNDARY] id=%u replacement=0x%llX hardEnd=%@",backendId,(unsigned long long)repl,semanticEnd?[NSString stringWithFormat:@"0x%llX",(unsigned long long)semanticEnd]:@"none"]);
            @try{sem34=HFASemanticAnalyzeReplacementBounded(repl,slot,semanticEnd);}'''
if call_old not in s:
    raise SystemExit('v0342 semantic call anchor missing')
s = s.replace(call_old, call_new, 1)

s = s.replace('com.hfa.runtime-analyzer/v0.3.4.1', 'com.hfa.runtime-analyzer/v0.3.4.2', 1)
s = s.replace('[V0341-SCAN-BEGIN]', '[V0342-SCAN-BEGIN]').replace('[V0341-SEM-BEGIN]', '[V0342-SEM-BEGIN]').replace('[V0341-SEM-END]', '[V0342-SEM-END]').replace('[V0341-IL2CPP-BEGIN]', '[V0342-IL2CPP-BEGIN]').replace('[V0341-IL2CPP-END]', '[V0342-IL2CPP-END]').replace('[V0341-BACKEND]', '[V0342-BACKEND]').replace('[V0341-SCAN-END]', '[V0342-SCAN-END]').replace('[V0341-DECRYPT]', '[V0342-DECRYPT]')
s = s.replace('HFAEnableIL2CPPEnrichmentV0341', 'HFAEnableIL2CPPEnrichmentV0342')
out_old = 'NSString *p341=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v0341.json");'
out_new = 'NSString *p342=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v0342.json");NSString *p341=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v0341.json");'
if out_old not in s:
    raise SystemExit('v0342 output anchor missing')
s = s.replace(out_old, out_new, 1)
write_old = '[json writeToFile:p341 atomically:YES];[json writeToFile:p34 atomically:YES];'
write_new = '[json writeToFile:p342 atomically:YES];[json writeToFile:p341 atomically:YES];[json writeToFile:p34 atomically:YES];'
if write_old not in s:
    raise SystemExit('v0342 output write anchor missing')
s = s.replace(write_old, write_new, 1)
SRC.write_text(s)

ui = UI.read_text()
ui = ui.replace('HFAMap RuntimeAnalyzer v0.3.4.1 Stability', 'HFAMap RuntimeAnalyzer v0.3.4.2 CFGReachability', 2)
ui = ui.replace('com.hfa.runtime-analyzer.v0341', 'com.hfa.runtime-analyzer.v0342')
UI.write_text(ui)

for p in (ROOT / 'src').glob('*'):
    if p.suffix not in ('.m', '.mm'): continue
    t = p.read_text()
    t2 = t.replace('[V0341-BOOT-', '[V0342-BOOT-')
    if t2 != t: p.write_text(t2)

sem = SEM.read_text(); s = SRC.read_text(); ui = UI.read_text(); hdr = HDR.read_text()
required_sem = ['HFASemBuildReachability','reachable[256]','basicBlocks','reachableInstructions','HFASemConditionalTarget','return-transform','support-thunk','TAILCALL_ORIGINAL','HFAMap_RuntimeAnalyzer_v0342_stage.log','V0342-CFG-END']
for x in required_sem:
    if x not in sem: raise SystemExit('v0342 reachability missing: '+x)
required_src = ['HFAV0342NextReplacementBoundary','HFASemanticAnalyzeReplacementBounded','[V0342-BOUNDARY]','[V0342-SCAN-BEGIN]','[V0342-SEM-BEGIN]','[V0342-SCAN-END]','HFAMap_RuntimeAnalyzer_v0342.json','com.hfa.runtime-analyzer/v0.3.4.2','HFAEnableIL2CPPEnrichmentV0342']
for x in required_src:
    if x not in s: raise SystemExit('v0342 main integration missing: '+x)
if 'HFASemanticAnalyzeReplacementBounded' not in hdr:
    raise SystemExit('v0342 bounded API missing')
if 'HFAMap RuntimeAnalyzer v0.3.4.2 CFGReachability' not in ui:
    raise SystemExit('v0342 UI marker missing')
if 'disabled-by-default' not in s:
    raise SystemExit('v0342 enrichment unexpectedly enabled')
print('v0.3.4.2 CFG boundary/reachability fix applied')

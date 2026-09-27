from pathlib import Path

P = Path('hfamap/src/HFAMap5MDispatcherResolver.m')
s = P.read_text()

anchor = 'static BOOL HFA5MDecodeADDX(uint32_t insn, unsigned *rdOut, unsigned *rnOut, uint64_t *offsetOut) {'
if anchor not in s:
    raise SystemExit('v0311 decoder anchor missing')

if 'HFA0311ResolveNearbyBlockInvoke' not in s:
    helper = r'''
static BOOL HFA0311DecodeADR(uint32_t w, uintptr_t pc, unsigned *rd, uintptr_t *target) {
    if ((w & 0x9F000000u) != 0x10000000u) return NO;
    uint64_t imm = ((uint64_t)((w >> 5) & 0x7FFFFu) << 2) | ((w >> 29) & 3u);
    int64_t sx = (int64_t)((imm ^ (1ULL << 20)) - (1ULL << 20));
    if (rd) *rd = w & 31u;
    if (target) *target = (uintptr_t)((int64_t)pc + sx);
    return YES;
}
static BOOL HFA0311DecodeSTPXToSP(uint32_t w, unsigned *rt, unsigned *rt2, int64_t *offset) {
    if ((w & 0xFFC00000u) != 0xA9000000u) return NO;
    unsigned rn = (w >> 5) & 31u;
    if (rn != 31u) return NO;
    int64_t imm7 = (int64_t)((w >> 15) & 0x7Fu);
    if (imm7 & 0x40) imm7 -= 0x80;
    if (rt) *rt = w & 31u;
    if (rt2) *rt2 = (w >> 10) & 31u;
    if (offset) *offset = imm7 * 8;
    return YES;
}
static void HFA0311AppendBlockCandidate(NSMutableArray *out, NSMutableSet *seen, uintptr_t target, unsigned reg, const uint32_t *words, NSUInteger storeStart, NSUInteger callIndex, HFA5MImageLayout layout, NSString *materialization) {
    if (!out || !seen || !target || !HFA5MRangeContains(layout.text, target, 4)) return;
    NSUInteger stop = MIN(callIndex, storeStart + 18);
    for (NSUInteger k = storeStart; k < stop; k++) {
        unsigned rt=0, base=0; uint64_t off=0;
        if (HFA0310DecodeSTRX(words[k], &rt, &base, &off) && base == 31u && rt == reg) {
            NSString *key=[NSString stringWithFormat:@"%llX|str|%llu",(unsigned long long)target,(unsigned long long)off];
            if ([seen containsObject:key]) continue;
            [seen addObject:key];
            NSMutableDictionary *x=[(HFA5MAddressInfo((const void*)target)?:@{}) mutableCopy];
            x[@"discovery"]=@"stack-block-code-pointer";x[@"materialization"]=materialization?:@"unknown";x[@"stackStore"]=@"str-x";x[@"stackOffset"]=@(off);[out addObject:x];
        }
        unsigned p0=0,p1=0; int64_t poff=0;
        if (HFA0311DecodeSTPXToSP(words[k], &p0, &p1, &poff) && (p0 == reg || p1 == reg)) {
            NSString *key=[NSString stringWithFormat:@"%llX|stp|%lld",(unsigned long long)target,(long long)poff];
            if ([seen containsObject:key]) continue;
            [seen addObject:key];
            NSMutableDictionary *x=[(HFA5MAddressInfo((const void*)target)?:@{}) mutableCopy];
            x[@"discovery"]=@"stack-block-code-pointer";x[@"materialization"]=materialization?:@"unknown";x[@"stackStore"]=@"stp-x";x[@"stackOffset"]=@(poff);[out addObject:x];
        }
    }
}
static NSDictionary *HFA0311ResolveNearbyBlockInvoke(const uint32_t *words, NSUInteger count, uintptr_t start, NSUInteger callIndex, HFA5MImageLayout layout) {
    if (!words || !count || callIndex >= count) return @{};
    NSUInteger lo = callIndex > 48 ? callIndex - 48 : 0;
    NSMutableArray *candidates=[NSMutableArray array]; NSMutableSet *seen=[NSMutableSet set];
    for (NSUInteger i=lo;i<callIndex;i++) {
        unsigned reg=0; uintptr_t target=0; uintptr_t pc=start+i*4;
        if (HFA0311DecodeADR(words[i], pc, &reg, &target)) {
            HFA0311AppendBlockCandidate(candidates, seen, target, reg, words, i+1, callIndex, layout, @"adr");
        }
        uintptr_t page=0;
        if (HFA5MDecodeADRP(words[i], pc, &reg, &page)) {
            for (NSUInteger q=i+1;q<callIndex && q<=i+3;q++) {
                unsigned rd=0,rn=0; uint64_t imm=0;
                if (!HFA5MDecodeADDX(words[q], &rd, &rn, &imm) || rn != reg) continue;
                HFA0311AppendBlockCandidate(candidates, seen, page+(uintptr_t)imm, rd, words, q+1, callIndex, layout, @"adrp-add");
            }
        }
    }
    if (candidates.count == 1) {
        NSMutableDictionary *out=[candidates[0] mutableCopy];out[@"resolved"]=@YES;out[@"confidence"]=@"strong";out[@"candidateCount"]=@1;return out;
    }
    return @{@"resolved":@NO,@"candidateCount":@(candidates.count),@"candidates":candidates?:@[]};
}
'''
    s = s.replace(anchor, helper + '\n' + anchor, 1)

old = 'NSDictionary *bi=HFA0310ResolveNearbyBlockInvoke(words,count,start,j,layout);BOOL resolved=[bi[@"resolved"] boolValue];'
if old not in s:
    raise SystemExit('v0311 block call anchor missing')
s = s.replace(old, 'NSDictionary *bi=HFA0311ResolveNearbyBlockInvoke(words,count,start,j,layout);BOOL resolved=[bi[@"resolved"] boolValue];', 1)
s = s.replace('[V0310-BLOCK-INVOKE]', '[V0311-BLOCK-INVOKE]')
P.write_text(s)

for required in ['HFA0311DecodeADR','HFA0311DecodeSTPXToSP','HFA0311ResolveNearbyBlockInvoke','@"adr"','@"stp-x"','[V0311-BLOCK-INVOKE]']:
    if required not in s:
        raise SystemExit('missing '+required)
print('v0.3.11 ADR/STP block invoke resolver applied')

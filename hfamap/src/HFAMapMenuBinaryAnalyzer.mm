#import "HFAMapMenuBinaryAnalyzer.h"

#import <mach-o/nlist.h>
#include <string.h>

static const uint32_t kHFAMenuMaxSymbols = 200000;
static const NSUInteger kHFAMenuMaxFunctions = 4096;
static const NSUInteger kHFAMenuMaxPrimitiveSymbols = 64;
static const NSUInteger kHFAMenuMaxEntrySymbols = 128;
static const NSUInteger kHFAMenuMaxDispatcherSymbols = 256;
static const NSUInteger kHFAMenuMaxCallEdges = 256;
static const NSUInteger kHFAMenuMaxArgumentEvidence = 8;
static const uint64_t kHFAMenuMaxFunctionBytes = 4096;
static const uint64_t kHFAMenuArgumentWindowBytes = 32;

static BOOL HFAExpired(NSTimeInterval deadline) {
    return [[NSDate date] timeIntervalSince1970] > deadline;
}

static NSString *HFASymbolString(const char *bytes, uint32_t available) {
    if (!bytes || !available) return nil;
    const void *end = memchr(bytes, 0, available);
    if (!end) return nil;
    NSUInteger length = (const char *)end - bytes;
    if (!length || length > 4096) return nil;
    return [[[NSString alloc] initWithBytes:bytes
                                    length:length
                                  encoding:NSUTF8StringEncoding] autorelease];
}

static NSString *HFAPrimitiveKind(NSString *name) {
    if (!name.length) return nil;
    if ([name containsString:@"MemoryPatch13createWithHex"]) return @"createWithHex";
    if ([name containsString:@"MemoryPatch15createWithBytes"]) return @"createWithBytes";
    if ([name containsString:@"MemoryPatch13createWithAsm"]) return @"createWithAsm";
    if ([name containsString:@"MemoryPatch6Modify"]) return @"Modify";
    if ([name containsString:@"MemoryPatch7Restore"]) return @"Restore";
    if ([name isEqualToString:@"_CodePatch"] || [name hasSuffix:@"CodePatch"]) return @"CodePatch";
    return nil;
}

static BOOL HFAMenuEntryLike(NSString *name) {
    if (!name.length) return NO;
    return [name containsString:@"setupModMenu"] ||
           [name containsString:@"offset:patch:"] ||
           [name containsString:@"machoPath"] ||
           [name containsString:@"initialValue"] ||
           [name containsString:@"ModMenu"];
}

static NSString *HFADispatcherSelector(NSString *name) {
    if (!name.length) return nil;
    NSRange r = [name rangeOfString:@"objc_msgSend$"];
    if (r.location == NSNotFound) return nil;
    NSUInteger start = NSMaxRange(r);
    if (start >= name.length) return nil;
    return [name substringFromIndex:start];
}

static int64_t HFASignExtend26(uint32_t value) {
    int64_t signedValue = value & 0x03ffffffU;
    if (signedValue & 0x02000000LL) signedValue |= ~0x03ffffffLL;
    return signedValue;
}

static NSDictionary *HFAMovWideImmediateEvidence(uint32_t instruction, uint64_t rva) {
    // ARM64 MOVZ (32/64-bit). This is candidate evidence only; no ABI ownership is claimed.
    if ((instruction & 0x7f800000U) != 0x52800000U) return nil;
    unsigned reg = instruction & 0x1fU;
    unsigned hw = (instruction >> 21) & 0x3U;
    uint64_t imm16 = (instruction >> 5) & 0xffffU;
    uint64_t value = imm16 << (hw * 16U);
    return @{ @"kind": @"movz-immediate-candidate",
              @"instructionRVA": @(rva), @"register": @(reg),
              @"value": @(value), @"valueHex": [NSString stringWithFormat:@"0x%llX", value],
              @"argumentBinding": @"unproven" };
}

NSDictionary *HFAMapAnalyzeMenuBinary(const struct mach_header_64 *header,
                                      intptr_t slide,
                                      NSTimeInterval deadline) {
    if (!header || header->magic != MH_MAGIC_64 || header->ncmds > 4096 ||
        header->sizeofcmds > 4U * 1024U * 1024U) return @{};

    const struct symtab_command *symtab = NULL;
    const struct segment_command_64 *linkedit = NULL;
    uint64_t textVMAddr = 0, textSize = 0;
    uint8_t textSectionIndex = 0;
    uint8_t sectionOrdinal = 1;

    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *commandEnd = cursor + header->sizeofcmds;
    for (uint32_t commandIndex = 0; commandIndex < header->ncmds; ++commandIndex) {
        if (HFAExpired(deadline)) break;
        if (cursor + sizeof(struct load_command) > commandEnd) return @{};
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > commandEnd) return @{};
        if (lc->cmd == LC_SYMTAB && lc->cmdsize >= sizeof(struct symtab_command))
            symtab = (const struct symtab_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (!strncmp(seg->segname, SEG_LINKEDIT, 16)) linkedit = seg;
            if (sizeof(*seg) + (uint64_t)seg->nsects * sizeof(struct section_64) > lc->cmdsize)
                return @{};
            const struct section_64 *sects = (const struct section_64 *)(seg + 1);
            for (uint32_t i = 0; i < seg->nsects; ++i, ++sectionOrdinal) {
                if (!strncmp(sects[i].segname, SEG_TEXT, 16) &&
                    !strncmp(sects[i].sectname, SECT_TEXT, 16)) {
                    textVMAddr = sects[i].addr;
                    textSize = sects[i].size;
                    textSectionIndex = sectionOrdinal;
                }
            }
        }
        cursor += lc->cmdsize;
    }

    if (!symtab || !linkedit || !textVMAddr || !textSize || !textSectionIndex ||
        !symtab->nsyms || symtab->nsyms > kHFAMenuMaxSymbols) {
        return @{ @"schema": @"com.hfa.menu-callgraph/v2",
                  @"status": @"symbol-table-unavailable",
                  @"analysisOnly": @YES, @"canonicalEligible": @NO };
    }

    uint64_t linkeditEnd = linkedit->fileoff + linkedit->filesize;
    uint64_t symbolsEnd = (uint64_t)symtab->symoff +
                          (uint64_t)symtab->nsyms * sizeof(struct nlist_64);
    uint64_t stringsEnd = (uint64_t)symtab->stroff + symtab->strsize;
    if (linkeditEnd < linkedit->fileoff || symbolsEnd < symtab->symoff ||
        stringsEnd < symtab->stroff || symtab->symoff < linkedit->fileoff ||
        symtab->stroff < linkedit->fileoff || symbolsEnd > linkeditEnd ||
        stringsEnd > linkeditEnd) {
        return @{ @"schema": @"com.hfa.menu-callgraph/v2",
                  @"status": @"invalid-linkedit-bounds",
                  @"analysisOnly": @YES, @"canonicalEligible": @NO };
    }

    intptr_t linkeditBase = slide + (intptr_t)linkedit->vmaddr - (intptr_t)linkedit->fileoff;
    const struct nlist_64 *symbols =
        (const struct nlist_64 *)(uintptr_t)(linkeditBase + symtab->symoff);
    const char *strings = (const char *)(uintptr_t)(linkeditBase + symtab->stroff);

    NSMutableArray *functions = [NSMutableArray array];
    NSMutableArray *primitiveSymbols = [NSMutableArray array];
    NSMutableArray *entrySymbols = [NSMutableArray array];
    NSMutableArray *dispatcherSymbols = [NSMutableArray array];
    NSMutableDictionary *primitiveByAddress = [NSMutableDictionary dictionary];
    uint64_t textEnd = textVMAddr + textSize;
    BOOL truncatedFunctions = NO, dispatcherTruncated = NO;

    for (uint32_t i = 0; i < symtab->nsyms; ++i) {
        if (HFAExpired(deadline)) break;
        const struct nlist_64 *item = &symbols[i];
        if ((item->n_type & N_STAB) || item->n_un.n_strx >= symtab->strsize) continue;
        NSString *name = HFASymbolString(strings + item->n_un.n_strx,
                                         symtab->strsize - item->n_un.n_strx);
        if (!name.length) continue;

        NSString *selector = HFADispatcherSelector(name);
        if (selector.length) {
            if (dispatcherSymbols.count < kHFAMenuMaxDispatcherSymbols)
                [dispatcherSymbols addObject:@{ @"symbol": name, @"selector": selector }];
            else
                dispatcherTruncated = YES;
        }

        if ((item->n_type & N_TYPE) != N_SECT || item->n_sect != textSectionIndex ||
            !item->n_value || item->n_value < textVMAddr || item->n_value >= textEnd) continue;

        uint64_t rva = item->n_value;
        uint64_t runtimeAddress = item->n_value + slide;
        NSDictionary *symbolRecord = @{ @"name": name, @"rva": @(rva),
                                         @"runtimeAddress": @(runtimeAddress) };
        if (functions.count < kHFAMenuMaxFunctions)
            [functions addObject:symbolRecord];
        else
            truncatedFunctions = YES;

        NSString *kind = HFAPrimitiveKind(name);
        if (kind.length && primitiveSymbols.count < kHFAMenuMaxPrimitiveSymbols) {
            NSDictionary *primitive = @{ @"name": name, @"kind": kind,
                                          @"rva": @(rva) };
            [primitiveSymbols addObject:primitive];
            primitiveByAddress[@(runtimeAddress)] = primitive;
        }
        if (HFAMenuEntryLike(name) && entrySymbols.count < kHFAMenuMaxEntrySymbols)
            [entrySymbols addObject:@{ @"name": name, @"rva": @(rva) }];
    }

    [functions sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        uint64_t x = [a[@"rva"] unsignedLongLongValue];
        uint64_t y = [b[@"rva"] unsignedLongLongValue];
        if (x == y) return NSOrderedSame;
        return x < y ? NSOrderedAscending : NSOrderedDescending;
    }];

    NSMutableArray *edges = [NSMutableArray array];
    NSUInteger scannedFunctions = 0;
    uint64_t scannedTextBytes = 0;
    for (NSUInteger i = 0; i < functions.count && edges.count < kHFAMenuMaxCallEdges; ++i) {
        if (HFAExpired(deadline)) break;
        NSDictionary *caller = functions[i];
        uint64_t startRVA = [caller[@"rva"] unsignedLongLongValue];
        uint64_t endRVA = textEnd;
        if (i + 1 < functions.count) {
            uint64_t next = [functions[i + 1][@"rva"] unsignedLongLongValue];
            if (next > startRVA) endRVA = MIN(endRVA, next);
        }
        if (endRVA <= startRVA) continue;
        uint64_t span = MIN(endRVA - startRVA, kHFAMenuMaxFunctionBytes);
        span &= ~3ULL;
        if (!span) continue;
        ++scannedFunctions;
        scannedTextBytes += span;
        const uint32_t *instructions = (const uint32_t *)(uintptr_t)(startRVA + slide);
        for (uint64_t offset = 0; offset < span; offset += 4) {
            uint32_t instruction = instructions[offset / 4];
            if ((instruction & 0xfc000000U) != 0x94000000U) continue;
            int64_t displacement = HFASignExtend26(instruction & 0x03ffffffU) << 2;
            uint64_t callsiteRuntime = startRVA + slide + offset;
            uint64_t targetRuntime = (uint64_t)((int64_t)callsiteRuntime + displacement);
            NSDictionary *primitive = primitiveByAddress[@(targetRuntime)];
            if (!primitive) continue;

            NSMutableArray *argumentEvidence = [NSMutableArray array];
            uint64_t windowStart = offset > kHFAMenuArgumentWindowBytes ?
                offset - kHFAMenuArgumentWindowBytes : 0;
            for (uint64_t evidenceOffset = windowStart;
                 evidenceOffset < offset && argumentEvidence.count < kHFAMenuMaxArgumentEvidence;
                 evidenceOffset += 4) {
                NSDictionary *ev = HFAMovWideImmediateEvidence(instructions[evidenceOffset / 4],
                                                               startRVA + evidenceOffset);
                if (ev) [argumentEvidence addObject:ev];
            }

            [edges addObject:@{
                @"callerSymbol": caller[@"name"] ?: @"?",
                @"callerRVA": @(startRVA),
                @"callsiteRVA": @(startRVA + offset),
                @"primitive": primitive[@"kind"] ?: @"?",
                @"primitiveSymbol": primitive[@"name"] ?: @"?",
                @"primitiveRVA": primitive[@"rva"] ?: @0,
                @"edgeType": @"arm64-direct-bl",
                @"argumentEvidence": argumentEvidence,
                @"argumentEvidencePolicy": @"candidate-only-no-abi-binding"
            }];
            if (edges.count >= kHFAMenuMaxCallEdges) break;
        }
    }

    NSString *status = primitiveSymbols.count ?
        (edges.count ? @"direct-call-edges-found" : @"primitives-found-no-direct-call-edges") :
        @"no-known-patch-primitives";
    return @{
        @"schema": @"com.hfa.menu-callgraph/v2",
        @"status": status,
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"symbolCount": @(symtab->nsyms),
        @"functionSymbolsInspected": @(functions.count),
        @"functionInventoryTruncated": @(truncatedFunctions),
        @"scannedFunctions": @(scannedFunctions),
        @"scannedTextBytes": @(scannedTextBytes),
        @"primitiveSymbols": primitiveSymbols,
        @"menuEntrySymbols": entrySymbols,
        @"dispatcherSymbols": dispatcherSymbols,
        @"dispatcherInventoryTruncated": @(dispatcherTruncated),
        @"directPatchCallEdges": edges,
        @"directPatchCallerCount": @([[NSSet setWithArray:[edges valueForKey:@"callerSymbol"]] count]),
        @"addressSemantics": @"unslid-mach-o-vmaddr-rva",
        @"argumentSemantics": @"near-callsite-immediate-candidates-not-proven-arguments"
    };
}

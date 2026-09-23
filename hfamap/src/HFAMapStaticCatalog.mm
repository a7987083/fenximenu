#import "HFAMapStaticCatalog.h"

#import <CommonCrypto/CommonDigest.h>
#import <mach-o/dyld.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <libkern/OSByteOrder.h>

#include <stdint.h>
#include <string.h>
#include <vector>
#include <algorithm>

static const NSUInteger kHFAStaticMaxDocumentDylibs = 128;
static const NSUInteger kHFAStaticMaxDirectoryDepth = 4;
static const NSUInteger kHFAStaticMaxFunctions = 65536;
static const NSUInteger kHFAStaticMaxFunctionBytes = 0x3000;
static const NSUInteger kHFAStaticMaxStringsPerFunction = 32;
static const NSUInteger kHFAStaticMaxCatalogRecords = 4096;

static NSDictionary *gHFAStaticCatalog = nil;

struct HFAStaticSegment {
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
};

struct HFAStaticSlice {
    const uint8_t *bytes;
    uint64_t size;
    uint64_t fileBase;
};

struct HFAStaticImage {
    HFAStaticSlice slice;
    uint64_t imageBaseVM;
    uint64_t textVM;
    uint64_t textSize;
    uint64_t functionStartsOff;
    uint64_t functionStartsSize;
    NSString *uuid;
    std::vector<HFAStaticSegment> segments;
};

static NSError *HFAStaticError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:@"com.hfa.static-catalog" code:code
                            userInfo:@{NSLocalizedDescriptionKey: message ?: @"static catalog error"}];
}

static uint32_t HFAReadU32(const void *p) {
    uint32_t v = 0; memcpy(&v, p, sizeof(v)); return v;
}

static BOOL HFAStaticSelectSlice(NSData *data, HFAStaticSlice *outSlice, NSError **error) {
    if (!data.length || data.length < sizeof(uint32_t)) {
        if (error) *error = HFAStaticError(1, @"empty-or-truncated-file");
        return NO;
    }
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    uint32_t magic = HFAReadU32(bytes);
    if (magic == MH_MAGIC_64) {
        if (outSlice) *outSlice = { bytes, (uint64_t)data.length, 0 };
        return YES;
    }

    uint32_t raw = magic;
    BOOL fatBig = raw == FAT_CIGAM || raw == FAT_CIGAM_64;
    BOOL fatLittle = raw == FAT_MAGIC || raw == FAT_MAGIC_64;
    if (!fatBig && !fatLittle) {
        if (error) *error = HFAStaticError(2, @"unsupported-mach-o-magic");
        return NO;
    }

    BOOL is64 = raw == FAT_MAGIC_64 || raw == FAT_CIGAM_64;
    if (data.length < sizeof(struct fat_header)) {
        if (error) *error = HFAStaticError(3, @"truncated-fat-header");
        return NO;
    }
    const struct fat_header *fh = (const struct fat_header *)bytes;
    uint32_t nfat = fatBig ? OSSwapBigToHostInt32(fh->nfat_arch) : OSSwapLittleToHostInt32(fh->nfat_arch);
    if (!nfat || nfat > 64) {
        if (error) *error = HFAStaticError(4, @"invalid-fat-arch-count");
        return NO;
    }

    uint64_t cursor = sizeof(struct fat_header);
    for (uint32_t i = 0; i < nfat; ++i) {
        cpu_type_t cputype = 0;
        uint64_t offset = 0, size = 0;
        if (is64) {
            if (cursor + sizeof(struct fat_arch_64) > data.length) break;
            const struct fat_arch_64 *arch = (const struct fat_arch_64 *)(bytes + cursor);
            cputype = fatBig ? (cpu_type_t)OSSwapBigToHostInt32((uint32_t)arch->cputype) : arch->cputype;
            offset = fatBig ? OSSwapBigToHostInt64(arch->offset) : arch->offset;
            size = fatBig ? OSSwapBigToHostInt64(arch->size) : arch->size;
            cursor += sizeof(*arch);
        } else {
            if (cursor + sizeof(struct fat_arch) > data.length) break;
            const struct fat_arch *arch = (const struct fat_arch *)(bytes + cursor);
            cputype = fatBig ? (cpu_type_t)OSSwapBigToHostInt32((uint32_t)arch->cputype) : arch->cputype;
            offset = fatBig ? OSSwapBigToHostInt32(arch->offset) : arch->offset;
            size = fatBig ? OSSwapBigToHostInt32(arch->size) : arch->size;
            cursor += sizeof(*arch);
        }
        if (cputype != CPU_TYPE_ARM64) continue;
        if (!size || offset > data.length || size > data.length - offset) continue;
        if (HFAReadU32(bytes + offset) != MH_MAGIC_64) continue;
        if (outSlice) *outSlice = { bytes + offset, size, offset };
        return YES;
    }
    if (error) *error = HFAStaticError(5, @"arm64-slice-not-found");
    return NO;
}

static NSString *HFAStaticUUIDString(const uint8_t uuid[16]) {
    return [NSString stringWithFormat:
        @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        uuid[0],uuid[1],uuid[2],uuid[3],uuid[4],uuid[5],uuid[6],uuid[7],
        uuid[8],uuid[9],uuid[10],uuid[11],uuid[12],uuid[13],uuid[14],uuid[15]];
}

static BOOL HFAStaticParseImage(HFAStaticSlice slice, HFAStaticImage *image, NSError **error) {
    if (slice.size < sizeof(struct mach_header_64)) {
        if (error) *error = HFAStaticError(10, @"truncated-mach-header");
        return NO;
    }
    const struct mach_header_64 *mh = (const struct mach_header_64 *)slice.bytes;
    if (mh->magic != MH_MAGIC_64 || mh->cputype != CPU_TYPE_ARM64 || mh->ncmds > 8192 || mh->sizeofcmds > slice.size) {
        if (error) *error = HFAStaticError(11, @"invalid-arm64-mach-header");
        return NO;
    }
    uint64_t commandsEnd = sizeof(*mh) + mh->sizeofcmds;
    if (commandsEnd > slice.size) {
        if (error) *error = HFAStaticError(12, @"truncated-load-commands");
        return NO;
    }

    HFAStaticImage parsed = {};
    parsed.slice = slice;
    parsed.imageBaseVM = UINT64_MAX;
    const uint8_t *cursor = slice.bytes + sizeof(*mh);
    const uint8_t *end = slice.bytes + commandsEnd;
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (cursor + sizeof(struct load_command) > end) break;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) {
            if (error) *error = HFAStaticError(13, @"invalid-load-command");
            return NO;
        }
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (seg->fileoff <= slice.size && seg->filesize <= slice.size - seg->fileoff) {
                parsed.segments.push_back({seg->vmaddr, seg->vmsize, seg->fileoff, seg->filesize});
                if (seg->filesize && seg->fileoff == 0) parsed.imageBaseVM = std::min(parsed.imageBaseVM, seg->vmaddr);
            }
            const uint8_t *sectionCursor = cursor + sizeof(*seg);
            for (uint32_t s = 0; s < seg->nsects; ++s) {
                if (sectionCursor + sizeof(struct section_64) > cursor + lc->cmdsize) break;
                const struct section_64 *section = (const struct section_64 *)sectionCursor;
                if (strncmp(section->sectname, "__text", 16) == 0) {
                    parsed.textVM = section->addr;
                    parsed.textSize = section->size;
                }
                sectionCursor += sizeof(*section);
            }
        } else if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            parsed.uuid = HFAStaticUUIDString(((const struct uuid_command *)cursor)->uuid);
        } else if (lc->cmd == LC_FUNCTION_STARTS && lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *cmd = (const struct linkedit_data_command *)cursor;
            parsed.functionStartsOff = cmd->dataoff;
            parsed.functionStartsSize = cmd->datasize;
        }
        cursor += lc->cmdsize;
    }
    if (parsed.imageBaseVM == UINT64_MAX) parsed.imageBaseVM = 0;
    if (!parsed.textVM || !parsed.textSize) {
        if (error) *error = HFAStaticError(14, @"missing-text-section");
        return NO;
    }
    if (image) *image = parsed;
    return YES;
}

static BOOL HFAStaticVMToFile(const HFAStaticImage &image, uint64_t vm, uint64_t size, uint64_t *fileOff) {
    for (const HFAStaticSegment &seg : image.segments) {
        if (vm < seg.vmaddr) continue;
        uint64_t delta = vm - seg.vmaddr;
        if (delta > seg.filesize || size > seg.filesize - delta) continue;
        uint64_t off = seg.fileoff + delta;
        if (off > image.slice.size || size > image.slice.size - off) continue;
        if (fileOff) *fileOff = off;
        return YES;
    }
    return NO;
}

static NSString *HFAStaticCStringAtVM(const HFAStaticImage &image, uint64_t vm) {
    uint64_t off = 0;
    if (!HFAStaticVMToFile(image, vm, 1, &off)) return nil;
    const char *p = (const char *)(image.slice.bytes + off);
    uint64_t available = image.slice.size - off;
    size_t max = (size_t)MIN((uint64_t)192, available);
    size_t n = strnlen(p, max);
    if (!n || n == max || n > 160) return nil;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)p[i];
        if (c < 0x20 || c > 0x7e) return nil;
    }
    return [NSString stringWithUTF8String:p];
}

static int64_t HFAStaticSignExtend(uint64_t value, unsigned bits) {
    uint64_t sign = 1ULL << (bits - 1U);
    return (int64_t)((value ^ sign) - sign);
}

static NSString *HFAStaticStringRole(NSString *value) {
    if (!value.length) return @"unknown";
    NSString *lower = value.lowercaseString;
    if ([lower hasSuffix:@".dll"] || [lower hasSuffix:@".exe"]) return @"assembly-like";
    if ([value containsString:@"."] && ![value containsString:@" "] && value.length <= 160)
        return @"qualified-type-like";
    NSCharacterSet *identifier = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_`<>$@"];
    if (value.length <= 128 && [[value stringByTrimmingCharactersInSet:identifier] length] == 0)
        return @"identifier-like";
    return @"literal";
}

static std::vector<uint64_t> HFAStaticFunctionStarts(const HFAStaticImage &image) {
    std::vector<uint64_t> starts;
    if (!image.functionStartsOff || !image.functionStartsSize ||
        image.functionStartsOff > image.slice.size ||
        image.functionStartsSize > image.slice.size - image.functionStartsOff) return starts;
    const uint8_t *p = image.slice.bytes + image.functionStartsOff;
    const uint8_t *end = p + image.functionStartsSize;
    uint64_t current = image.imageBaseVM;
    while (p < end && starts.size() < kHFAStaticMaxFunctions) {
        uint64_t value = 0; unsigned shift = 0;
        while (p < end && shift < 64) {
            uint8_t byte = *p++;
            value |= (uint64_t)(byte & 0x7f) << shift;
            if (!(byte & 0x80)) break;
            shift += 7;
        }
        if (!value) break;
        current += value;
        if (current >= image.textVM && current < image.textVM + image.textSize) starts.push_back(current);
    }
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
    return starts;
}

static NSDictionary *HFAStaticAnalyzeFunction(const HFAStaticImage &image, uint64_t startVM, uint64_t endVM) {
    if (endVM <= startVM) return nil;
    uint64_t length = MIN(endVM - startVM, (uint64_t)kHFAStaticMaxFunctionBytes);
    uint64_t fileOff = 0;
    if (!HFAStaticVMToFile(image, startVM, MIN(length, 4ULL), &fileOff)) return nil;

    struct Reg { BOOL known; uint64_t value; } regs[31] = {};
    NSMutableArray *strings = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    NSUInteger directCalls = 0, indirectCalls = 0;
    BOOL sawReturn = NO;

    for (uint64_t delta = 0; delta + 4 <= length; delta += 4) {
        uint64_t pc = startVM + delta;
        uint64_t insnOff = 0;
        if (!HFAStaticVMToFile(image, pc, 4, &insnOff)) break;
        uint32_t insn = HFAReadU32(image.slice.bytes + insnOff);
        if (insn == 0xD65F03C0U) { sawReturn = YES; break; }

        auto appendVMString = ^(unsigned reg, uint64_t vm) {
            if (strings.count >= kHFAStaticMaxStringsPerFunction) return;
            NSString *text = HFAStaticCStringAtVM(image, vm);
            if (!text.length) return;
            NSString *key = [NSString stringWithFormat:@"%@:%llu", text, (unsigned long long)delta];
            if ([seen containsObject:key]) return;
            [seen addObject:key];
            [strings addObject:@{ @"value": text,
                                  @"role": HFAStaticStringRole(text),
                                  @"sourceRVA": @(pc - image.imageBaseVM),
                                  @"sourceRVAHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(pc - image.imageBaseVM)],
                                  @"register": [NSString stringWithFormat:@"x%u", reg] }];
        };

        if ((insn & 0x9F000000U) == 0x90000000U) {
            unsigned rd = insn & 31U;
            int64_t imm = HFAStaticSignExtend((((uint64_t)(insn >> 5) & 0x7ffffULL) << 2) |
                                               ((insn >> 29) & 3U), 21) << 12;
            if (rd < 31) regs[rd] = { YES, (pc & ~0xfffULL) + imm };
            continue;
        }
        if ((insn & 0x9F000000U) == 0x10000000U) {
            unsigned rd = insn & 31U;
            int64_t imm = HFAStaticSignExtend((((uint64_t)(insn >> 5) & 0x7ffffULL) << 2) |
                                               ((insn >> 29) & 3U), 21);
            if (rd < 31) { regs[rd] = { YES, pc + imm }; appendVMString(rd, regs[rd].value); }
            continue;
        }
        if ((insn & 0xFFC00000U) == 0x91000000U) {
            unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;
            uint64_t imm = (insn >> 10) & 0xfffU; if (insn & (1U << 22)) imm <<= 12;
            if (rd < 31 && rn < 31 && regs[rn].known) {
                regs[rd] = { YES, regs[rn].value + imm }; appendVMString(rd, regs[rd].value);
            }
            continue;
        }
        if ((insn & 0xFF000000U) == 0x58000000U) {
            unsigned rt = insn & 31U;
            int64_t off = HFAStaticSignExtend((insn >> 5) & 0x7ffffU, 19) << 2;
            uint64_t literalVM = (uint64_t)((int64_t)pc + off), literalOff = 0, loaded = 0;
            if (rt < 31 && HFAStaticVMToFile(image, literalVM, 8, &literalOff)) {
                memcpy(&loaded, image.slice.bytes + literalOff, sizeof(loaded));
                regs[rt] = { YES, loaded }; appendVMString(rt, loaded);
            }
            continue;
        }
        if ((insn & 0xFFE0FFE0U) == 0xAA0003E0U) {
            unsigned rd = insn & 31U, rm = (insn >> 16) & 31U;
            if (rd < 31 && rm < 31) regs[rd] = regs[rm];
            continue;
        }
        if ((insn & 0xFC000000U) == 0x94000000U) { ++directCalls; continue; }
        if ((insn & 0xFFFFFC1FU) == 0xD63F0000U || (insn & 0xFFFFFC1FU) == 0xD61F0000U) {
            ++indirectCalls;
            if ((insn & 0xFFFFFC1FU) == 0xD61F0000U) break;
        }
    }

    NSUInteger assemblyLike = 0, identifierLike = 0, qualifiedLike = 0;
    NSString *assembly = @"", *qualified = @"";
    NSMutableArray *identifiers = [NSMutableArray array];
    for (NSDictionary *entry in strings) {
        NSString *role = entry[@"role"];
        NSString *value = entry[@"value"] ?: @"";
        if ([role isEqualToString:@"assembly-like"]) { ++assemblyLike; if (!assembly.length) assembly = value; }
        else if ([role isEqualToString:@"qualified-type-like"]) { ++qualifiedLike; if (!qualified.length) qualified = value; }
        else if ([role isEqualToString:@"identifier-like"]) { ++identifierLike; if (identifiers.count < 16) [identifiers addObject:value]; }
    }
    BOOL runtimeMethod = assemblyLike > 0 && identifierLike >= 2 && indirectCalls > 0;
    if (!runtimeMethod) return nil;

    NSString *classCandidate = identifiers.count ? identifiers.firstObject : @"";
    NSString *methodCandidate = identifiers.count ? identifiers.lastObject : @"";
    return @{ @"schema": @"com.hfa.static-runtime-method/v1",
              @"classification": @"runtime-method-candidate",
              @"callbackRVA": @(startVM - image.imageBaseVM),
              @"callbackRVAHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(startVM - image.imageBaseVM)],
              @"functionVM": @(startVM),
              @"functionVMHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)startVM],
              @"assemblyCandidate": assembly,
              @"qualifiedTypeCandidate": qualified,
              @"classCandidate": classCandidate,
              @"methodCandidate": methodCandidate,
              @"identifierCandidates": identifiers,
              @"stringEvidence": strings,
              @"assemblyLikeCount": @(assemblyLike),
              @"identifierLikeCount": @(identifierLike),
              @"qualifiedTypeLikeCount": @(qualifiedLike),
              @"directCallCount": @(directCalls),
              @"indirectCallCount": @(indirectCalls),
              @"sawReturn": @(sawReturn),
              @"canonicalEligible": @NO,
              @"evidencePolicy": @"offline-arm64-function-starts-plus-string-xref-plus-indirect-call" };
}

static NSString *HFAStaticSHA256(NSData *data) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *s = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i) [s appendFormat:@"%02x", digest[i]];
    return s;
}

NSArray<NSDictionary *> *HFAMapStaticCatalogListDocumentDylibs(void) {
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!documents.length) return @[];
    NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:documents]
        includingPropertiesForKeys:@[NSURLIsRegularFileKey, NSURLFileSizeKey]
        options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:^BOOL(NSURL *url, NSError *error) { return YES; }];
    NSMutableArray *results = [NSMutableArray array];
    for (NSURL *url in enumerator) {
        if (results.count >= kHFAStaticMaxDocumentDylibs) break;
        NSString *relative = [url.path substringFromIndex:MIN(documents.length + 1, url.path.length)];
        if (relative.pathComponents.count > kHFAStaticMaxDirectoryDepth + 1) { [enumerator skipDescendants]; continue; }
        NSNumber *regular = nil, *size = nil;
        [url getResourceValue:&regular forKey:NSURLIsRegularFileKey error:nil];
        if (![regular boolValue] || ![url.pathExtension.lowercaseString isEqualToString:@"dylib"]) continue;
        [url getResourceValue:&size forKey:NSURLFileSizeKey error:nil];
        [results addObject:@{ @"name": url.lastPathComponent ?: @"?",
                              @"path": url.path ?: @"",
                              @"relativePath": relative ?: @"",
                              @"size": size ?: @0 }];
    }
    [results sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"relativePath"] compare:b[@"relativePath"] options:NSCaseInsensitiveSearch];
    }];
    return results;
}

NSDictionary *HFAMapStaticCatalogAnalyzeFile(NSString *path, NSError **error) {
    if (!path.length || ![path.pathExtension.lowercaseString isEqualToString:@"dylib"]) {
        if (error) *error = HFAStaticError(20, @"expected-dylib-path");
        return nil;
    }
    NSError *readError = nil;
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:&readError];
    if (!data) { if (error) *error = readError ?: HFAStaticError(21, @"file-read-failed"); return nil; }

    HFAStaticSlice slice = {};
    if (!HFAStaticSelectSlice(data, &slice, error)) return nil;
    HFAStaticImage image = {};
    if (!HFAStaticParseImage(slice, &image, error)) return nil;

    std::vector<uint64_t> starts = HFAStaticFunctionStarts(image);
    NSMutableArray *methods = [NSMutableArray array];
    for (size_t i = 0; i < starts.size() && methods.count < kHFAStaticMaxCatalogRecords; ++i) {
        uint64_t endVM = (i + 1 < starts.size()) ? starts[i + 1] : (image.textVM + image.textSize);
        NSDictionary *record = HFAStaticAnalyzeFunction(image, starts[i], endVM);
        if (record) [methods addObject:record];
    }

    NSDictionary *source = @{ @"fileName": path.lastPathComponent ?: @"?",
                              @"path": path,
                              @"uuid": image.uuid ?: @"unknown",
                              @"sha256": HFAStaticSHA256(data),
                              @"fileSize": @(data.length),
                              @"sliceOffset": @(slice.fileBase),
                              @"sliceSize": @(slice.size),
                              @"arch": @"arm64",
                              @"imageBaseVM": @(image.imageBaseVM),
                              @"imageBaseVMHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)image.imageBaseVM] };
    return @{ @"schema": @"com.hfa.static-catalog/v1",
              @"status": @"complete",
              @"source": source,
              @"runtimeMethods": methods,
              @"runtimeMethodCount": @(methods.count),
              @"functionStartCount": @(starts.size()),
              @"analysisMode": @"offline-file-read-only-no-dlopen",
              @"genericity": @"no-sample-name-no-sample-rva-no-known-method-input",
              @"analysisOnly": @YES,
              @"canonicalEligible": @NO };
}

static NSString *HFAStaticCatalogDirectory(void) {
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [[documents stringByAppendingPathComponent:@"HFAMap"] stringByAppendingPathComponent:@"Catalogs"];
}

BOOL HFAMapStaticCatalogRegisterAndPersist(NSDictionary *catalog, NSError **error) {
    if (![catalog[@"schema"] isEqualToString:@"com.hfa.static-catalog/v1"] || ![catalog[@"status"] isEqualToString:@"complete"]) {
        if (error) *error = HFAStaticError(30, @"invalid-static-catalog");
        return NO;
    }
    NSString *directory = HFAStaticCatalogDirectory();
    NSError *mkdirError = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:&mkdirError]) {
        if (error) *error = mkdirError; return NO;
    }
    NSString *uuid = catalog[@"source"][@"uuid"] ?: @"unknown";
    NSString *sha = catalog[@"source"][@"sha256"] ?: @"catalog";
    NSString *key = ![uuid isEqualToString:@"unknown"] ? uuid : [sha substringToIndex:MIN((NSUInteger)16, sha.length)];
    NSString *path = [directory stringByAppendingPathComponent:[key stringByAppendingPathExtension:@"json"]];
    NSError *jsonError = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:catalog options:NSJSONWritingPrettyPrinted error:&jsonError];
    if (!json || ![json writeToFile:path options:NSDataWritingAtomic error:&jsonError]) {
        if (error) *error = jsonError ?: HFAStaticError(31, @"catalog-write-failed"); return NO;
    }
    @synchronized(NSObject.class) {
        [gHFAStaticCatalog release];
        gHFAStaticCatalog = [catalog copy];
    }
    return YES;
}

NSDictionary *HFAMapStaticCatalogCurrent(void) {
    @synchronized(NSObject.class) { return [[gHFAStaticCatalog retain] autorelease]; }
}

static NSString *HFAStaticLoadedUUID(NSString *imageName) {
    if (!imageName.length) return nil;
    for (uint32_t i = 0, n = _dyld_image_count(); i < n && i < 4096; ++i) {
        const char *name = _dyld_get_image_name(i);
        NSString *path = name ? [NSString stringWithUTF8String:name] : @"";
        if (![path.lastPathComponent isEqualToString:imageName]) continue;
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64 || mh->ncmds > 8192) return nil;
        const uint8_t *cursor = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; ++c) {
            const struct load_command *lc = (const struct load_command *)cursor;
            if (lc->cmdsize < sizeof(*lc)) break;
            if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command))
                return HFAStaticUUIDString(((const struct uuid_command *)cursor)->uuid);
            cursor += lc->cmdsize;
        }
    }
    return nil;
}

NSDictionary *HFAMapStaticCatalogLookup(NSString *loadedImage, uint64_t rva) {
    NSDictionary *catalog = HFAMapStaticCatalogCurrent();
    if (!catalog) return nil;
    NSDictionary *source = catalog[@"source"];
    if (![[source[@"fileName"] lastPathComponent] isEqualToString:loadedImage.lastPathComponent]) return nil;
    NSString *catalogUUID = source[@"uuid"];
    NSString *loadedUUID = HFAStaticLoadedUUID(loadedImage.lastPathComponent);
    if (catalogUUID.length && ![catalogUUID isEqualToString:@"unknown"] && loadedUUID.length &&
        ![catalogUUID isEqualToString:loadedUUID]) return nil;
    for (NSDictionary *record in catalog[@"runtimeMethods"] ?: @[]) {
        if ([record[@"callbackRVA"] unsignedLongLongValue] == rva)
            return @{ @"status": @"matched",
                      @"matchType": @"same-session-static-catalog-rva",
                      @"source": source ?: @{},
                      @"record": record };
    }
    return nil;
}

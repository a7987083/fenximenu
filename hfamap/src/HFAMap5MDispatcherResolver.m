#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

static NSMutableDictionary<NSString *, NSMutableDictionary *> *gHFA5MFeatures;
static NSMutableDictionary<NSString *, NSDictionary *> *gHFA5MDispatcherCache;

static void HFA5MLog(NSString *line) {
    if (!line.length) return;
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];
    FILE *f = fopen(path.fileSystemRepresentation, "a");
    if (!f) return;
    fprintf(f, "%s\n", line.UTF8String ?: "[5M-DISPATCH]");
    fflush(f);
    fclose(f);
}

static const char *HFA5MBase(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static uintptr_t HFA5MStripCodePointer(const void *p) {
    uintptr_t value = (uintptr_t)p;
#if __has_feature(ptrauth_calls)
    value = (uintptr_t)ptrauth_strip((void *)value, ptrauth_key_function_pointer);
#endif
    return value;
}

static NSDictionary *HFA5MAddressInfo(const void *address) {
    uintptr_t value = HFA5MStripCodePointer(address);
    if (!value) return nil;
    Dl_info info = {0};
    if (!dladdr((void *)value, &info) || !info.dli_fbase || !info.dli_fname) return nil;
    uintptr_t base = (uintptr_t)info.dli_fbase;
    return @{ @"image": [NSString stringWithUTF8String:HFA5MBase(info.dli_fname)] ?: @"?",
              @"rva": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(value - base)] };
}

typedef struct {
    uintptr_t start;
    uintptr_t end;
} HFA5MRange;

typedef struct {
    HFA5MRange text;
    HFA5MRange selrefs;
    HFA5MRange msgrefs;
    HFA5MRange cfstrings;
    intptr_t slide;
} HFA5MImageLayout;

static BOOL HFA5MRangeContains(HFA5MRange range, uintptr_t address, size_t size) {
    if (!range.start || range.end <= range.start || address < range.start) return NO;
    if (size > UINTPTR_MAX - address) return NO;
    return address + size <= range.end;
}

static BOOL HFA5MLayoutForAddress(uintptr_t code, HFA5MImageLayout *out) {
    if (!code || !out) return NO;
    Dl_info info = {0};
    if (!dladdr((void *)code, &info) || !info.dli_fbase) return NO;
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t index = 0; index < imageCount; index++) {
        const struct mach_header *raw = _dyld_get_image_header(index);
        if ((const void *)raw != info.dli_fbase || !raw || raw->magic != MH_MAGIC_64) continue;
        HFA5MImageLayout layout = {0};
        layout.slide = _dyld_get_image_vmaddr_slide(index);
        const struct mach_header_64 *header = (const struct mach_header_64 *)raw;
        const uint8_t *cursor = (const uint8_t *)(header + 1);
        const uint8_t *commandsEnd = cursor + header->sizeofcmds;
        for (uint32_t i = 0; i < header->ncmds; i++) {
            if (cursor + sizeof(struct load_command) > commandsEnd) return NO;
            const struct load_command *lc = (const struct load_command *)cursor;
            if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > commandsEnd) return NO;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
                if (sizeof(*seg) + (uint64_t)seg->nsects * sizeof(struct section_64) > lc->cmdsize) return NO;
                const struct section_64 *sec = (const struct section_64 *)(seg + 1);
                for (uint32_t s = 0; s < seg->nsects; s++, sec++) {
                    uintptr_t start = (uintptr_t)layout.slide + (uintptr_t)sec->addr;
                    uintptr_t end = start + (uintptr_t)sec->size;
                    if (end < start) continue;
                    if (strncmp(sec->sectname, "__text", 16) == 0) layout.text = (HFA5MRange){start, end};
                    else if (strncmp(sec->sectname, "__objc_selrefs", 16) == 0) layout.selrefs = (HFA5MRange){start, end};
                    else if (strncmp(sec->sectname, "__objc_msgrefs", 16) == 0) layout.msgrefs = (HFA5MRange){start, end};
                    else if (strncmp(sec->sectname, "__cfstring", 16) == 0) layout.cfstrings = (HFA5MRange){start, end};
                }
            }
            cursor += lc->cmdsize;
        }
        *out = layout;
        return HFA5MRangeContains(layout.text, code, 4);
    }
    return NO;
}

static int64_t HFA5MSignExtend(uint64_t value, unsigned bits) {
    uint64_t sign = 1ULL << (bits - 1);
    return (int64_t)((value ^ sign) - sign);
}

static BOOL HFA5MDecodeADRP(uint32_t insn, uintptr_t pc, unsigned *rdOut, uintptr_t *pageOut) {
    if ((insn & 0x9F000000u) != 0x90000000u) return NO;
    uint64_t immlo = (insn >> 29) & 3u;
    uint64_t immhi = (insn >> 5) & 0x7FFFFu;
    int64_t pages = HFA5MSignExtend((immhi << 2) | immlo, 21);
    uintptr_t base = pc & ~(uintptr_t)0xFFF;
    if (rdOut) *rdOut = insn & 31u;
    if (pageOut) *pageOut = (uintptr_t)((int64_t)base + (pages << 12));
    return YES;
}

static BOOL HFA5MDecodeLDRX(uint32_t insn, unsigned *rtOut, unsigned *rnOut, uint64_t *offsetOut) {
    if ((insn & 0xFFC00000u) != 0xF9400000u) return NO;
    if (rtOut) *rtOut = insn & 31u;
    if (rnOut) *rnOut = (insn >> 5) & 31u;
    if (offsetOut) *offsetOut = (uint64_t)((insn >> 10) & 0xFFFu) * 8u;
    return YES;
}

static BOOL HFA5MDecodeADDX(uint32_t insn, unsigned *rdOut, unsigned *rnOut, uint64_t *offsetOut) {
    if ((insn & 0xFF000000u) != 0x91000000u) return NO;
    unsigned shift = (insn >> 22) & 1u;
    uint64_t imm = (insn >> 10) & 0xFFFu;
    if (shift) imm <<= 12;
    if (rdOut) *rdOut = insn & 31u;
    if (rnOut) *rnOut = (insn >> 5) & 31u;
    if (offsetOut) *offsetOut = imm;
    return YES;
}

static BOOL HFA5MDecodeB(uint32_t insn, uintptr_t pc, uintptr_t *targetOut) {
    if ((insn & 0xFC000000u) != 0x14000000u) return NO;
    int64_t imm = HFA5MSignExtend(insn & 0x03FFFFFFu, 26) << 2;
    if (targetOut) *targetOut = (uintptr_t)((int64_t)pc + imm);
    return YES;
}

static SEL HFA5MSelectorFromSlot(uintptr_t slot, HFA5MImageLayout layout) {
    if (!HFA5MRangeContains(layout.selrefs, slot, sizeof(uintptr_t)) &&
        !HFA5MRangeContains(layout.msgrefs, slot, sizeof(uintptr_t) * 2)) return NULL;
    SEL selector = NULL;
    memcpy(&selector, (const void *)slot, sizeof(selector));
    return selector;
}

static NSString *HFA5MConstantStringAt(uintptr_t address, HFA5MImageLayout layout) {
    if (!HFA5MRangeContains(layout.cfstrings, address, sizeof(uintptr_t) * 4)) return nil;
    @try {
        id object = (id)(void *)address;
        if (![object isKindOfClass:[NSString class]]) return nil;
        NSString *value = (NSString *)object;
        return value.length && value.length <= 512 ? value : nil;
    } @catch (__unused id exception) {
        return nil;
    }
}

static uintptr_t HFA5MMethodEnd(Class cls, uintptr_t start, HFA5MImageLayout layout) {
    uintptr_t end = layout.text.end;
    if (end > start + 0x4000) end = start + 0x4000;
    unsigned count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    for (unsigned i = 0; methods && i < count; i++) {
        uintptr_t imp = HFA5MStripCodePointer((const void *)method_getImplementation(methods[i]));
        if (imp > start && imp < end) end = imp;
    }
    free(methods);
    return end;
}

static NSString *HFA5MStringGetter(id object, const char *selectorName) {
    if (!object || !selectorName) return nil;
    SEL sel = sel_registerName(selectorName);
    Method method = class_getInstanceMethod(object_getClass(object), sel);
    if (!method) return nil;
    char *ret = method_copyReturnType(method);
    BOOL objectReturn = ret && ret[0] == '@';
    free(ret);
    if (!objectReturn) return nil;
    @try {
        id value = ((id (*)(id, SEL))objc_msgSend)(object, sel);
        return [value isKindOfClass:[NSString class]] ? value : nil;
    } @catch (__unused id exception) { return nil; }
}

typedef struct {
    void *isa;
    int flags;
    int reserved;
    void (*invoke)(void);
} HFA5MBlockLiteral;

static NSDictionary *HFA5MBlockInfo(id value, NSString *key) {
    if (!value) return nil;
    Class cls = object_getClass(value);
    const char *className = cls ? class_getName(cls) : NULL;
    if (!className || !strstr(className, "Block")) return nil;
    HFA5MBlockLiteral *literal = (HFA5MBlockLiteral *)(void *)value;
    NSDictionary *address = HFA5MAddressInfo((const void *)literal->invoke);
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"key"] = key ?: @"?";
    result[@"class"] = [NSString stringWithUTF8String:className] ?: @"?";
    if (address) [result addEntriesFromDictionary:address];
    return result;
}

static NSMutableDictionary *HFA5MFeatureRecord(NSString *identifier, BOOL create) {
    if (!identifier.length) return nil;
    if (!gHFA5MFeatures && create) gHFA5MFeatures = [NSMutableDictionary dictionary];
    NSMutableDictionary *record = gHFA5MFeatures[identifier];
    if (!record && create) {
        record = [@{ @"identifier": identifier,
                     @"actions": [NSMutableArray array],
                     @"dictionaryBlocks": [NSMutableArray array] } mutableCopy];
        gHFA5MFeatures[identifier] = record;
    }
    return record;
}

static void HFA5MAppendUnique(NSMutableArray *array, NSDictionary *value, NSArray<NSString *> *keys) {
    if (!array || !value) return;
    for (NSDictionary *existing in array) {
        BOOL same = YES;
        for (NSString *key in keys) {
            id a = existing[key] ?: [NSNull null];
            id b = value[key] ?: [NSNull null];
            if (![a isEqual:b]) { same = NO; break; }
        }
        if (same) return;
    }
    [array addObject:value];
}

static NSDictionary *HFA5MScanMethod(Class cls, SEL selector, IMP implementation) {
    uintptr_t start = HFA5MStripCodePointer((const void *)implementation);
    HFA5MImageLayout layout = {0};
    if (!start || !HFA5MLayoutForAddress(start, &layout)) return nil;
    uintptr_t end = HFA5MMethodEnd(cls, start, layout);
    if (end <= start || end - start > 0x4000) return nil;

    NSMutableOrderedSet<NSString *> *selectorNames = [NSMutableOrderedSet orderedSet];
    NSMutableArray<NSDictionary *> *notifications = [NSMutableArray array];
    const uint32_t *words = (const uint32_t *)start;
    NSUInteger count = (end - start) / sizeof(uint32_t);
    for (NSUInteger i = 0; i < count; i++) {
        unsigned adrpReg = 0;
        uintptr_t page = 0;
        uintptr_t pc = start + i * 4;
        if (!HFA5MDecodeADRP(words[i], pc, &adrpReg, &page)) continue;
        for (NSUInteger j = i + 1; j < count && j <= i + 3; j++) {
            unsigned rt = 0, rn = 0;
            uint64_t offset = 0;
            if (!HFA5MDecodeLDRX(words[j], &rt, &rn, &offset) || rt != 1 || rn != adrpReg) continue;
            uintptr_t slot = page + (uintptr_t)offset;
            SEL loaded = HFA5MSelectorFromSlot(slot, layout);
            const char *name = loaded ? sel_getName(loaded) : NULL;
            if (!name || !*name) break;
            NSString *selectorName = [NSString stringWithUTF8String:name];
            if (selectorName.length && selectorNames.count < 96) [selectorNames addObject:selectorName];
            if (strcmp(name, "postNotificationName:object:userInfo:") == 0) {
                NSUInteger upper = MIN(count, j + 8);
                for (NSUInteger k = j + 1; k < upper; k++) {
                    unsigned cfReg = 0;
                    uintptr_t cfPage = 0;
                    uintptr_t cfPC = start + k * 4;
                    if (!HFA5MDecodeADRP(words[k], cfPC, &cfReg, &cfPage)) continue;
                    for (NSUInteger q = k + 1; q < upper && q <= k + 3; q++) {
                        unsigned rd = 0, rn2 = 0;
                        uint64_t cfOffset = 0;
                        if (!HFA5MDecodeADDX(words[q], &rd, &rn2, &cfOffset) || rd != 2 || rn2 != cfReg) continue;
                        NSString *notification = HFA5MConstantStringAt(cfPage + (uintptr_t)cfOffset, layout);
                        if (notification.length) {
                            NSDictionary *entry = @{ @"name": notification,
                                                     @"selector": @"postNotificationName:object:userInfo:" };
                            HFA5MAppendUnique(notifications, entry, @[@"name", @"selector"]);
                        }
                        break;
                    }
                    if (notifications.count) break;
                }
            }
            break;
        }
    }

    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    NSDictionary *address = HFA5MAddressInfo((const void *)start);
    if (address) [result addEntriesFromDictionary:address];
    result[@"selector"] = selector ? NSStringFromSelector(selector) : @"?";
    if (selectorNames.count) result[@"calledSelectors"] = selectorNames.array;
    if (notifications.count) result[@"notifications"] = notifications;
    return result;
}

static NSDictionary *HFA5MResolveDispatcher(id target, SEL action) {
    if (!target || !action) return nil;
    Class cls = object_getClass(target);
    Method method = class_getInstanceMethod(cls, action);
    if (!method) return nil;
    IMP actionIMP = method_getImplementation(method);
    uintptr_t actionAddress = HFA5MStripCodePointer((const void *)actionIMP);
    HFA5MImageLayout layout = {0};
    if (!actionAddress || !HFA5MLayoutForAddress(actionAddress, &layout)) return nil;

    SEL dispatcherSEL = action;
    IMP dispatcherIMP = actionIMP;
    NSString *resolution = @"direct";
    if (HFA5MRangeContains(layout.text, actionAddress, 12)) {
        uint32_t words[3] = {0};
        memcpy(words, (const void *)actionAddress, sizeof(words));
        unsigned adrpReg = 0, rt = 0, rn = 0;
        uintptr_t page = 0, branchTarget = 0;
        uint64_t offset = 0;
        if (HFA5MDecodeADRP(words[0], actionAddress, &adrpReg, &page) &&
            HFA5MDecodeLDRX(words[1], &rt, &rn, &offset) && rt == 1 && rn == adrpReg &&
            HFA5MDecodeB(words[2], actionAddress + 8, &branchTarget)) {
            SEL forwarded = HFA5MSelectorFromSlot(page + (uintptr_t)offset, layout);
            Method forwardedMethod = forwarded ? class_getInstanceMethod(cls, forwarded) : NULL;
            if (forwardedMethod) {
                dispatcherSEL = forwarded;
                dispatcherIMP = method_getImplementation(forwardedMethod);
                resolution = @"arm64-tail-forwarder";
            }
        }
    }

    NSString *cacheKey = [NSString stringWithFormat:@"%s|%@", class_getName(cls) ?: "?", NSStringFromSelector(dispatcherSEL)];
    NSDictionary *scan = gHFA5MDispatcherCache[cacheKey];
    if (!scan) {
        scan = HFA5MScanMethod(cls, dispatcherSEL, dispatcherIMP) ?: @{};
        if (!gHFA5MDispatcherCache) gHFA5MDispatcherCache = [NSMutableDictionary dictionary];
        gHFA5MDispatcherCache[cacheKey] = scan;
    }

    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"resolution"] = resolution;
    NSDictionary *actionInfo = HFA5MAddressInfo((const void *)actionIMP);
    if (actionInfo) {
        NSMutableDictionary *actionRecord = [actionInfo mutableCopy];
        actionRecord[@"selector"] = NSStringFromSelector(action);
        result[@"action"] = actionRecord;
    }
    if (scan.count) result[@"dispatcher"] = scan;
    return result;
}

static NSArray *HFA5MObserverBridgesForNotification(Class cls, NSString *notification) {
    if (!cls || !notification.length) return @[];
    NSMutableArray *bridges = [NSMutableArray array];
    unsigned count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    for (unsigned i = 0; methods && i < count; i++) {
        Method method = methods[i];
        SEL sel = method_getName(method);
        IMP imp = method_getImplementation(method);
        NSDictionary *scan = HFA5MScanMethod(cls, sel, imp);
        NSArray *selectors = scan[@"calledSelectors"];
        if (![selectors containsObject:@"addObserverForName:object:queue:usingBlock:"]) continue;
        NSArray *notifications = scan[@"notifications"];
        BOOL matched = NO;
        for (NSDictionary *entry in notifications) {
            if ([entry[@"name"] isEqual:notification]) { matched = YES; break; }
        }
        if (!matched && notifications.count) continue;
        NSMutableDictionary *bridge = [scan mutableCopy];
        bridge[@"observerSelector"] = @"addObserverForName:object:queue:usingBlock:";
        HFA5MAppendUnique(bridges, bridge, @[@"selector", @"rva"]);
        if (bridges.count >= 16) break;
    }
    free(methods);
    return bridges;
}

void HFA5MDispatcherReset(void) {
    gHFA5MFeatures = [NSMutableDictionary dictionary];
    gHFA5MDispatcherCache = [NSMutableDictionary dictionary];
    HFA5MLog(@"[5M-DISPATCH-RESET]");
}

void HFA5MDispatcherObserveFeatureArray(id menuTarget, NSArray *features) {
    if (!menuTarget || ![features isKindOfClass:[NSArray class]]) return;
    for (id item in features) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *dictionary = item;
        NSString *identifier = [dictionary[@"identifier"] isKindOfClass:[NSString class]] ? dictionary[@"identifier"] : nil;
        if (!identifier.length) continue;
        NSMutableDictionary *record = HFA5MFeatureRecord(identifier, YES);
        NSString *label = [dictionary[@"label"] isKindOfClass:[NSString class]] ? dictionary[@"label"] : nil;
        NSString *type = [dictionary[@"type"] isKindOfClass:[NSString class]] ? dictionary[@"type"] : nil;
        if (label.length) record[@"title"] = label;
        if (type.length) record[@"type"] = type;
        NSMutableArray *blocks = record[@"dictionaryBlocks"];
        for (id key in dictionary) {
            id value = dictionary[key];
            NSDictionary *block = HFA5MBlockInfo(value, [key isKindOfClass:[NSString class]] ? key : [key description]);
            if (block) HFA5MAppendUnique(blocks, block, @[@"key", @"image", @"rva"]);
        }
    }
    HFA5MLog([NSString stringWithFormat:@"[5M-DISPATCH-FEATURES] menuClass=%s features=%lu",
              class_getName(object_getClass(menuTarget)) ?: "?", (unsigned long)features.count]);
}

void HFA5MDispatcherObserveAction(id sender, id target, SEL action) {
    if (!sender || !target || !action) return;
    NSString *identifier = HFA5MStringGetter(sender, "identifier");
    if (!identifier.length) return;
    NSMutableDictionary *record = HFA5MFeatureRecord(identifier, YES);
    NSDictionary *resolved = HFA5MResolveDispatcher(target, action);
    if (!resolved.count) return;
    NSMutableArray *actions = record[@"actions"];
    NSMutableDictionary *actionEvidence = [resolved mutableCopy];
    actionEvidence[@"targetClass"] = [NSString stringWithUTF8String:class_getName(object_getClass(target)) ?: "?"];
    actionEvidence[@"senderClass"] = [NSString stringWithUTF8String:class_getName(object_getClass(sender)) ?: "?"];
    HFA5MAppendUnique(actions, actionEvidence, @[@"targetClass", @"senderClass"]);

    NSDictionary *dispatcher = resolved[@"dispatcher"];
    NSArray *notifications = dispatcher[@"notifications"];
    if (notifications.count) {
        NSMutableArray *allBridges = [NSMutableArray array];
        Class cls = object_getClass(target);
        for (NSDictionary *entry in notifications) {
            NSString *name = entry[@"name"];
            NSArray *bridges = HFA5MObserverBridgesForNotification(cls, name);
            for (NSDictionary *bridge in bridges)
                HFA5MAppendUnique(allBridges, bridge, @[@"selector", @"rva"]);
        }
        if (allBridges.count) record[@"observerBridges"] = allBridges;
    }

    NSString *dispatcherSelector = dispatcher[@"selector"] ?: @"?";
    NSString *dispatcherRVA = dispatcher[@"rva"] ?: @"?";
    HFA5MLog([NSString stringWithFormat:@"[5M-DISPATCH] identifier=%@ action=%@ resolution=%@ dispatcher=%@ rva=%@ notifications=%lu",
              identifier, NSStringFromSelector(action), resolved[@"resolution"] ?: @"?",
              dispatcherSelector, dispatcherRVA, (unsigned long)notifications.count]);
}

NSDictionary *HFA5MDispatcherEvidenceForIdentifier(NSString *identifier) {
    if (!identifier.length) return nil;
    NSMutableDictionary *record = gHFA5MFeatures[identifier];
    if (!record) return nil;
    NSMutableDictionary *copy = [record mutableCopy];
    NSArray *actions = copy[@"actions"];
    if (!actions.count) [copy removeObjectForKey:@"actions"];
    NSArray *blocks = copy[@"dictionaryBlocks"];
    if (!blocks.count) [copy removeObjectForKey:@"dictionaryBlocks"];
    copy[@"dispatcherResolved"] = @(actions.count > 0);
    copy[@"downstreamCallbackResolved"] = @(blocks.count > 0);
    return copy;
}

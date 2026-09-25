#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern const char *HFAAppLocalPrimaryImage(void);
extern void HFACyberUIAppendLog(NSString *text);

static const NSTimeInterval kHFACaptureDuration = 8.0;
static const uint64_t kHFACaptureDurationMs = 8000;
static BOOL gHFACaptureActive = NO;
static CFAbsoluteTime gHFACaptureStart = 0;
static NSString *gHFACaptureImage = nil;
static NSMutableArray *gHFACaptureActions = nil;
static NSMutableDictionary *gHFACaptureActionByKey = nil;
static NSMutableDictionary *gHFACaptureBaselineStates = nil;
static NSMutableArray *gHFACaptureCandidates = nil;
static NSMutableDictionary *gHFACaptureCandidateByID = nil;
static NSMutableDictionary *gHFACaptureLastProbeValues = nil;
static NSMutableArray *gHFACaptureUnassignedDeltas = nil;
static unsigned gHFACaptureSequence = 0;

typedef void (*HFASendActionIMP)(id, SEL, SEL, id, UIEvent *);
static HFASendActionIMP gHFACaptureOriginalSendAction = NULL;
static IMP gHFACaptureInstalledIMP = NULL;

static NSString *HFACaptureBase(const char *path) {
    if (!path) return @"";
    const char *slash = strrchr(path, '/');
    return [NSString stringWithUTF8String:slash ? slash + 1 : path] ?: @"";
}

static void HFACaptureEnsureContainers(void) {
    if (!gHFACaptureActions) gHFACaptureActions = [[NSMutableArray alloc] init];
    if (!gHFACaptureActionByKey) gHFACaptureActionByKey = [[NSMutableDictionary alloc] init];
    if (!gHFACaptureBaselineStates) gHFACaptureBaselineStates = [[NSMutableDictionary alloc] init];
    if (!gHFACaptureCandidates) gHFACaptureCandidates = [[NSMutableArray alloc] init];
    if (!gHFACaptureCandidateByID) gHFACaptureCandidateByID = [[NSMutableDictionary alloc] init];
    if (!gHFACaptureLastProbeValues) gHFACaptureLastProbeValues = [[NSMutableDictionary alloc] init];
    if (!gHFACaptureUnassignedDeltas) gHFACaptureUnassignedDeltas = [[NSMutableArray alloc] init];
}

static void HFACaptureResetContainers(void) {
    HFACaptureEnsureContainers();
    [gHFACaptureActions removeAllObjects];
    [gHFACaptureActionByKey removeAllObjects];
    [gHFACaptureBaselineStates removeAllObjects];
    [gHFACaptureCandidates removeAllObjects];
    [gHFACaptureCandidateByID removeAllObjects];
    [gHFACaptureLastProbeValues removeAllObjects];
    [gHFACaptureUnassignedDeltas removeAllObjects];
    gHFACaptureSequence = 0;
}

static void HFACaptureLog(NSString *line) {
    if (!line.length) return;
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Capture.log"];
    FILE *f = fopen(path.fileSystemRepresentation, "a");
    if (f) {
        fprintf(f, "%s\n", line.UTF8String ?: "[CAPTURE]");
        fflush(f);
        fclose(f);
    }
    HFACyberUIAppendLog(line);
}

static uint64_t HFACaptureNowMs(void) {
    if (!gHFACaptureStart) return 0;
    NSTimeInterval d = CFAbsoluteTimeGetCurrent() - gHFACaptureStart;
    if (d < 0) d = 0;
    return (uint64_t)(d * 1000.0);
}

static id HFACaptureSafeObjectGetter(id object, const char *name) {
    if (!object || !name) return nil;
    SEL sel = sel_registerName(name);
    Method m = class_getInstanceMethod(object_getClass(object), sel);
    if (!m) return nil;
    char *ret = method_copyReturnType(m);
    BOOL ok = ret && ret[0] == '@';
    if (ret) free(ret);
    if (!ok) return nil;
    @try { return ((id (*)(id, SEL))objc_msgSend)(object, sel); }
    @catch (__unused id e) { return nil; }
}

static NSString *HFACaptureStringGetter(id object, const char *name) {
    id value = HFACaptureSafeObjectGetter(object, name);
    return [value isKindOfClass:[NSString class]] ? value : nil;
}

static NSNumber *HFACaptureNumericGetter(id object, const char *name) {
    if (!object || !name) return nil;
    SEL sel = sel_registerName(name);
    Method m = class_getInstanceMethod(object_getClass(object), sel);
    if (!m) return nil;
    char *ret = method_copyReturnType(m);
    if (!ret) return nil;
    char t = ret[0];
    free(ret);
    @try {
        switch (t) {
            case 'B': case 'c': case 'C': case 's': case 'S': case 'i': case 'I': case 'l': case 'L': case 'q': case 'Q':
                return @(((uint64_t (*)(id, SEL))objc_msgSend)(object, sel));
            case 'f':
                return @(((float (*)(id, SEL))objc_msgSend)(object, sel));
            case 'd':
                return @(((double (*)(id, SEL))objc_msgSend)(object, sel));
            default:
                return nil;
        }
    } @catch (__unused id e) { return nil; }
}

static NSString *HFACaptureLabel(id sender) {
    const char *names[] = { "label", "currentTitle", "title", "text", "accessibilityLabel" };
    for (unsigned i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        NSString *s = HFACaptureStringGetter(sender, names[i]);
        if (s.length) return s;
    }
    @try {
        if ([sender respondsToSelector:@selector(titleLabel)]) {
            id label = ((id (*)(id, SEL))objc_msgSend)(sender, @selector(titleLabel));
            NSString *s = HFACaptureStringGetter(label, "text");
            if (s.length) return s;
        }
    } @catch (__unused id e) {}
    return nil;
}

static NSDictionary *HFACaptureState(id sender) {
    if (!sender) return @{};
    NSMutableDictionary *state = [NSMutableDictionary dictionary];
    state[@"pointer"] = [NSString stringWithFormat:@"%p", sender];
    Class cls = object_getClass(sender);
    if (cls) state[@"class"] = [NSString stringWithUTF8String:class_getName(cls)] ?: @"";
    NSString *identifier = HFACaptureStringGetter(sender, "identifier");
    NSString *label = HFACaptureLabel(sender);
    if (identifier.length) state[@"identifier"] = identifier;
    if (label.length) state[@"label"] = label;
    NSNumber *currentState = HFACaptureNumericGetter(sender, "currentState");
    NSNumber *isOn = HFACaptureNumericGetter(sender, "isOn");
    NSNumber *value = HFACaptureNumericGetter(sender, "value");
    if (currentState) state[@"currentState"] = currentState;
    if (isOn) state[@"isOn"] = isOn;
    if (value) state[@"value"] = value;
    return state;
}

static BOOL HFACaptureStateChanged(NSDictionary *a, NSDictionary *b) {
    if (!a || !b) return NO;
    NSArray *keys = @[ @"currentState", @"isOn", @"value" ];
    for (NSString *k in keys) {
        id av = a[k], bv = b[k];
        if (!av && !bv) continue;
        if ((av && !bv) || (!av && bv) || ![av isEqual:bv]) return YES;
    }
    return NO;
}

static NSString *HFACaptureFeatureKey(id sender, id target, SEL action) {
    NSString *identifier = HFACaptureStringGetter(sender, "identifier");
    if (identifier.length) return [@"id:" stringByAppendingString:identifier];
    NSString *label = HFACaptureLabel(sender);
    if (label.length) return [@"label:" stringByAppendingString:label];
    const char *targetClass = target ? class_getName(object_getClass(target)) : "?";
    const char *actionName = action ? sel_getName(action) : "?";
    return [NSString stringWithFormat:@"action:%s::%s", targetClass ?: "?", actionName ?: "?"];
}

static BOOL HFACaptureClassMatchesSelected(Class cls) {
    if (!cls || !gHFACaptureImage.length) return NO;
    const char *path = class_getImageName(cls);
    NSString *base = HFACaptureBase(path);
    return [base isEqualToString:gHFACaptureImage];
}

static BOOL HFACaptureActionRelevant(id sender, id target) {
    if (!gHFACaptureActive || !gHFACaptureImage.length) return NO;
    Class sc = sender ? object_getClass(sender) : Nil;
    Class tc = target ? object_getClass(target) : Nil;
    return HFACaptureClassMatchesSelected(sc) || HFACaptureClassMatchesSelected(tc);
}

static BOOL HFACaptureVMInfo(uintptr_t address, vm_prot_t *protOut, mach_vm_size_t *sizeOut) {
    if (!address) return NO;
    mach_vm_address_t region = (mach_vm_address_t)address;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &region, &size, VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &count, &object);
    if (kr != KERN_SUCCESS || address < region || address >= region + size) return NO;
    if (protOut) *protOut = info.protection;
    if (sizeOut) *sizeOut = size - (mach_vm_size_t)(address - region);
    return YES;
}

static BOOL HFACaptureReadable(uintptr_t address, size_t size) {
    vm_prot_t prot = 0; mach_vm_size_t remain = 0;
    return HFACaptureVMInfo(address, &prot, &remain) && (prot & VM_PROT_READ) && remain >= size;
}

static BOOL HFACaptureWritable(uintptr_t address, size_t size) {
    vm_prot_t prot = 0; mach_vm_size_t remain = 0;
    return HFACaptureVMInfo(address, &prot, &remain) && (prot & VM_PROT_READ) && (prot & VM_PROT_WRITE) && remain >= size;
}

static NSString *HFACaptureHexAt(uintptr_t address, NSUInteger size) {
    if (!size || size > 32 || !HFACaptureReadable(address, size)) return nil;
    uint8_t bytes[32] = {0};
    memcpy(bytes, (void *)address, size);
    static const char *hex = "0123456789ABCDEF";
    char out[65] = {0};
    for (NSUInteger i = 0; i < size; i++) {
        out[i*2] = hex[bytes[i] >> 4];
        out[i*2+1] = hex[bytes[i] & 15];
    }
    return [NSString stringWithUTF8String:out];
}

static BOOL HFACapturePointerLike(uint64_t value) {
    if (value < 0x10000ull) return NO;
    return HFACaptureReadable((uintptr_t)value, 1);
}

static uintptr_t HFACaptureImageBase(NSString *name) {
    if (!name.length) return 0;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if ([HFACaptureBase(path) isEqualToString:name])
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

static uint64_t HFACaptureParseInteger(id value) {
    if ([value isKindOfClass:[NSNumber class]]) return [value unsignedLongLongValue];
    if (![value isKindOfClass:[NSString class]]) return 0;
    const char *s = [(NSString *)value UTF8String];
    if (!s) return 0;
    return strtoull(s, NULL, 0);
}

static NSDictionary *HFACaptureReadJSON(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) return nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [obj isKindOfClass:[NSDictionary class]] ? obj : nil;
}

static BOOL HFACaptureWriteJSON(id root, NSString *path) {
    if (!root || !path.length || ![NSJSONSerialization isValidJSONObject:root]) return NO;
    NSData *data = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:nil];
    return data.length && [data writeToFile:path atomically:YES];
}

static NSString *HFACaptureCurrentPatchPath(void) {
    NSBundle *bundle = NSBundle.mainBundle;
    NSString *bundleID = bundle.bundleIdentifier ?: @"unknown.game";
    NSString *shortVersion = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"0";
    NSString *buildVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"0";
    NSString *safeID = [bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    NSString *name = [NSString stringWithFormat:@"%@_%@_%@.hfapatch.json", safeID, shortVersion, buildVersion];
    return [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:name];
}

static int64_t HFACaptureSignExtend(uint64_t value, unsigned bits) {
    uint64_t mask = 1ull << (bits - 1);
    return (int64_t)((value ^ mask) - mask);
}

static BOOL HFACaptureADR(uint32_t w, uintptr_t pc, unsigned *rd, uintptr_t *value) {
    if ((w & 0x9F000000u) != 0x10000000u) return NO;
    uint64_t imm = ((uint64_t)((w >> 5) & 0x7FFFFu) << 2) | ((w >> 29) & 3u);
    if (rd) *rd = w & 31u;
    if (value) *value = (uintptr_t)((int64_t)pc + HFACaptureSignExtend(imm, 21));
    return YES;
}

static BOOL HFACaptureADRP(uint32_t w, uintptr_t pc, unsigned *rd, uintptr_t *page) {
    if ((w & 0x9F000000u) != 0x90000000u) return NO;
    uint64_t imm = ((uint64_t)((w >> 5) & 0x7FFFFu) << 2) | ((w >> 29) & 3u);
    int64_t off = HFACaptureSignExtend(imm, 21) << 12;
    if (rd) *rd = w & 31u;
    if (page) *page = (pc & ~(uintptr_t)0xFFF) + off;
    return YES;
}

static BOOL HFACaptureADD(uint32_t w, unsigned *rd, unsigned *rn, uint64_t *imm) {
    if ((w & 0x7F000000u) != 0x11000000u) return NO;
    if ((w >> 22) & 1u) return NO;
    uint64_t value = (w >> 10) & 0xFFFu;
    if ((w >> 22) & 1u) value <<= 12;
    if (rd) *rd = w & 31u;
    if (rn) *rn = (w >> 5) & 31u;
    if (imm) *imm = value;
    return YES;
}

static BOOL HFACaptureLoadStoreAddress(uint32_t w, unsigned baseReg, uintptr_t page, uintptr_t *address) {
    uint32_t top = w & 0xFFC00000u;
    unsigned scale = 0;
    if (top == 0xF9400000u || top == 0xF9000000u) scale = 8;
    else if (top == 0xB9400000u || top == 0xB9000000u) scale = 4;
    else if (top == 0x39400000u || top == 0x39000000u) scale = 1;
    else return NO;
    unsigned rn = (w >> 5) & 31u;
    if (rn != baseReg) return NO;
    uint64_t imm12 = (w >> 10) & 0xFFFu;
    if (address) *address = page + imm12 * scale;
    return YES;
}

static NSMutableArray *HFACaptureProbesForReplacement(uintptr_t replacement, NSString *candidateID) {
    NSMutableArray *probes = [NSMutableArray array];
    if (!replacement || !HFACaptureReadable(replacement, 4)) return probes;
    const uint32_t *words = (const uint32_t *)replacement;
    NSUInteger maxWords = 160;
    NSMutableSet *seen = [NSMutableSet set];
    for (NSUInteger i = 0; i < maxWords && HFACaptureReadable(replacement + i*4, 4); i++) {
        uintptr_t pc = replacement + i*4;
        unsigned rd = 0; uintptr_t direct = 0;
        if (HFACaptureADR(words[i], pc, &rd, &direct) && HFACaptureWritable(direct, 1)) {
            NSString *key = [NSString stringWithFormat:@"0x%llX", (unsigned long long)direct];
            if (![seen containsObject:key]) {
                [seen addObject:key];
                [probes addObject:[@{ @"id": [NSString stringWithFormat:@"%@/state/%lu", candidateID, (unsigned long)probes.count],
                                      @"address": @(direct), @"size": @8, @"kind": @"native-state" } mutableCopy]];
            }
        }
        unsigned r = 0; uintptr_t page = 0;
        if (!HFACaptureADRP(words[i], pc, &r, &page) || i + 1 >= maxWords) continue;
        unsigned addRD = 0, addRN = 0; uint64_t addImm = 0; uintptr_t address = 0;
        if (HFACaptureADD(words[i+1], &addRD, &addRN, &addImm) && addRD == r && addRN == r)
            address = page + addImm;
        else
            HFACaptureLoadStoreAddress(words[i+1], r, page, &address);
        if (!address || !HFACaptureWritable(address, 1)) continue;
        NSString *key = [NSString stringWithFormat:@"0x%llX", (unsigned long long)address];
        if ([seen containsObject:key]) continue;
        [seen addObject:key];
        [probes addObject:[@{ @"id": [NSString stringWithFormat:@"%@/state/%lu", candidateID, (unsigned long)probes.count],
                              @"address": @(address), @"size": @8, @"kind": @"native-state" } mutableCopy]];
        if (probes.count >= 24) break;
    }
    return probes;
}

static void HFACaptureAddCandidate(NSMutableDictionary *candidate) {
    NSString *cid = [candidate[@"id"] isKindOfClass:[NSString class]] ? candidate[@"id"] : nil;
    if (!cid.length || gHFACaptureCandidateByID[cid]) return;
    if (![candidate[@"probes"] isKindOfClass:[NSArray class]]) candidate[@"probes"] = [NSMutableArray array];
    [gHFACaptureCandidates addObject:candidate];
    gHFACaptureCandidateByID[cid] = candidate;
}

static void HFACaptureLoadV03Candidates(void) {
    NSString *path = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:@"HFAMap_RuntimeAnalyzer_v03.json"];
    NSDictionary *root = HFACaptureReadJSON(path);
    NSArray *records = [root[@"descriptors"] isKindOfClass:[NSArray class]] ? root[@"descriptors"] : @[];
    uintptr_t menuBase = HFACaptureImageBase(gHFACaptureImage);
    for (NSDictionary *record in records) {
        if (![record isKindOfClass:[NSDictionary class]]) continue;
        NSString *kind = [record[@"kind"] isKindOfClass:[NSString class]] ? record[@"kind"] : @"";
        NSString *sink = [record[@"sink"] isKindOfClass:[NSString class]] ? record[@"sink"] : @"";
        if (![kind isEqualToString:@"target-rva"] && ![kind isEqualToString:@"patch-data"] && ![sink isEqualToString:@"native-hook"]) continue;
        NSString *descriptorRVA = [record[@"descriptorRVA"] description] ?: @"?";
        NSString *cid = [NSString stringWithFormat:@"descriptor:%@", descriptorRVA];
        unsigned keyId = [record[@"keyId"] unsignedIntValue];
        NSString *type = @"descriptor";
        if ([sink isEqualToString:@"native-hook"]) type = keyId == 2 ? @"k2-native-hook" : @"native-hook";
        else if ([kind isEqualToString:@"patch-data"]) type = keyId == 2 ? @"k2-patch-descriptor" : (keyId == 1 ? @"k1-patch-descriptor" : @"patch-descriptor");
        else type = keyId == 0 ? @"k0-target" : [NSString stringWithFormat:@"k%u-target", keyId];
        NSMutableDictionary *candidate = [@{ @"id": cid, @"type": type, @"source": @"v03", @"descriptor": record,
                                               @"keyId": @(keyId), @"probes": [NSMutableArray array] } mutableCopy];
        NSMutableArray *probes = candidate[@"probes"];
        if ([sink isEqualToString:@"native-hook"] && menuBase) {
            uint64_t replRVA = HFACaptureParseInteger(record[@"replacementRVA"]);
            uint64_t slotRVA = HFACaptureParseInteger(record[@"originalSlotRVA"]);
            if (replRVA) {
                uintptr_t repl = menuBase + (uintptr_t)replRVA;
                [probes addObjectsFromArray:HFACaptureProbesForReplacement(repl, cid)];
            }
            if (slotRVA) {
                uintptr_t slot = menuBase + (uintptr_t)slotRVA;
                if (HFACaptureReadable(slot, 8))
                    [probes addObject:[@{ @"id": [cid stringByAppendingString:@"/original-slot"], @"address": @(slot), @"size": @8, @"kind": @"original-slot" } mutableCopy]];
            }
        }
        HFACaptureAddCandidate(candidate);
    }
}

static void HFACaptureCollectPatchNodes(id node, NSMutableArray *out) {
    if ([node isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = node;
        id module = d[@"module"] ?: d[@"image"];
        id offset = d[@"offset"] ?: d[@"rva"];
        if ([module isKindOfClass:[NSString class]] && offset) [out addObject:d];
        for (id value in d.allValues) HFACaptureCollectPatchNodes(value, out);
    } else if ([node isKindOfClass:[NSArray class]]) {
        for (id value in (NSArray *)node) HFACaptureCollectPatchNodes(value, out);
    }
}

static void HFACaptureLoadPatchCandidates(void) {
    NSDictionary *root = HFACaptureReadJSON(HFACaptureCurrentPatchPath());
    if (!root) return;
    NSMutableArray *nodes = [NSMutableArray array];
    HFACaptureCollectPatchNodes(root, nodes);
    unsigned index = 0;
    for (NSDictionary *d in nodes) {
        NSString *module = [d[@"module"] isKindOfClass:[NSString class]] ? d[@"module"] : ([d[@"image"] isKindOfClass:[NSString class]] ? d[@"image"] : nil);
        uint64_t offset = HFACaptureParseInteger(d[@"offset"] ?: d[@"rva"]);
        if (!module.length || !offset) continue;
        uintptr_t base = HFACaptureImageBase(module);
        if (!base) continue;
        uintptr_t address = base + (uintptr_t)offset;
        if (!HFACaptureReadable(address, 4)) continue;
        NSString *cid = [NSString stringWithFormat:@"patch:%@:%llX", module, (unsigned long long)offset];
        NSUInteger size = 8;
        NSString *original = [d[@"original"] isKindOfClass:[NSString class]] ? d[@"original"] : nil;
        if (original.length >= 2 && original.length/2 <= 32) size = MAX((NSUInteger)4, original.length/2);
        NSMutableDictionary *candidate = [@{ @"id": cid, @"type": @"static-patch", @"source": @"hfapatch",
                                               @"module": module, @"offset": [NSString stringWithFormat:@"0x%llX", (unsigned long long)offset],
                                               @"metadata": d, @"probes": [NSMutableArray array] } mutableCopy];
        [candidate[@"probes"] addObject:[@{ @"id": [cid stringByAppendingString:@"/bytes"], @"address": @(address), @"size": @(size), @"kind": @"patch-bytes" } mutableCopy]];
        HFACaptureAddCandidate(candidate);
        if (++index >= 128) break;
    }
}

static void HFACaptureBuildCandidates(void) {
    HFACaptureLoadV03Candidates();
    HFACaptureLoadPatchCandidates();
    HFACaptureLog([NSString stringWithFormat:@"[CAPTURE-CANDIDATES] image=%@ count=%lu", gHFACaptureImage ?: @"?", (unsigned long)gHFACaptureCandidates.count]);
}

static NSString *HFACaptureProbeValue(NSDictionary *probe) {
    uintptr_t address = (uintptr_t)[probe[@"address"] unsignedLongLongValue];
    NSUInteger size = [probe[@"size"] unsignedIntegerValue];
    return HFACaptureHexAt(address, size);
}

static void HFACaptureSnapshotProbeBaseline(void) {
    for (NSDictionary *candidate in gHFACaptureCandidates) {
        for (NSDictionary *probe in candidate[@"probes"]) {
            NSString *pid = probe[@"id"];
            NSString *value = HFACaptureProbeValue(probe);
            if (pid.length && value) gHFACaptureLastProbeValues[pid] = value;
        }
    }
}

static NSMutableDictionary *HFACaptureAnchorForKey(NSString *key, id sender, id target, SEL action) {
    NSMutableDictionary *anchor = gHFACaptureActionByKey[key];
    uint64_t now = HFACaptureNowMs();
    NSDictionary *live = HFACaptureState(sender);
    if (anchor) {
        anchor[@"actionCount"] = @([anchor[@"actionCount"] unsignedIntegerValue] + 1);
        anchor[@"lastTimestampMs"] = @(now);
        anchor[@"repeated"] = @YES;
        return anchor;
    }
    NSString *identifier = HFACaptureStringGetter(sender, "identifier") ?: @"";
    NSString *label = HFACaptureLabel(sender) ?: @"";
    NSString *actionName = action ? [NSString stringWithUTF8String:sel_getName(action)] : @"";
    NSString *targetClass = target ? [NSString stringWithUTF8String:class_getName(object_getClass(target))] : @"";
    NSString *senderClass = sender ? [NSString stringWithUTF8String:class_getName(object_getClass(sender))] : @"";
    NSDictionary *before = gHFACaptureBaselineStates[key] ?: live ?: @{};
    anchor = [@{ @"sequence": @(++gHFACaptureSequence), @"key": key, @"timestampMs": @(now), @"lastTimestampMs": @(now),
                  @"actionCount": @1, @"identifier": identifier, @"title": label, @"action": actionName ?: @"",
                  @"senderClass": senderClass ?: @"", @"targetClass": targetClass ?: @"", @"beforeState": before,
                  @"backendDeltas": [NSMutableArray array] } mutableCopy];
    [gHFACaptureActions addObject:anchor];
    gHFACaptureActionByKey[key] = anchor;
    HFACaptureLog([NSString stringWithFormat:@"[CAPTURE-ACTION] seq=%u t=%llums identifier=%@ title=%@ action=%@ target=%@",
                   gHFACaptureSequence, (unsigned long long)now, identifier.length ? identifier : @"?",
                   label.length ? label : @"?", actionName.length ? actionName : @"?", targetClass.length ? targetClass : @"?"]);
    return anchor;
}

static void HFACaptureSampleDeltas(NSMutableDictionary *anchor, NSString *phase) {
    if (!gHFACaptureActive || !anchor) return;
    uint64_t now = HFACaptureNowMs();
    NSMutableArray *deltas = anchor[@"backendDeltas"];
    for (NSDictionary *candidate in gHFACaptureCandidates) {
        NSString *cid = candidate[@"id"];
        for (NSDictionary *probe in candidate[@"probes"]) {
            NSString *pid = probe[@"id"];
            NSString *before = gHFACaptureLastProbeValues[pid];
            NSString *after = HFACaptureProbeValue(probe);
            if (!pid.length || !after) continue;
            if (!before) {
                gHFACaptureLastProbeValues[pid] = after;
                continue;
            }
            if ([before isEqualToString:after]) continue;
            uintptr_t address = (uintptr_t)[probe[@"address"] unsignedLongLongValue];
            uint64_t raw = 0;
            if ([probe[@"size"] unsignedIntegerValue] >= 8 && HFACaptureReadable(address, 8)) memcpy(&raw, (void *)address, 8);
            BOOL receiver = [[probe[@"kind"] description] isEqualToString:@"native-state"] && HFACapturePointerLike(raw);
            NSDictionary *delta = @{ @"candidateID": cid ?: @"?", @"candidateType": candidate[@"type"] ?: @"?",
                                     @"probeID": pid, @"probeKind": probe[@"kind"] ?: @"?", @"phase": phase ?: @"?",
                                     @"timestampMs": @(now), @"before": before, @"after": after,
                                     @"receiverCandidate": @(receiver) };
            [deltas addObject:delta];
            gHFACaptureLastProbeValues[pid] = after;
            HFACaptureLog([NSString stringWithFormat:@"[CAPTURE-DELTA] seq=%@ t=%llums backend=%@ type=%@ probe=%@ receiver=%d",
                           anchor[@"sequence"], (unsigned long long)now, cid ?: @"?", candidate[@"type"] ?: @"?", probe[@"kind"] ?: @"?", receiver ? 1 : 0]);
        }
    }
}

static void HFACapturePostAction(id sender, NSString *key, uint64_t delayMs) {
    if (!gHFACaptureActive) return;
    NSMutableDictionary *anchor = gHFACaptureActionByKey[key];
    if (!anchor) return;
    NSDictionary *after = HFACaptureState(sender);
    anchor[@"afterState"] = after ?: @{};
    anchor[@"stateChanged"] = @(HFACaptureStateChanged(anchor[@"beforeState"], after));
    HFACaptureSampleDeltas(anchor, [NSString stringWithFormat:@"+%llums", (unsigned long long)delayMs]);
}

static void HFACaptureSendAction(id self, SEL _cmd, SEL action, id target, UIEvent *event) {
    BOOL relevant = HFACaptureActionRelevant(self, target);
    NSString *key = nil;
    if (relevant) {
        key = HFACaptureFeatureKey(self, target, action);
        HFACaptureAnchorForKey(key, self, target, action);
    }
    if (gHFACaptureOriginalSendAction) gHFACaptureOriginalSendAction(self, _cmd, action, target, event);
    if (relevant && key.length) {
        id sender = self;
        NSString *capturedKey = [key copy];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(60 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
            HFACapturePostAction(sender, capturedKey, 60);
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(250 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
            HFACapturePostAction(sender, capturedKey, 250);
        });
    }
}

static BOOL HFACaptureInstallActionTap(void) {
    Method m = class_getInstanceMethod([UIControl class], @selector(sendAction:to:forEvent:));
    if (!m) return NO;
    IMP current = method_getImplementation(m);
    IMP ours = (IMP)HFACaptureSendAction;
    if (current == ours) return YES;
    gHFACaptureOriginalSendAction = (HFASendActionIMP)current;
    gHFACaptureInstalledIMP = ours;
    method_setImplementation(m, ours);
    return YES;
}

static void HFACaptureRemoveActionTap(void) {
    Method m = class_getInstanceMethod([UIControl class], @selector(sendAction:to:forEvent:));
    if (!m || !gHFACaptureOriginalSendAction) return;
    if (method_getImplementation(m) == gHFACaptureInstalledIMP)
        method_setImplementation(m, (IMP)gHFACaptureOriginalSendAction);
    gHFACaptureOriginalSendAction = NULL;
    gHFACaptureInstalledIMP = NULL;
}

static void HFACaptureCollectBaselineView(UIView *view, unsigned depth) {
    if (!view || depth > 32) return;
    if ([view isKindOfClass:[UIControl class]]) {
        UIControl *control = (UIControl *)view;
        BOOL relevant = HFACaptureClassMatchesSelected(object_getClass(control));
        if (!relevant) {
            for (id target in control.allTargets) if (HFACaptureClassMatchesSelected(object_getClass(target))) { relevant = YES; break; }
        }
        if (relevant) {
            NSString *key = HFACaptureFeatureKey(control, nil, NULL);
            if (key.length) gHFACaptureBaselineStates[key] = HFACaptureState(control);
        }
    }
    NSUInteger count = MIN(view.subviews.count, (NSUInteger)512);
    for (NSUInteger i = 0; i < count; i++) HFACaptureCollectBaselineView(view.subviews[i], depth + 1);
}

static void HFACaptureCollectBaseline(void) {
    NSArray *windows = UIApplication.sharedApplication.windows ?: @[];
    NSUInteger count = MIN(windows.count, (NSUInteger)32);
    for (NSUInteger i = 0; i < count; i++) HFACaptureCollectBaselineView(windows[i], 0);
}

static NSDictionary *HFACaptureCandidatePublicView(NSDictionary *candidate) {
    NSMutableDictionary *copy = [candidate mutableCopy];
    NSMutableArray *probes = [NSMutableArray array];
    for (NSDictionary *probe in candidate[@"probes"]) {
        NSMutableDictionary *p = [probe mutableCopy];
        [p removeObjectForKey:@"address"];
        [probes addObject:p];
    }
    copy[@"probes"] = probes;
    return copy;
}

static NSDictionary *HFACaptureBuildMatrix(void) {
    NSMutableArray *rows = [NSMutableArray array];
    NSMutableDictionary *candidateFeatures = [NSMutableDictionary dictionary];
    for (NSDictionary *action in gHFACaptureActions) {
        NSMutableDictionary *group = [NSMutableDictionary dictionary];
        for (NSDictionary *delta in action[@"backendDeltas"]) {
            NSString *cid = delta[@"candidateID"] ?: @"?";
            NSMutableDictionary *entry = group[cid];
            if (!entry) {
                NSDictionary *candidate = gHFACaptureCandidateByID[cid] ?: @{};
                entry = [@{ @"candidateID": cid, @"candidateType": candidate[@"type"] ?: delta[@"candidateType"] ?: @"?",
                            @"deltaCount": @0, @"patchChanged": @NO, @"receiverObserved": @NO } mutableCopy];
                group[cid] = entry;
            }
            entry[@"deltaCount"] = @([entry[@"deltaCount"] unsignedIntegerValue] + 1);
            if ([[delta[@"probeKind"] description] isEqualToString:@"patch-bytes"]) entry[@"patchChanged"] = @YES;
            if ([delta[@"receiverCandidate"] boolValue]) entry[@"receiverObserved"] = @YES;
        }
        NSMutableArray *links = [NSMutableArray array];
        for (NSString *cid in group) {
            NSMutableDictionary *entry = group[cid];
            unsigned score = [action[@"stateChanged"] boolValue] ? 20 : 0;
            score += MIN(50u, (unsigned)[entry[@"deltaCount"] unsignedIntegerValue] * 20u);
            if ([entry[@"patchChanged"] boolValue]) score += 25;
            if ([entry[@"receiverObserved"] boolValue]) score += 25;
            NSDictionary *candidate = gHFACaptureCandidateByID[cid];
            NSArray *hints = [candidate[@"descriptor"][@"featureHints"] isKindOfClass:[NSArray class]] ? candidate[@"descriptor"][@"featureHints"] : @[];
            NSString *identifier = action[@"identifier"] ?: @"";
            NSString *title = action[@"title"] ?: @"";
            for (NSString *hint in hints) {
                if ((identifier.length && [hint caseInsensitiveCompare:identifier] == NSOrderedSame) ||
                    (title.length && [hint caseInsensitiveCompare:title] == NSOrderedSame)) { score += 25; break; }
            }
            if (score > 100) score = 100;
            entry[@"score"] = @(score);
            entry[@"confidence"] = score >= 80 ? @"high" : (score >= 50 ? @"medium" : @"low");
            [links addObject:entry];
            NSMutableArray *features = candidateFeatures[cid];
            if (!features) { features = [NSMutableArray array]; candidateFeatures[cid] = features; }
            NSString *name = title.length ? title : (identifier.length ? identifier : action[@"key"]);
            if (name.length && ![features containsObject:name]) [features addObject:name];
        }
        [rows addObject:@{ @"sequence": action[@"sequence"] ?: @0,
                           @"identifier": action[@"identifier"] ?: @"",
                           @"title": action[@"title"] ?: @"",
                           @"stateChanged": action[@"stateChanged"] ?: @NO,
                           @"backends": links }];
    }
    NSMutableArray *shared = [NSMutableArray array];
    for (NSString *cid in candidateFeatures) {
        NSArray *features = candidateFeatures[cid];
        if (features.count > 1) [shared addObject:@{ @"candidateID": cid, @"features": features }];
    }
    return @{ @"rows": rows, @"sharedBackendGroups": shared };
}

static void HFACaptureStopAndWrite(void) {
    if (!gHFACaptureActive) return;
    gHFACaptureActive = NO;
    HFACaptureRemoveActionTap();
    uint64_t ended = HFACaptureNowMs();
    NSDictionary *matrix = HFACaptureBuildMatrix();
    NSMutableArray *publicCandidates = [NSMutableArray array];
    for (NSDictionary *candidate in gHFACaptureCandidates) [publicCandidates addObject:HFACaptureCandidatePublicView(candidate)];
    NSBundle *bundle = NSBundle.mainBundle;
    NSDictionary *root = @{ @"schema": @"com.hfa.manual-capture/v0.3.1",
                            @"durationMs": @(kHFACaptureDurationMs),
                            @"actualEndMs": @(ended),
                            @"selectedImage": gHFACaptureImage ?: @"?",
                            @"bundleID": bundle.bundleIdentifier ?: @"unknown.game",
                            @"shortVersion": [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"0",
                            @"buildVersion": [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"0",
                            @"actions": gHFACaptureActions ?: @[],
                            @"backendCandidates": publicCandidates,
                            @"backendMatrix": matrix[@"rows"] ?: @[],
                            @"sharedBackendGroups": matrix[@"sharedBackendGroups"] ?: @[],
                            @"unassignedDeltas": gHFACaptureUnassignedDeltas ?: @[] };
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *dir = [docs stringByAppendingPathComponent:@"HFAMap_Captures"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    long long stamp = (long long)([[NSDate date] timeIntervalSince1970] * 1000.0);
    NSString *session = [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"session_%lld.json", stamp]];
    NSString *latest = [docs stringByAppendingPathComponent:@"HFAMap_ManualCapture.latest.json"];
    BOOL a = HFACaptureWriteJSON(root, session);
    BOOL b = HFACaptureWriteJSON(root, latest);
    HFACaptureLog([NSString stringWithFormat:@"[CAPTURE-END] duration=%llums actions=%lu candidates=%lu wrote=%d latest=%d",
                   (unsigned long long)ended, (unsigned long)gHFACaptureActions.count,
                   (unsigned long)gHFACaptureCandidates.count, a ? 1 : 0, b ? 1 : 0]);
    HFACaptureLog(@"✅ 8 秒捕获结束。已输出 HFAMap_ManualCapture.latest.json");
}

BOOL HFAManualCaptureIsActive(void) { return gHFACaptureActive; }

BOOL HFAManualCaptureStart8s(void) {
    if (gHFACaptureActive) return NO;
    const char *image = HFAAppLocalPrimaryImage();
    if (!image || !*image) {
        HFACaptureLog(@"❌ 8 秒捕获失败：请先扫描并选择目标 dylib");
        return NO;
    }
    HFACaptureResetContainers();
    gHFACaptureImage = [[NSString alloc] initWithUTF8String:image];
    HFACaptureCollectBaseline();
    HFACaptureBuildCandidates();
    HFACaptureSnapshotProbeBaseline();
    if (!HFACaptureInstallActionTap()) {
        HFACaptureLog(@"❌ 8 秒捕获失败：无法安装 UI action recorder");
        return NO;
    }
    gHFACaptureStart = CFAbsoluteTimeGetCurrent();
    gHFACaptureActive = YES;
    HFACaptureLog([NSString stringWithFormat:@"[CAPTURE-BEGIN] duration=8000ms image=%@ baselineFeatures=%lu candidates=%lu",
                   gHFACaptureImage, (unsigned long)gHFACaptureBaselineStates.count, (unsigned long)gHFACaptureCandidates.count]);
    HFACaptureLog(@"▶️ 8 秒捕获开始：请依次点击所有目标功能；滑杆只移动一个小步。每个功能尽量间隔 0.5 秒。");
    for (unsigned second = 1; second <= 7; second++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(second * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (gHFACaptureActive) HFACaptureLog([NSString stringWithFormat:@"[CAPTURE-TICK] remaining=%us", 8 - second]);
        });
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kHFACaptureDuration * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        HFACaptureStopAndWrite();
    });
    return YES;
}

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void HFARegisterPatchObject(id owner, const char *ownerClass);
extern void HFARegisterPatchSecret(id owner, id wrapper, const char *kind);
extern void HFARegisterFeatureDefinition(const char *label, const char *identifier);

static const char *kHFAGenericVersion = "HFAMap v1.9.28 GenericMenuResolver";
static id gSeenObjects[1024];
static unsigned gSeenObjectCount;
static Class gSeenClasses[512];
static unsigned gSeenClassCount;
static unsigned gScanGeneration;

static void HFAGenericLog(const char *fmt, ...) {
    @autoreleasepool {
        NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];
        FILE *f = fopen(path.fileSystemRepresentation, "a");
        if (!f) return;
        va_list ap;
        va_start(ap, fmt);
        vfprintf(f, fmt, ap);
        va_end(ap);
        fflush(f);
        fclose(f);
    }
}

static void HFAGenericJSON(NSDictionary *record) {
    if (!record || ![NSJSONSerialization isValidJSONObject:record]) return;
    @autoreleasepool {
        @try {
            NSMutableDictionary *envelope = [record mutableCopy];
            envelope[@"hfamapVersion"] = @"1.9.28";
            envelope[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
            NSData *json = [NSJSONSerialization dataWithJSONObject:envelope options:0 error:nil];
            if (!json) return;
            NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_MenuMap.jsonl"];
            NSFileManager *fm = [NSFileManager defaultManager];
            if (![fm fileExistsAtPath:path]) [fm createFileAtPath:path contents:nil attributes:nil];
            NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
            if (!handle) return;
            [handle seekToEndOfFile];
            [handle writeData:json];
            [handle writeData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];
            [handle closeFile];
        } @catch (__unused id exception) {
            HFAGenericLog("[GENERIC-JSON-ERROR] objc-exception\n");
        }
    }
}

static const char *HFABaseName(const char *path) {
    if (!path) return "?";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static NSDictionary *HFAAddressInfo(const void *address) {
    if (!address) return nil;
    Dl_info info = {0};
    if (!dladdr(address, &info) || !info.dli_fbase || !info.dli_fname) return nil;
    uintptr_t value = (uintptr_t)address;
    uintptr_t base = (uintptr_t)info.dli_fbase;
    return @{
        @"image": [NSString stringWithUTF8String:HFABaseName(info.dli_fname)] ?: @"?",
        @"rva": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(value - base)]
    };
}

static BOOL HFASeenObject(id object) {
    for (unsigned i = 0; i < gSeenObjectCount; i++) if (gSeenObjects[i] == object) return YES;
    if (gSeenObjectCount < sizeof(gSeenObjects) / sizeof(gSeenObjects[0])) gSeenObjects[gSeenObjectCount++] = object;
    return NO;
}

static BOOL HFASeenClass(Class cls) {
    for (unsigned i = 0; i < gSeenClassCount; i++) if (gSeenClasses[i] == cls) return YES;
    if (gSeenClassCount < sizeof(gSeenClasses) / sizeof(gSeenClasses[0])) gSeenClasses[gSeenClassCount++] = cls;
    return NO;
}

static BOOL HFAIsSubclassOf(Class cls, Class base) {
    if (!cls || !base) return NO;
    for (Class cursor = cls; cursor; cursor = class_getSuperclass(cursor)) if (cursor == base) return YES;
    return NO;
}

static BOOL HFAClassHasSelector(Class cls, const char *name) {
    return cls && name && class_getInstanceMethod(cls, sel_registerName(name)) != NULL;
}

static BOOL HFATypeContains(const char *encoding, const char *token) {
    return encoding && token && strstr(encoding, token) != NULL;
}

static BOOL HFAClassHasObjectIvarType(Class cls, const char *token) {
    for (Class cursor = cls; cursor; cursor = class_getSuperclass(cursor)) {
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        for (unsigned i = 0; i < count; i++) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            if (HFATypeContains(type, token)) {
                free(ivars);
                return YES;
            }
        }
        free(ivars);
    }
    return NO;
}

static BOOL HFAClassLooksLikePatchItem(Class cls) {
    Protocol *protocol = objc_getProtocol("APPatchItem");
    if (protocol && class_conformsToProtocol(cls, protocol)) return YES;
    return HFAClassHasSelector(cls, "identifier") &&
           HFAClassHasSelector(cls, "type") &&
           HFAClassHasSelector(cls, "currentState") &&
           HFAClassHasSelector(cls, "setCurrentState:");
}

static NSString *HFAKindForClass(Class cls) {
    Class button = objc_getClass("UIButton");
    Class slider = objc_getClass("UISlider");
    Class control = objc_getClass("UIControl");
    if (button && HFAIsSubclassOf(cls, button)) return @"button";
    if (slider && HFAIsSubclassOf(cls, slider)) return @"slider";
    if (control && HFAIsSubclassOf(cls, control) && HFAClassHasSelector(cls, "isOn")) return @"switch";
    if (HFAClassHasObjectIvarType(cls, "NSArray") || HFAClassHasObjectIvarType(cls, "NSMutableArray")) return @"group";
    return @"item";
}

static NSString *HFASafeStringGetter(id object, const char *selectorName) {
    if (!object || !selectorName) return nil;
    SEL sel = sel_registerName(selectorName);
    if (![object respondsToSelector:sel]) return nil;
    @try {
        id value = ((id (*)(id, SEL))objc_msgSend)(object, sel);
        return [value isKindOfClass:[NSString class]] ? value : nil;
    } @catch (__unused id exception) {
        return nil;
    }
}

static BOOL HFAUnsignedGetter(id object, const char *selectorName, uint64_t *valueOut) {
    if (!object || !selectorName) return NO;
    SEL sel = sel_registerName(selectorName);
    Class cls = object_getClass(object);
    Method method = class_getInstanceMethod(cls, sel);
    if (!method) return NO;
    char *returnType = method_copyReturnType(method);
    if (!returnType) return NO;
    char t = returnType[0];
    free(returnType);
    if (!(t == 'Q' || t == 'q' || t == 'I' || t == 'i' || t == 'L' || t == 'l' || t == 'B' || t == 'c' || t == 'C')) return NO;
    @try {
        uint64_t value = ((uint64_t (*)(id, SEL))objc_msgSend)(object, sel);
        if (valueOut) *valueOut = value;
        return YES;
    } @catch (__unused id exception) {
        return NO;
    }
}

static NSString *HFALabelForObject(id object) {
    NSString *label = HFASafeStringGetter(object, "currentTitle");
    if (label.length) return label;
    label = HFASafeStringGetter(object, "text");
    if (label.length) return label;
    label = HFASafeStringGetter(object, "accessibilityLabel");
    if (label.length) return label;
    @try {
        if ([object respondsToSelector:sel_registerName("titleLabel")]) {
            id titleLabel = ((id (*)(id, SEL))objc_msgSend)(object, sel_registerName("titleLabel"));
            label = HFASafeStringGetter(titleLabel, "text");
            if (label.length) return label;
        }
    } @catch (__unused id exception) {}
    return nil;
}

static unsigned HFADescriptorScoreForClass(Class cls) {
    unsigned score = 0;
    if (HFAClassHasObjectIvarType(cls, "IGSecretInt")) score += 25;
    if (HFAClassHasObjectIvarType(cls, "IGSecretData")) score += 25;
    if (HFAClassHasObjectIvarType(cls, "IGSecretString")) score += 15;
    if (HFAClassHasObjectIvarType(cls, "APSubpatchManager")) score += 15;
    if (HFAClassHasObjectIvarType(cls, "IGCodePatch")) score += 10;
    if (HFAClassHasSelector(cls, "identifier")) score += 10;
    return score;
}

static void HFALogMethod(Class cls, const char *selectorName) {
    Method method = class_getInstanceMethod(cls, sel_registerName(selectorName));
    if (!method) return;
    IMP imp = method_getImplementation(method);
    NSDictionary *address = HFAAddressInfo((const void *)imp);
    HFAGenericLog("[GENERIC-METHOD] class=%s selector=%s types=%s image=%s rva=%s\n",
                  class_getName(cls), selectorName,
                  method_getTypeEncoding(method) ?: "?",
                  [[address objectForKey:@"image"] UTF8String] ?: "?",
                  [[address objectForKey:@"rva"] UTF8String] ?: "?");
}

static void HFAInspectClassLayout(Class cls, const char *tag) {
    if (!cls) return;
    for (Class cursor = cls; cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        for (unsigned i = 0; i < count; i++) {
            const char *name = ivar_getName(ivars[i]);
            const char *type = ivar_getTypeEncoding(ivars[i]);
            ptrdiff_t offset = ivar_getOffset(ivars[i]);
            if (HFATypeContains(type, "IGSecret") || HFATypeContains(type, "APSubpatchManager") ||
                HFATypeContains(type, "IGCodePatch") || HFATypeContains(type, "NSArray") ||
                HFATypeContains(type, "NSString")) {
                HFAGenericLog("[GENERIC-IVAR] tag=%s class=%s owner=%s name=%s type=%s offset=0x%llX\n",
                              tag ?: "?", class_getName(cls), class_getName(cursor),
                              name ?: "?", type ?: "?", (unsigned long long)offset);
            }
        }
        free(ivars);
    }
}

static void HFAInspectDescriptorObject(id owner, id object, const char *context) {
    if (!object) return;
    Class cls = object_getClass(object);
    unsigned score = HFADescriptorScoreForClass(cls);
    if (score < 25) return;
    NSMutableArray *components = [NSMutableArray array];
    NSMutableDictionary *nested = [NSMutableDictionary dictionary];
    for (Class cursor = cls; cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        for (unsigned i = 0; i < count; i++) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            const char *kind = NULL;
            if (HFATypeContains(type, "IGSecretInt")) kind = "IGSecretInt";
            else if (HFATypeContains(type, "IGSecretData")) kind = "IGSecretData";
            else if (HFATypeContains(type, "IGSecretString")) kind = "IGSecretString";
            else if (HFATypeContains(type, "APSubpatchManager")) kind = "APSubpatchManager";
            else if (HFATypeContains(type, "IGCodePatch")) kind = "IGCodePatch";
            if (!kind || !type || type[0] != '@') continue;
            id value = nil;
            @try { value = object_getIvar(object, ivars[i]); } @catch (__unused id exception) { value = nil; }
            NSString *kindString = [NSString stringWithUTF8String:kind];
            [components addObject:kindString];
            if (value) nested[kindString] = [NSString stringWithFormat:@"%p", value];
            HFAGenericLog("[GENERIC-DESCRIPTOR-IVAR] context=%s owner=%p object=%p class=%s kind=%s value=%p offset=0x%llX\n",
                          context ?: "?", owner, object, class_getName(cls), kind, value,
                          (unsigned long long)ivar_getOffset(ivars[i]));
            if (value && (strcmp(kind, "IGSecretInt") == 0 || strcmp(kind, "IGSecretData") == 0))
                HFARegisterPatchSecret(owner ?: object, value, kind);
        }
        free(ivars);
    }
    HFARegisterPatchObject(owner ?: object, class_getName(cls));
    HFAGenericLog("[GENERIC-DESCRIPTOR] context=%s object=%p class=%s score=%u components=%s\n",
                  context ?: "?", object, class_getName(cls), score,
                  [[components componentsJoinedByString:@","] UTF8String] ?: "?");
    HFAGenericJSON(@{
        @"record": @"patch-descriptor",
        @"context": [NSString stringWithUTF8String:context ?: "?"],
        @"class": [NSString stringWithUTF8String:class_getName(cls)],
        @"pointer": [NSString stringWithFormat:@"%p", object],
        @"score": @(score),
        @"components": components,
        @"nested": nested
    });
}

void HFAGenericMenuObserveObject(id object, const char *context) {
    if (!object) return;
    @autoreleasepool {
        @try {
            Class cls = object_getClass(object);
            if (!cls) return;
            BOOL patchItem = HFAClassLooksLikePatchItem(cls);
            unsigned descriptorScore = HFADescriptorScoreForClass(cls);
            if (!patchItem && descriptorScore < 25) return;
            BOOL firstSeen = !HFASeenObject(object);
            if (patchItem && firstSeen) {
                NSString *identifier = HFASafeStringGetter(object, "identifier");
                NSString *label = HFALabelForObject(object);
                NSString *kind = HFAKindForClass(cls);
                uint64_t type = 0, state = 0;
                BOOL hasType = HFAUnsignedGetter(object, "type", &type);
                BOOL hasState = HFAUnsignedGetter(object, "currentState", &state);
                if (label.length && identifier.length)
                    HFARegisterFeatureDefinition(label.UTF8String, identifier.UTF8String);
                HFAGenericLog("[GENERIC-MENU-ITEM] context=%s object=%p class=%s kind=%s identifier=%s label=%s type=%s%llu state=%s%llu\n",
                              context ?: "?", object, class_getName(cls), kind.UTF8String,
                              identifier.UTF8String ?: "?", label.UTF8String ?: "?",
                              hasType ? "" : "?", (unsigned long long)type,
                              hasState ? "" : "?", (unsigned long long)state);
                HFAInspectClassLayout(cls, "menu-item");
                NSMutableDictionary *record = [@{
                    @"record": @"menu-item",
                    @"context": [NSString stringWithUTF8String:context ?: "?"],
                    @"pointer": [NSString stringWithFormat:@"%p", object],
                    @"class": [NSString stringWithUTF8String:class_getName(cls)],
                    @"kind": kind,
                    @"identifier": identifier ?: @"",
                    @"label": label ?: @"",
                    @"type": hasType ? @(type) : [NSNull null],
                    @"currentState": hasState ? @(state) : [NSNull null]
                } mutableCopy];
                const char *image = class_getImageName(cls);
                if (image) record[@"image"] = [NSString stringWithUTF8String:HFABaseName(image)];
                HFAGenericJSON(record);
            }
            if (descriptorScore >= 25) HFAInspectDescriptorObject(object, object, context);

            for (Class cursor = cls; cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {
                unsigned count = 0;
                Ivar *ivars = class_copyIvarList(cursor, &count);
                for (unsigned i = 0; i < count; i++) {
                    const char *type = ivar_getTypeEncoding(ivars[i]);
                    if (!type || type[0] != '@') continue;
                    if (!(HFATypeContains(type, "IGSecret") || HFATypeContains(type, "APSubpatchManager") ||
                          HFATypeContains(type, "IGCodePatch"))) continue;
                    id nested = nil;
                    @try { nested = object_getIvar(object, ivars[i]); } @catch (__unused id exception) { nested = nil; }
                    if (nested) HFAInspectDescriptorObject(object, nested, "nested-ivar");
                }
                free(ivars);
            }
        } @catch (__unused id exception) {
            HFAGenericLog("[GENERIC-OBJECT-SKIP] context=%s object=%p reason=objc-exception\n", context ?: "?", object);
        }
    }
}

static BOOL HFABytesContain(const uint8_t *bytes, size_t size, const char *needle) {
    if (!bytes || !needle) return NO;
    size_t n = strlen(needle);
    if (!n || size < n) return NO;
    for (size_t i = 0; i + n <= size; i++) if (memcmp(bytes + i, needle, n) == 0) return YES;
    return NO;
}

static BOOL HFAImageContainsCString(uint32_t index, const char *needle) {
    const struct mach_header *mh = _dyld_get_image_header(index);
    if (!mh || mh->magic != MH_MAGIC_64) return NO;
    const struct mach_header_64 *header = (const struct mach_header_64 *)mh;
    intptr_t slide = _dyld_get_image_vmaddr_slide(index);
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc->cmdsize) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            const struct section_64 *sec = (const struct section_64 *)(seg + 1);
            for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
                if (strncmp(sec->sectname, "__cstring", 16) != 0) continue;
                const uint8_t *bytes = (const uint8_t *)((uintptr_t)slide + (uintptr_t)sec->addr);
                if (bytes && HFABytesContain(bytes, (size_t)sec->size, needle)) return YES;
            }
        }
        cursor += lc->cmdsize;
    }
    return NO;
}

static BOOL HFAShouldScanImage(const char *path) {
    if (!path) return NO;
    if (strstr(path, "/System/Library/")) return NO;
    if (strstr(path, "/usr/lib/")) return NO;
    if (strstr(path, "HFAMapUniversal")) return NO;
    return YES;
}

static void HFAArchitectureScan(void) {
    unsigned legacyScore = 0, jailScore = 0, candidateClasses = 0;
    NSMutableArray *legacyEvidence = [NSMutableArray array];
    NSMutableArray *jailEvidence = [NSMutableArray array];
    Protocol *patchProtocol = objc_getProtocol("APPatchItem");
    if (patchProtocol) { legacyScore += 40; [legacyEvidence addObject:@"APPatchItem"]; }
    const char *legacyClasses[] = {"IGSecretInt", "IGSecretData", "IGSecretString", "APSubpatchManager", "IGCodePatch"};
    const unsigned legacyWeights[] = {12, 12, 8, 8, 5};
    for (unsigned i = 0; i < 5; i++) if (objc_getClass(legacyClasses[i])) {
        legacyScore += legacyWeights[i];
        [legacyEvidence addObject:[NSString stringWithUTF8String:legacyClasses[i]]];
    }

    int count = objc_getClassList(NULL, 0);
    if (count > 0) {
        Class *classes = (Class *)calloc((size_t)count, sizeof(Class));
        if (classes) {
            count = objc_getClassList(classes, count);
            for (int i = 0; i < count; i++) if (HFAClassLooksLikePatchItem(classes[i])) candidateClasses++;
            free(classes);
        }
    }
    if (candidateClasses) {
        legacyScore += candidateClasses >= 4 ? 15 : 8;
        [legacyEvidence addObject:[NSString stringWithFormat:@"patchItemClasses:%u", candidateClasses]];
    }

    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!HFAShouldScanImage(path)) continue;
        unsigned localLegacy = 0, localJail = 0;
        if (HFAImageContainsCString(i, "APPatchItem")) localLegacy += 20;
        if (HFAImageContainsCString(i, "IGSecretInt")) localLegacy += 10;
        if (HFAImageContainsCString(i, "IGSecretData")) localLegacy += 10;
        if (HFAImageContainsCString(i, "APSubpatchManager")) localLegacy += 10;
        if (HFAImageContainsCString(i, ".app-key-metadata-")) localJail += 30;
        if (HFAImageContainsCString(i, "JailpatchConfigValidator")) localJail += 25;
        if (HFAImageContainsCString(i, "Jailpatch runtime table")) localJail += 25;
        if (HFAImageContainsCString(i, "jailpatch")) localJail += 10;
        if (localLegacy) {
            legacyScore += localLegacy;
            [legacyEvidence addObject:[NSString stringWithFormat:@"image:%s", HFABaseName(path)]];
            HFAGenericLog("[GENERIC-ARCH-IMAGE] family=legacy-ap image=%s score=%u\n", HFABaseName(path), localLegacy);
        }
        if (localJail) {
            jailScore += localJail;
            [jailEvidence addObject:[NSString stringWithFormat:@"image:%s", HFABaseName(path)]];
            HFAGenericLog("[GENERIC-ARCH-IMAGE] family=jailpatch-v2 image=%s score=%u\n", HFABaseName(path), localJail);
        }
    }

    NSString *family = @"unknown";
    NSString *mode = @"probe";
    unsigned score = 0;
    NSArray *evidence = @[];
    if (legacyScore >= jailScore && legacyScore >= 40) {
        family = @"legacy-ap";
        mode = @"resolver";
        score = legacyScore;
        evidence = legacyEvidence;
    } else if (jailScore >= 30) {
        family = @"jailpatch-v2";
        mode = @"probe-only";
        score = jailScore;
        evidence = jailEvidence;
    }
    if (score > 100) score = 100;
    HFAGenericLog("[GENERIC-ARCH] family=%s mode=%s score=%u patchItemClasses=%u evidence=%s\n",
                  family.UTF8String, mode.UTF8String, score, candidateClasses,
                  [[evidence componentsJoinedByString:@","] UTF8String] ?: "?");
    HFAGenericJSON(@{
        @"record": @"architecture",
        @"family": family,
        @"mode": mode,
        @"score": @(score),
        @"patchItemClasses": @(candidateClasses),
        @"evidence": evidence
    });
}

static void HFAClassRegistryScan(void) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return;
    Class *classes = (Class *)calloc((size_t)count, sizeof(Class));
    if (!classes) return;
    count = objc_getClassList(classes, count);
    unsigned patchItems = 0, descriptors = 0;
    for (int i = 0; i < count; i++) {
        Class cls = classes[i];
        BOOL patchItem = HFAClassLooksLikePatchItem(cls);
        unsigned descriptorScore = HFADescriptorScoreForClass(cls);
        if (!patchItem && descriptorScore < 25) continue;
        if (patchItem) patchItems++;
        if (descriptorScore >= 25) descriptors++;
        if (HFASeenClass(cls)) continue;
        NSString *kind = patchItem ? HFAKindForClass(cls) : @"descriptor";
        const char *image = class_getImageName(cls);
        HFAGenericLog("[GENERIC-CLASS] class=%s kind=%s patchItem=%d descriptorScore=%u image=%s\n",
                      class_getName(cls), kind.UTF8String, patchItem ? 1 : 0,
                      descriptorScore, image ? HFABaseName(image) : "?");
        if (patchItem) {
            HFALogMethod(cls, "identifier");
            HFALogMethod(cls, "type");
            HFALogMethod(cls, "currentState");
            HFALogMethod(cls, "setCurrentState:");
        }
        HFAInspectClassLayout(cls, patchItem ? "patch-item-class" : "descriptor-class");
        HFAGenericJSON(@{
            @"record": @"class-fingerprint",
            @"class": [NSString stringWithUTF8String:class_getName(cls)],
            @"kind": kind,
            @"patchItem": @(patchItem),
            @"descriptorScore": @(descriptorScore),
            @"image": image ? [NSString stringWithUTF8String:HFABaseName(image)] : @""
        });
    }
    free(classes);
    HFAGenericLog("[GENERIC-CLASS-SCAN] generation=%u patchItems=%u descriptors=%u\n",
                  gScanGeneration, patchItems, descriptors);
}

void HFAGenericMenuObserveAction(id sender, id target, SEL action) {
    @autoreleasepool {
        Class senderClass = sender ? object_getClass(sender) : Nil;
        Class targetClass = target ? object_getClass(target) : Nil;
        BOOL senderRelevant = senderClass &&
            (HFAClassLooksLikePatchItem(senderClass) || HFADescriptorScoreForClass(senderClass) >= 25);
        BOOL targetRelevant = targetClass &&
            (HFAClassLooksLikePatchItem(targetClass) || HFADescriptorScoreForClass(targetClass) >= 25);
        if (!senderRelevant && !targetRelevant) return;
        HFAGenericMenuObserveObject(sender, "action-sender");
        HFAGenericMenuObserveObject(target, "action-target");
        Method method = (targetClass && action) ? class_getInstanceMethod(targetClass, action) : NULL;
        NSDictionary *impl = method ? HFAAddressInfo((const void *)method_getImplementation(method)) : nil;
        NSString *identifier = HFASafeStringGetter(sender, "identifier");
        NSString *label = HFALabelForObject(sender);
        NSString *kind = sender ? HFAKindForClass(object_getClass(sender)) : @"?";
        const char *actionName = action ? sel_getName(action) : "?";
        HFAGenericLog("[GENERIC-ACTION] sender=%p class=%s kind=%s identifier=%s label=%s target=%p targetClass=%s action=%s image=%s rva=%s\n",
                      sender, senderClass ? class_getName(senderClass) : "?",
                      kind.UTF8String, identifier.UTF8String ?: "?", label.UTF8String ?: "?",
                      target, targetClass ? class_getName(targetClass) : "?", actionName,
                      [[impl objectForKey:@"image"] UTF8String] ?: "?",
                      [[impl objectForKey:@"rva"] UTF8String] ?: "?");
        HFAGenericJSON(@{
            @"record": @"action",
            @"senderClass": senderClass ? [NSString stringWithUTF8String:class_getName(senderClass)] : @"",
            @"kind": kind,
            @"identifier": identifier ?: @"",
            @"label": label ?: @"",
            @"targetClass": targetClass ? [NSString stringWithUTF8String:class_getName(targetClass)] : @"",
            @"action": [NSString stringWithUTF8String:actionName],
            @"implementation": impl ?: @{}
        });
    }
}

void HFAGenericMenuRescan(void) {
    @autoreleasepool {
        gScanGeneration++;
        HFAGenericLog("[GENERIC-SCAN-BEGIN] generation=%u version=%s\n", gScanGeneration, kHFAGenericVersion);
        HFAArchitectureScan();
        HFAClassRegistryScan();
        HFAGenericLog("[GENERIC-SCAN-END] generation=%u\n", gScanGeneration);
    }
}

__attribute__((constructor)) static void HFAGenericMenuInit(void) {
    HFAGenericLog("[HFAMap v1.9.28 GenericMenuResolver] loaded json=Documents/HFAMap_MenuMap.jsonl\n");
}

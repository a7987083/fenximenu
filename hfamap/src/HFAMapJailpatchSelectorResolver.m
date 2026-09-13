#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void HFARegisterPatchObject(id obj, const char *actualClass);
extern void HFARegisterPatchSecret(id owner, id wrapper, const char *kind);
extern void HFARegisterPatchString(id owner, const char *value);
extern void HFARegisterFeatureDefinition(const char *label, const char *identifier);

static const char *kHFAJPSRVersion = "HFAMap v1.9.30 JailpatchSelectorResolver";

static void HFAJPSRLog(const char *fmt, ...) {
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

static void HFAJPSRJSON(NSDictionary *record) {
    if (!record || ![NSJSONSerialization isValidJSONObject:record]) return;
    @autoreleasepool {
        @try {
            NSMutableDictionary *envelope = [record mutableCopy];
            envelope[@"hfamapVersion"] = @"1.9.30";
            envelope[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
            NSData *json = [NSJSONSerialization dataWithJSONObject:envelope options:0 error:nil];
            if (!json) return;
            NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_JailpatchMap.jsonl"];
            NSFileManager *fm = [NSFileManager defaultManager];
            if (![fm fileExistsAtPath:path]) [fm createFileAtPath:path contents:nil attributes:nil];
            NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
            if (!handle) return;
            [handle seekToEndOfFile];
            [handle writeData:json];
            [handle writeData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];
            [handle closeFile];
        } @catch (__unused id exception) {
            HFAJPSRLog("[JAILPATCH-RESOLVER-JSON-ERROR] objc-exception\n");
        }
    }
}

static NSDictionary *HFAJPSRAddressInfo(const void *address) {
    if (!address) return nil;
    Dl_info info = {0};
    if (!dladdr(address, &info) || !info.dli_fbase || !info.dli_fname) return nil;
    const char *slash = strrchr(info.dli_fname, '/');
    const char *name = slash ? slash + 1 : info.dli_fname;
    uintptr_t value = (uintptr_t)address;
    uintptr_t base = (uintptr_t)info.dli_fbase;
    return @{
        @"image": [NSString stringWithUTF8String:name ?: "?"] ?: @"?",
        @"rva": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(value - base)]
    };
}

static BOOL HFAJPSRHasSelector(Class cls, const char *name) {
    return cls && name && class_getInstanceMethod(cls, sel_registerName(name)) != NULL;
}

static BOOL HFAJPSRLooksDescriptor(Class cls) {
    static const char *required[] = {
        "identifier", "type", "architecture", "active",
        "offset", "signature", "range", "searchDirection", "setActive:"
    };
    for (unsigned i = 0; i < sizeof(required) / sizeof(required[0]); i++)
        if (!HFAJPSRHasSelector(cls, required[i])) return NO;
    return YES;
}

static id HFAJPSRObjectGetter(id object, const char *selectorName) {
    if (!object || !selectorName) return nil;
    SEL sel = sel_registerName(selectorName);
    Method m = class_getInstanceMethod(object_getClass(object), sel);
    if (!m) return nil;
    char *ret = method_copyReturnType(m);
    BOOL ok = ret && ret[0] == '@';
    if (ret) free(ret);
    if (!ok) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, sel);
    } @catch (__unused id exception) {
        return nil;
    }
}

static BOOL HFAJPSRUIntGetter(id object, const char *selectorName, uint64_t *out) {
    if (!object || !selectorName) return NO;
    SEL sel = sel_registerName(selectorName);
    Method m = class_getInstanceMethod(object_getClass(object), sel);
    if (!m) return NO;
    char *ret = method_copyReturnType(m);
    if (!ret) return NO;
    char t = ret[0];
    free(ret);
    if (!(t == 'Q' || t == 'q' || t == 'I' || t == 'i' || t == 'L' || t == 'l' || t == 'B' || t == 'c' || t == 'C')) return NO;
    @try {
        uint64_t value = ((uint64_t (*)(id, SEL))objc_msgSend)(object, sel);
        if (out) *out = value;
        return YES;
    } @catch (__unused id exception) {
        return NO;
    }
}

static BOOL HFAJPSRHasSecret(id object) {
    if (!object) return NO;
    Method m = class_getInstanceMethod(object_getClass(object), sel_registerName("secret"));
    if (!m) return NO;
    char *ret = method_copyReturnType(m);
    BOOL ok = ret && ret[0] == '^';
    if (ret) free(ret);
    return ok;
}

static void *HFAJPSRSecretPointer(id object) {
    if (!HFAJPSRHasSecret(object)) return NULL;
    @try {
        return ((void *(*)(id, SEL))objc_msgSend)(object, sel_registerName("secret"));
    } @catch (__unused id exception) {
        return NULL;
    }
}

static BOOL HFAJPSRContainsObject(id *objects, unsigned count, id value) {
    for (unsigned i = 0; i < count; i++) if (objects[i] == value) return YES;
    return NO;
}

static NSString *HFAJPSRString(id object) {
    return [object isKindOfClass:[NSString class]] ? object : nil;
}

void HFAJailpatchResolveRecord(id record, const char *featureIdentifier, const char *featureLabel) {
    if (!record) return;
    @autoreleasepool {
        @try {
            Class cls = object_getClass(record);
            if (!HFAJPSRLooksDescriptor(cls)) return;

            NSString *identifier = HFAJPSRString(HFAJPSRObjectGetter(record, "identifier"));
            id offsetWrapper = HFAJPSRObjectGetter(record, "offset");
            id signatureWrapper = HFAJPSRObjectGetter(record, "signature");
            uint64_t type = 0, architecture = 0, active = 0, range = 0, searchDirection = 0;
            BOOL haveType = HFAJPSRUIntGetter(record, "type", &type);
            BOOL haveArchitecture = HFAJPSRUIntGetter(record, "architecture", &architecture);
            BOOL haveActive = HFAJPSRUIntGetter(record, "active", &active);
            BOOL haveRange = HFAJPSRUIntGetter(record, "range", &range);
            BOOL haveSearchDirection = HFAJPSRUIntGetter(record, "searchDirection", &searchDirection);

            if (featureLabel && *featureLabel && featureIdentifier && *featureIdentifier)
                HFARegisterFeatureDefinition(featureLabel, featureIdentifier);

            HFARegisterPatchObject(record, class_getName(cls));

            id secretObjects[16] = {0};
            unsigned secretCount = 0;
            NSMutableArray *strings = [NSMutableArray array];
            NSMutableArray *secretEvidence = [NSMutableArray array];

            for (Class cursor = cls; cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {
                unsigned count = 0;
                Ivar *ivars = class_copyIvarList(cursor, &count);
                if (count > 128) count = 128;
                for (unsigned i = 0; ivars && i < count; i++) {
                    const char *enc = ivar_getTypeEncoding(ivars[i]);
                    if (!enc || enc[0] != '@') continue;
                    id value = nil;
                    @try { value = object_getIvar(record, ivars[i]); } @catch (__unused id exception) { value = nil; }
                    if (!value) continue;

                    NSString *string = HFAJPSRString(value);
                    if (string.length) {
                        [strings addObject:string];
                        HFARegisterPatchString(record, string.UTF8String);
                    }

                    if (HFAJPSRHasSecret(value) && !HFAJPSRContainsObject(secretObjects, secretCount, value)) {
                        if (secretCount < sizeof(secretObjects) / sizeof(secretObjects[0]))
                            secretObjects[secretCount++] = value;
                        Method getter = class_getInstanceMethod(object_getClass(value), sel_registerName("secret"));
                        NSDictionary *imp = getter ? HFAJPSRAddressInfo((const void *)method_getImplementation(getter)) : nil;
                        void *secret = HFAJPSRSecretPointer(value);
                        [secretEvidence addObject:@{
                            @"pointer": [NSString stringWithFormat:@"%p", value],
                            @"class": [NSString stringWithUTF8String:class_getName(object_getClass(value)) ?: "?"],
                            @"secret": [NSString stringWithFormat:@"%p", secret],
                            @"getter": imp ?: @{}
                        }];
                    }
                }
                free(ivars);
            }

            BOOL offsetUsable = offsetWrapper && HFAJPSRHasSecret(offsetWrapper);
            BOOL signatureUsable = signatureWrapper && HFAJPSRHasSecret(signatureWrapper);
            if (offsetUsable) HFARegisterPatchSecret(record, offsetWrapper, "IGSecretInt");

            id patchCandidate = nil;
            unsigned patchCandidateCount = 0;
            for (unsigned i = 0; i < secretCount; i++) {
                id candidate = secretObjects[i];
                if (candidate == offsetWrapper || candidate == signatureWrapper) continue;
                patchCandidate = candidate;
                patchCandidateCount++;
            }
            if (patchCandidateCount == 1 && patchCandidate)
                HFARegisterPatchSecret(record, patchCandidate, "IGSecretData");

            if (signatureUsable)
                HFARegisterPatchSecret(record, signatureWrapper, "IGSecretString");

            NSDictionary *offsetGetterInfo = nil;
            Method offsetGetter = class_getInstanceMethod(cls, sel_registerName("offset"));
            if (offsetGetter) offsetGetterInfo = HFAJPSRAddressInfo((const void *)method_getImplementation(offsetGetter));
            NSDictionary *setActiveInfo = nil;
            Method setActive = class_getInstanceMethod(cls, sel_registerName("setActive:"));
            if (setActive) setActiveInfo = HFAJPSRAddressInfo((const void *)method_getImplementation(setActive));

            HFAJPSRLog("[JAILPATCH-SELECTOR-DESCRIPTOR] version=%s feature=%s label=\"%s\" object=%p class=%s identifier=%s type=%s%llu architecture=%s%llu active=%s%llu range=%s%llu searchDirection=%s%llu offsetWrapper=%p offsetClass=%s signatureWrapper=%p signatureClass=%s secretCount=%u patchCandidateCount=%u patchCandidate=%p patchClass=%s strings=%s\n",
                       kHFAJPSRVersion,
                       featureIdentifier ?: "?", featureLabel ?: "?", record,
                       class_getName(cls) ?: "?", identifier.UTF8String ?: "?",
                       haveType ? "" : "?", (unsigned long long)type,
                       haveArchitecture ? "" : "?", (unsigned long long)architecture,
                       haveActive ? "" : "?", (unsigned long long)active,
                       haveRange ? "" : "?", (unsigned long long)range,
                       haveSearchDirection ? "" : "?", (unsigned long long)searchDirection,
                       offsetWrapper, offsetWrapper ? class_getName(object_getClass(offsetWrapper)) : "?",
                       signatureWrapper, signatureWrapper ? class_getName(object_getClass(signatureWrapper)) : "?",
                       secretCount, patchCandidateCount, patchCandidate,
                       patchCandidate ? class_getName(object_getClass(patchCandidate)) : "?",
                       [[strings componentsJoinedByString:@","] UTF8String] ?: "?");

            HFAJPSRJSON(@{
                @"record": @"jailpatch-selector-descriptor",
                @"feature": featureIdentifier ? [NSString stringWithUTF8String:featureIdentifier] : @"",
                @"label": featureLabel ? [NSString stringWithUTF8String:featureLabel] : @"",
                @"pointer": [NSString stringWithFormat:@"%p", record],
                @"class": [NSString stringWithUTF8String:class_getName(cls) ?: "?"],
                @"identifier": identifier ?: @"",
                @"type": haveType ? @(type) : [NSNull null],
                @"architecture": haveArchitecture ? @(architecture) : [NSNull null],
                @"active": haveActive ? @(active) : [NSNull null],
                @"range": haveRange ? @(range) : [NSNull null],
                @"searchDirection": haveSearchDirection ? @(searchDirection) : [NSNull null],
                @"offsetWrapper": offsetWrapper ? [NSString stringWithFormat:@"%p", offsetWrapper] : @"",
                @"offsetClass": offsetWrapper ? [NSString stringWithUTF8String:class_getName(object_getClass(offsetWrapper)) ?: "?"] : @"",
                @"signatureWrapper": signatureWrapper ? [NSString stringWithFormat:@"%p", signatureWrapper] : @"",
                @"signatureClass": signatureWrapper ? [NSString stringWithUTF8String:class_getName(object_getClass(signatureWrapper)) ?: "?"] : @"",
                @"patchCandidate": patchCandidateCount == 1 && patchCandidate ? [NSString stringWithFormat:@"%p", patchCandidate] : @"",
                @"patchClass": patchCandidateCount == 1 && patchCandidate ? [NSString stringWithUTF8String:class_getName(object_getClass(patchCandidate)) ?: "?"] : @"",
                @"patchCandidateCount": @(patchCandidateCount),
                @"strings": strings,
                @"secrets": secretEvidence,
                @"offsetGetter": offsetGetterInfo ?: @{},
                @"setActive": setActiveInfo ?: @{},
                @"bridgeStatus": (offsetUsable && patchCandidateCount == 1) ? @"armed" : @"evidence-only"
            });
        } @catch (__unused id exception) {
            HFAJPSRLog("[JAILPATCH-SELECTOR-ERROR] feature=%s object=%p objc-exception\n", featureIdentifier ?: "?", record);
        }
    }
}

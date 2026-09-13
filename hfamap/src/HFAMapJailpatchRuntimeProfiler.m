#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *kHFAJPVersion = "HFAMap v1.9.29 JailpatchRuntimeProfiler";
static id gHFAJPTargets[64];
static unsigned gHFAJPTargetCount;
static id gHFAJPObjects[2048];
static unsigned gHFAJPObjectCount;
static Class gHFAJPClasses[512];
static unsigned gHFAJPClassCount;

struct HFAJPBlockLiteral {
    void *isa;
    int flags;
    int reserved;
    void (*invoke)(void *, ...);
    void *descriptor;
};

static void HFAJPLog(const char *fmt, ...) {
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

static void HFAJPJSON(NSDictionary *record) {
    if (!record || ![NSJSONSerialization isValidJSONObject:record]) return;
    @autoreleasepool {
        @try {
            NSMutableDictionary *envelope = [record mutableCopy];
            envelope[@"hfamapVersion"] = @"1.9.29";
            envelope[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
            NSData *data = [NSJSONSerialization dataWithJSONObject:envelope options:0 error:nil];
            if (!data) return;
            NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_JailpatchMap.jsonl"];
            NSFileManager *fm = [NSFileManager defaultManager];
            if (![fm fileExistsAtPath:path]) [fm createFileAtPath:path contents:nil attributes:nil];
            NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:path];
            if (!h) return;
            [h seekToEndOfFile];
            [h writeData:data];
            [h writeData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];
            [h closeFile];
        } @catch (__unused id exception) {
            HFAJPLog("[JAILPATCH-JSON-ERROR] objc-exception\n");
        }
    }
}

static const char *HFAJPBase(const char *path) {
    if (!path) return "?";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static NSDictionary *HFAJPAddressInfo(const void *address) {
    if (!address) return nil;
    Dl_info info = {0};
    if (!dladdr(address, &info) || !info.dli_fbase || !info.dli_fname) return nil;
    uintptr_t a = (uintptr_t)address;
    uintptr_t b = (uintptr_t)info.dli_fbase;
    return @{
        @"image": [NSString stringWithUTF8String:HFAJPBase(info.dli_fname)] ?: @"?",
        @"rva": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(a - b)]
    };
}

static BOOL HFAJPSeenTarget(id object) {
    for (unsigned i = 0; i < gHFAJPTargetCount; i++) if (gHFAJPTargets[i] == object) return YES;
    if (gHFAJPTargetCount < sizeof(gHFAJPTargets) / sizeof(gHFAJPTargets[0]))
        gHFAJPTargets[gHFAJPTargetCount++] = object;
    return NO;
}

static BOOL HFAJPSeenObject(id object) {
    if (!object) return YES;
    for (unsigned i = 0; i < gHFAJPObjectCount; i++) if (gHFAJPObjects[i] == object) return YES;
    if (gHFAJPObjectCount < sizeof(gHFAJPObjects) / sizeof(gHFAJPObjects[0]))
        gHFAJPObjects[gHFAJPObjectCount++] = object;
    return NO;
}

static BOOL HFAJPSeenClass(Class cls) {
    if (!cls) return YES;
    for (unsigned i = 0; i < gHFAJPClassCount; i++) if (gHFAJPClasses[i] == cls) return YES;
    if (gHFAJPClassCount < sizeof(gHFAJPClasses) / sizeof(gHFAJPClasses[0]))
        gHFAJPClasses[gHFAJPClassCount++] = cls;
    return NO;
}

static BOOL HFAJPIsFrameworkClass(Class cls) {
    const char *name = cls ? class_getName(cls) : NULL;
    if (!name) return YES;
    return strncmp(name, "NS", 2) == 0 || strncmp(name, "__NS", 4) == 0 ||
           strncmp(name, "UI", 2) == 0 || strncmp(name, "_UI", 3) == 0 ||
           strncmp(name, "CA", 2) == 0 || strncmp(name, "CG", 2) == 0 ||
           strncmp(name, "HFAMap", 6) == 0;
}

static size_t HFAJPPrimitiveSize(const char *type) {
    if (!type || !*type) return 0;
    while (*type == 'r' || *type == 'n' || *type == 'N' || *type == 'o' || *type == 'O' || *type == 'R' || *type == 'V') type++;
    switch (*type) {
        case 'c': case 'C': case 'B': return 1;
        case 's': case 'S': return 2;
        case 'i': case 'I': case 'f': return 4;
        case 'l': case 'L': case 'q': case 'Q': case 'd': return 8;
        case '^': case '*': case '#': case ':': return sizeof(void *);
        default: return 0;
    }
}

static NSString *HFAJPHex(const void *bytes, size_t size) {
    if (!bytes || !size || size > 32) return nil;
    const uint8_t *p = (const uint8_t *)bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:size * 2];
    for (size_t i = 0; i < size; i++) [s appendFormat:@"%02X", p[i]];
    return s;
}

static void HFAJPProfileMethods(Class cls) {
    if (!cls || HFAJPSeenClass(cls) || HFAJPIsFrameworkClass(cls)) return;
    const char *cn = class_getName(cls);
    unsigned count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    if (count > 160) count = 160;
    HFAJPLog("[JAILPATCH-CLASS] class=%s methods=%u instanceSize=%llu\n",
             cn ?: "?", count, (unsigned long long)class_getInstanceSize(cls));
    NSMutableArray *jsonMethods = [NSMutableArray array];
    for (unsigned i = 0; methods && i < count; i++) {
        SEL sel = method_getName(methods[i]);
        const char *sn = sel ? sel_getName(sel) : "?";
        const char *types = method_getTypeEncoding(methods[i]);
        IMP imp = method_getImplementation(methods[i]);
        NSDictionary *addr = HFAJPAddressInfo((const void *)imp);
        HFAJPLog("[JAILPATCH-METHOD] class=%s selector=%s types=%s image=%s rva=%s\n",
                 cn ?: "?", sn ?: "?", types ?: "?",
                 [[addr objectForKey:@"image"] UTF8String] ?: "?",
                 [[addr objectForKey:@"rva"] UTF8String] ?: "?");
        NSMutableDictionary *m = [@{
            @"selector": [NSString stringWithUTF8String:sn ?: "?"],
            @"types": [NSString stringWithUTF8String:types ?: "?"]
        } mutableCopy];
        if (addr) [m addEntriesFromDictionary:addr];
        [jsonMethods addObject:m];
    }
    free(methods);
    HFAJPJSON(@{
        @"record": @"jailpatch-class",
        @"class": [NSString stringWithUTF8String:cn ?: "?"],
        @"instanceSize": @(class_getInstanceSize(cls)),
        @"methods": jsonMethods
    });
}

static NSString *HFAJPString(id value) {
    return [value isKindOfClass:[NSString class]] ? (NSString *)value : nil;
}

static BOOL HFAJPIsCollection(id value) {
    return [value isKindOfClass:[NSArray class]] || [value isKindOfClass:[NSSet class]];
}

static NSArray *HFAJPArray(id value) {
    if ([value isKindOfClass:[NSArray class]]) return value;
    if ([value isKindOfClass:[NSSet class]]) return [(NSSet *)value allObjects];
    return nil;
}

static NSDictionary *HFAJPBlockInfo(id value) {
    if (!value) return nil;
    const char *cn = class_getName(object_getClass(value));
    if (!cn || !strstr(cn, "Block")) return nil;
    struct HFAJPBlockLiteral *b = (struct HFAJPBlockLiteral *)(void *)value;
    NSDictionary *invoke = HFAJPAddressInfo((const void *)b->invoke);
    NSMutableDictionary *result = [@{
        @"class": [NSString stringWithUTF8String:cn],
        @"pointer": [NSString stringWithFormat:@"%p", value]
    } mutableCopy];
    if (invoke) result[@"invoke"] = invoke;
    return result;
}

static void HFAJPProfileObject(id object, NSString *featureID, NSString *path, unsigned depth);

static void HFAJPProfileDictionary(NSDictionary *dict, NSString *featureID, NSString *path, unsigned depth) {
    if (!dict || depth > 4) return;
    for (id key in dict) {
        id value = dict[key];
        NSString *ks = [key isKindOfClass:[NSString class]] ? key : [key description];
        NSString *next = [path stringByAppendingFormat:@".%@", ks ?: @"?"];
        HFAJPProfileObject(value, featureID, next, depth + 1);
    }
}

static void HFAJPProfileObject(id object, NSString *featureID, NSString *path, unsigned depth) {
    if (!object || depth > 4 || HFAJPSeenObject(object)) return;
    Class cls = object_getClass(object);
    if (!cls) return;
    const char *cn = class_getName(cls);

    if ([object isKindOfClass:[NSString class]]) {
        NSString *s = (NSString *)object;
        HFAJPLog("[JAILPATCH-STRING] feature=%s path=%s class=%s value=%s\n",
                 featureID.UTF8String ?: "?", path.UTF8String ?: "?", cn ?: "?", s.UTF8String ?: "?");
        HFAJPJSON(@{ @"record": @"jailpatch-string", @"feature": featureID ?: @"", @"path": path ?: @"", @"value": s });
        return;
    }
    if ([object isKindOfClass:[NSNumber class]]) {
        HFAJPJSON(@{ @"record": @"jailpatch-number", @"feature": featureID ?: @"", @"path": path ?: @"", @"value": object });
        return;
    }
    if ([object isKindOfClass:[NSDictionary class]]) {
        HFAJPProfileDictionary((NSDictionary *)object, featureID, path, depth);
        return;
    }
    if (HFAJPIsCollection(object)) {
        NSArray *a = HFAJPArray(object);
        NSUInteger n = MIN(a.count, (NSUInteger)64);
        for (NSUInteger i = 0; i < n; i++)
            HFAJPProfileObject(a[i], featureID, [path stringByAppendingFormat:@"[%lu]", (unsigned long)i], depth + 1);
        return;
    }

    NSDictionary *block = HFAJPBlockInfo(object);
    if (block) {
        HFAJPLog("[JAILPATCH-BLOCK] feature=%s path=%s class=%s invokeImage=%s invokeRVA=%s\n",
                 featureID.UTF8String ?: "?", path.UTF8String ?: "?", cn ?: "?",
                 [[[block objectForKey:@"invoke"] objectForKey:@"image"] UTF8String] ?: "?",
                 [[[block objectForKey:@"invoke"] objectForKey:@"rva"] UTF8String] ?: "?");
        HFAJPJSON(@{ @"record": @"jailpatch-block", @"feature": featureID ?: @"", @"path": path ?: @"", @"block": block });
        return;
    }

    HFAJPProfileMethods(cls);
    NSMutableArray *fields = [NSMutableArray array];
    NSUInteger instanceSize = class_getInstanceSize(cls);
    for (Class cursor = cls; cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        if (count > 96) count = 96;
        for (unsigned i = 0; ivars && i < count; i++) {
            Ivar iv = ivars[i];
            const char *name = ivar_getName(iv);
            const char *type = ivar_getTypeEncoding(iv);
            ptrdiff_t off = ivar_getOffset(iv);
            NSMutableDictionary *field = [@{
                @"owner": [NSString stringWithUTF8String:class_getName(cursor) ?: "?"],
                @"name": [NSString stringWithUTF8String:name ?: "?"],
                @"type": [NSString stringWithUTF8String:type ?: "?"],
                @"offset": [NSString stringWithFormat:@"0x%llX", (unsigned long long)off]
            } mutableCopy];
            if (type && type[0] == '@') {
                id value = nil;
                @try { value = object_getIvar(object, iv); } @catch (__unused id exception) { value = nil; }
                const char *vcn = value ? class_getName(object_getClass(value)) : "(nil)";
                field[@"valueClass"] = [NSString stringWithUTF8String:vcn ?: "?"];
                if (value) field[@"pointer"] = [NSString stringWithFormat:@"%p", value];
                NSString *sv = HFAJPString(value);
                if (sv.length) field[@"string"] = sv;
                NSDictionary *bi = HFAJPBlockInfo(value);
                if (bi) field[@"block"] = bi;
                HFAJPLog("[JAILPATCH-IVAR] feature=%s path=%s object=%p class=%s owner=%s name=%s type=%s offset=0x%llX valueClass=%s value=%p%s%s\n",
                         featureID.UTF8String ?: "?", path.UTF8String ?: "?", object, cn ?: "?",
                         class_getName(cursor) ?: "?", name ?: "?", type ?: "?", (unsigned long long)off,
                         vcn ?: "?", value,
                         sv.length ? " string=" : "", sv.length ? sv.UTF8String : "");
                if (value && !sv.length && !bi && !HFAJPIsFrameworkClass(object_getClass(value)))
                    HFAJPProfileObject(value, featureID, [path stringByAppendingFormat:@".%s", name ?: "?"], depth + 1);
            } else {
                size_t size = HFAJPPrimitiveSize(type);
                if (size && off >= 0 && (NSUInteger)off + size <= instanceSize) {
                    uint8_t raw[16] = {0};
                    if (size > sizeof(raw)) size = sizeof(raw);
                    memcpy(raw, (const uint8_t *)(__bridge const void *)object + off, size);
                    NSString *hex = HFAJPHex(raw, size);
                    if (hex) field[@"raw"] = hex;
                    HFAJPLog("[JAILPATCH-SCALAR] feature=%s path=%s object=%p class=%s owner=%s name=%s type=%s offset=0x%llX raw=%s\n",
                             featureID.UTF8String ?: "?", path.UTF8String ?: "?", object, cn ?: "?",
                             class_getName(cursor) ?: "?", name ?: "?", type ?: "?",
                             (unsigned long long)off, hex.UTF8String ?: "?");
                }
            }
            [fields addObject:field];
        }
        free(ivars);
    }
    HFAJPJSON(@{
        @"record": @"jailpatch-object",
        @"feature": featureID ?: @"",
        @"path": path ?: @"",
        @"pointer": [NSString stringWithFormat:@"%p", object],
        @"class": [NSString stringWithUTF8String:cn ?: "?"],
        @"instanceSize": @(instanceSize),
        @"fields": fields
    });
}

static BOOL HFAJPFeatureDictionary(NSDictionary *dict, NSString **labelOut, NSString **identifierOut) {
    if (![dict isKindOfClass:[NSDictionary class]]) return NO;
    id label = dict[@"label"];
    id identifier = dict[@"identifier"];
    if (![label isKindOfClass:[NSString class]] || ![(NSString *)label length] ||
        ![identifier isKindOfClass:[NSString class]] || ![(NSString *)identifier length]) return NO;
    if (labelOut) *labelOut = label;
    if (identifierOut) *identifierOut = identifier;
    return YES;
}

static NSArray *HFAJPFindFeatureArray(id target, NSString **ivarNameOut) {
    if (ivarNameOut) *ivarNameOut = nil;
    NSArray *best = nil;
    NSString *bestName = nil;
    for (Class cursor = object_getClass(target); cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        if (count > 96) count = 96;
        for (unsigned i = 0; ivars && i < count; i++) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            if (!type || type[0] != '@') continue;
            id value = nil;
            @try { value = object_getIvar(target, ivars[i]); } @catch (__unused id exception) { value = nil; }
            if (![value isKindOfClass:[NSArray class]]) continue;
            NSArray *a = value;
            if (!a.count || a.count > 64) continue;
            NSUInteger valid = 0;
            for (id item in a) if (HFAJPFeatureDictionary(item, NULL, NULL)) valid++;
            if (valid == a.count && (!best || a.count > best.count)) {
                best = a;
                const char *name = ivar_getName(ivars[i]);
                bestName = [NSString stringWithUTF8String:name ?: "?"];
            }
        }
        free(ivars);
    }
    if (ivarNameOut) *ivarNameOut = bestName;
    return best;
}

static NSArray *HFAJPRuntimeRecordArrays(NSDictionary *feature, NSString **keyOut) {
    if (keyOut) *keyOut = nil;
    NSArray *best = nil;
    NSString *bestKey = nil;
    for (id key in feature) {
        if ([key isEqual:@"label"] || [key isEqual:@"identifier"] || [key isEqual:@"desc"] || [key isEqual:@"type"]) continue;
        id value = feature[key];
        NSArray *a = HFAJPArray(value);
        if (!a.count || a.count > 128) continue;
        NSUInteger custom = 0;
        for (id item in a) {
            Class cls = item ? object_getClass(item) : Nil;
            if (cls && !HFAJPIsFrameworkClass(cls)) custom++;
        }
        if (custom && (!best || custom > best.count)) {
            best = a;
            bestKey = [key isKindOfClass:[NSString class]] ? key : [key description];
        }
    }
    if (keyOut) *keyOut = bestKey;
    return best;
}

void HFAJailpatchProfileTarget(id target, const char *context) {
    if (!target || HFAJPSeenTarget(target)) return;
    @autoreleasepool {
        @try {
            NSString *arrayIvar = nil;
            NSArray *features = HFAJPFindFeatureArray(target, &arrayIvar);
            if (!features.count) return;
            Class cls = object_getClass(target);
            NSDictionary *targetImage = HFAJPAddressInfo((const void *)class_getMethodImplementation(cls, sel_registerName("class")));
            HFAJPLog("[JAILPATCH-TARGET] context=%s target=%p class=%s featureArrayIvar=%s features=%u version=%s\n",
                     context ?: "?", target, class_getName(cls) ?: "?", arrayIvar.UTF8String ?: "?",
                     (unsigned)features.count, kHFAJPVersion);
            HFAJPJSON(@{
                @"record": @"jailpatch-target",
                @"context": [NSString stringWithUTF8String:context ?: "?"],
                @"pointer": [NSString stringWithFormat:@"%p", target],
                @"class": [NSString stringWithUTF8String:class_getName(cls) ?: "?"],
                @"featureArrayIvar": arrayIvar ?: @"",
                @"featureCount": @(features.count),
                @"imageHint": targetImage ?: @{}
            });
            NSUInteger featureIndex = 0;
            for (NSDictionary *feature in features) {
                NSString *label = nil, *identifier = nil;
                if (!HFAJPFeatureDictionary(feature, &label, &identifier)) continue;
                NSString *recordsKey = nil;
                NSArray *records = HFAJPRuntimeRecordArrays(feature, &recordsKey);
                HFAJPLog("[JAILPATCH-FEATURE] index=%u identifier=%s label=\"%s\" recordsKey=%s records=%u\n",
                         (unsigned)featureIndex, identifier.UTF8String ?: "?", label.UTF8String ?: "?",
                         recordsKey.UTF8String ?: "?", (unsigned)records.count);
                HFAJPJSON(@{
                    @"record": @"jailpatch-feature",
                    @"index": @(featureIndex),
                    @"identifier": identifier,
                    @"label": label,
                    @"recordsKey": recordsKey ?: @"",
                    @"recordCount": @(records.count)
                });
                NSUInteger recordIndex = 0;
                for (id record in records) {
                    Class rc = record ? object_getClass(record) : Nil;
                    HFAJPLog("[JAILPATCH-RECORD] feature=%s index=%u object=%p class=%s\n",
                             identifier.UTF8String ?: "?", (unsigned)recordIndex, record, rc ? class_getName(rc) : "?");
                    HFAJPJSON(@{
                        @"record": @"jailpatch-runtime-record",
                        @"feature": identifier,
                        @"index": @(recordIndex),
                        @"pointer": [NSString stringWithFormat:@"%p", record],
                        @"class": rc ? [NSString stringWithUTF8String:class_getName(rc)] : @"?"
                    });
                    HFAJPProfileObject(record, identifier,
                                       [NSString stringWithFormat:@"feature[%@].records[%lu]", identifier, (unsigned long)recordIndex], 0);
                    recordIndex++;
                }
                featureIndex++;
            }
        } @catch (__unused id exception) {
            HFAJPLog("[JAILPATCH-PROFILE-ERROR] context=%s target=%p reason=objc-exception\n", context ?: "?", target);
        }
    }
}

__attribute__((constructor)) static void HFAJPInit(void) {
    HFAJPLog("[HFALearn v1.9.29 JailpatchRuntimeProfiler] loaded\n");
}

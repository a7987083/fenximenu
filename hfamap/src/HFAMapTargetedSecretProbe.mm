#import "HFAMapTargetedSecretProbe.h"

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

typedef int (*HFASecretDecryptFn)(void *, void *);

typedef struct {
    Class owner;
    Method method;
    IMP original;
} HFATargetedSecretHook;

static HFATargetedSecretHook gHooks[64];
static unsigned gHookCount;
static BOOL gActive;
static NSUInteger gGeneration;
static NSString *gSelectedPath;
static NSString *gSelectedImage;
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

static void HFATSPLog(const char *fmt, ...) {
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

static uintptr_t HFAStripCodePointer(uintptr_t value) {
#if __has_feature(ptrauth_calls)
    return (uintptr_t)ptrauth_strip((void *)value, ptrauth_key_function_pointer);
#else
    return value;
#endif
}

static BOOL HFASafeRead(uintptr_t address, void *output, size_t length) {
    if (!address || !output || !length) return NO;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)address,
                                         (vm_size_t)length, (vm_address_t)output, &copied);
    return kr == KERN_SUCCESS && copied == length;
}

static BOOL HFAPathMatchesSelected(const char *raw) {
    if (!raw || !gSelectedPath.length) return NO;
    NSString *path = [NSString stringWithUTF8String:raw];
    if ([path isEqualToString:gSelectedPath]) return YES;
    return [path.lastPathComponent isEqualToString:gSelectedImage];
}

static IMP HFAOriginalForObject(id object) {
    if (!object) return NULL;
    Class cls = object_getClass(object);
    pthread_mutex_lock(&gLock);
    while (cls) {
        for (unsigned i = 0; i < gHookCount; ++i) {
            if (gHooks[i].owner == cls) {
                IMP original = gHooks[i].original;
                pthread_mutex_unlock(&gLock);
                return original;
            }
        }
        cls = class_getSuperclass(cls);
    }
    pthread_mutex_unlock(&gLock);
    return NULL;
}

static BOOL HFATextRangeForBase(const void *base, uintptr_t *startOut, uintptr_t *endOut) {
    if (!base) return NO;
    uint32_t count = MIN(_dyld_image_count(), 2048U);
    for (uint32_t i = 0; i < count; ++i) {
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if ((const void *)mh != base || !mh || mh->magic != MH_MAGIC_64 ||
            mh->ncmds > 4096 || mh->sizeofcmds > 4U * 1024U * 1024U) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const uint8_t *cursor = (const uint8_t *)(mh + 1);
        const uint8_t *end = cursor + mh->sizeofcmds;
        for (uint32_t c = 0; c < mh->ncmds && cursor + sizeof(struct load_command) <= end; ++c) {
            const struct load_command *lc = (const struct load_command *)cursor;
            if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) return NO;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
                if (sizeof(*seg) + (uint64_t)seg->nsects * sizeof(struct section_64) > lc->cmdsize)
                    return NO;
                const struct section_64 *sections = (const struct section_64 *)(seg + 1);
                for (uint32_t s = 0; s < seg->nsects; ++s) {
                    if (strncmp(sections[s].segname, "__TEXT", 16) != 0 ||
                        strncmp(sections[s].sectname, "__text", 16) != 0) continue;
                    uintptr_t start = (uintptr_t)slide + (uintptr_t)sections[s].addr;
                    uintptr_t size = (uintptr_t)sections[s].size;
                    if (!size || size > 64U * 1024U * 1024U || UINTPTR_MAX - start < size) return NO;
                    if (startOut) *startOut = start;
                    if (endOut) *endOut = start + size;
                    return YES;
                }
            }
            cursor += lc->cmdsize;
        }
    }
    return NO;
}

static uintptr_t HFAUniqueDecryptForOriginal(IMP original, unsigned *matchesOut) {
    if (matchesOut) *matchesOut = 0;
    Dl_info info = {};
    uintptr_t getter = HFAStripCodePointer((uintptr_t)original);
    if (!getter || !dladdr((const void *)getter, &info) || !info.dli_fbase ||
        !HFAPathMatchesSelected(info.dli_fname)) return 0;
    uintptr_t start = 0, end = 0;
    if (!HFATextRangeForBase(info.dli_fbase, &start, &end)) return 0;
    uintptr_t found = 0;
    unsigned matches = 0;
    for (uintptr_t pc = (start + 3U) & ~(uintptr_t)3U;
         pc <= end && end - pc >= 0x44U; pc += 4U) {
        uint32_t a = 0, b = 0, c = 0;
        if (!HFASafeRead(pc, &a, sizeof(a)) || a != 0xD105C3FFU) continue;
        if (!HFASafeRead(pc + 0x30U, &b, sizeof(b)) || b != 0xB9400408U) continue;
        if (!HFASafeRead(pc + 0x40U, &c, sizeof(c)) || c != 0x53187D00U) continue;
        ++matches;
        found = matches == 1U ? pc : 0;
        if (matches > 1U) break;
    }
    if (matchesOut) *matchesOut = matches;
    return matches == 1U ? found : 0;
}

static BOOL HFAPlainIsHexRVA(const char *plain, size_t limit) {
    if (!plain || limit < 3 || plain[0] != '0' || (plain[1] != 'x' && plain[1] != 'X')) return NO;
    size_t i = 2;
    BOOL digit = NO;
    for (; i < limit && plain[i]; ++i) {
        char c = plain[i];
        BOOL hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return NO;
        digit = YES;
    }
    return digit && i < limit;
}

static void *HFATargetedSecretReplacement(id self, SEL _cmd) {
    IMP original = HFAOriginalForObject(self);
    if (!original) return NULL;
    void *secret = ((void *(*)(id, SEL))original)(self, _cmd);
    if (!secret) return NULL;

    uint32_t header[2] = {};
    if (!HFASafeRead((uintptr_t)secret, header, sizeof(header))) return secret;
    uint32_t length = header[0], flags = header[1];
    if (!length || length > 0x10000U) return secret;
    size_t blobSize = (size_t)(length & ~0xFU) + 0x28U;
    if (blobSize < 0x28U || blobSize > 0x11000U) return secret;

    unsigned matches = 0;
    uintptr_t decrypt = HFAUniqueDecryptForOriginal(original, &matches);
    Dl_info info = {};
    uintptr_t getter = HFAStripCodePointer((uintptr_t)original);
    dladdr((const void *)getter, &info);
    uintptr_t getterRVA = info.dli_fbase ? getter - (uintptr_t)info.dli_fbase : 0;
    uintptr_t decryptRVA = (decrypt && info.dli_fbase) ? decrypt - (uintptr_t)info.dli_fbase : 0;

    if (!decrypt) {
        HFATSPLog("[TARGETED-SECRET-SKIP] class=%s image=%s getterRVA=%llX len=%u flags=%08X keySlot=%u decryptMatches=%u\n",
                  class_getName(object_getClass(self)), gSelectedImage.UTF8String ?: "?",
                  (unsigned long long)getterRVA, length, flags, flags >> 24, matches);
        return secret;
    }

    void *copy = malloc(blobSize);
    char *plain = (char *)calloc(1, (size_t)length + 1U);
    if (!copy || !plain) { free(copy); free(plain); return secret; }
    if (!HFASafeRead((uintptr_t)secret, copy, blobSize)) {
        free(copy); free(plain); return secret;
    }
    int rc = ((HFASecretDecryptFn)decrypt)(copy, plain);
    BOOL valid = rc == 0 && HFAPlainIsHexRVA(plain, (size_t)length + 1U);
    HFATSPLog("[TARGETED-SECRET] class=%s image=%s getterRVA=%llX decryptRVA=%llX descriptor=%p len=%u flags=%08X keySlot=%u rc=%d plain=%s validHexRVA=%d\n",
              class_getName(object_getClass(self)), gSelectedImage.UTF8String ?: "?",
              (unsigned long long)getterRVA, (unsigned long long)decryptRVA,
              secret, length, flags, flags >> 24, rc, valid ? plain : "?", valid ? 1 : 0);
    free(copy);
    free(plain);
    return secret;
}

static Method HFAClassOwnSecretMethod(Class cls) {
    if (!cls) return NULL;
    SEL secret = sel_registerName("secret");
    unsigned count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    Method found = NULL;
    for (unsigned i = 0; methods && i < count; ++i) {
        if (method_getName(methods[i]) == secret) { found = methods[i]; break; }
    }
    if (methods) free(methods);
    return found;
}

BOOL HFAMapTargetedSecretProbeIsActive(void) {
    pthread_mutex_lock(&gLock);
    BOOL active = gActive;
    pthread_mutex_unlock(&gLock);
    return active;
}

void HFAMapStopTargetedSecretProbe(NSString *reason) {
    pthread_mutex_lock(&gLock);
    if (!gActive && !gHookCount) { pthread_mutex_unlock(&gLock); return; }
    unsigned count = gHookCount;
    HFATargetedSecretHook local[64] = {};
    memcpy(local, gHooks, sizeof(HFATargetedSecretHook) * count);
    gHookCount = 0;
    gActive = NO;
    ++gGeneration;
    pthread_mutex_unlock(&gLock);

    for (unsigned i = 0; i < count; ++i) {
        if (!local[i].method || !local[i].original) continue;
        IMP current = method_getImplementation(local[i].method);
        if (current == (IMP)HFATargetedSecretReplacement)
            method_setImplementation(local[i].method, local[i].original);
    }
    HFATSPLog("[TARGETED-SECRET-PROBE] stop reason=%s restored=%u\n",
              (reason ?: @"unknown").UTF8String, count);
}

NSDictionary *HFAMapArmTargetedSecretProbe(NSDictionary *candidate, NSTimeInterval duration) {
    HFAMapStopTargetedSecretProbe(@"rearm");
    NSString *path = [candidate[@"path"] isKindOfClass:NSString.class] ? candidate[@"path"] : nil;
    NSString *image = [candidate[@"image"] isKindOfClass:NSString.class] ? candidate[@"image"] : path.lastPathComponent;
    if (!path.length || !image.length)
        return @{ @"status": @"missing-selected-image", @"installed": @0 };

    [gSelectedPath release];
    [gSelectedImage release];
    gSelectedPath = [path copy];
    gSelectedImage = [image copy];

    unsigned classCount = 0;
    const char **names = objc_copyClassNamesForImage(path.fileSystemRepresentation, &classCount);
    unsigned bounded = MIN(classCount, 512U);
    unsigned candidates = 0, installed = 0, rejectedOwner = 0, rejectedABI = 0;

    pthread_mutex_lock(&gLock);
    gActive = YES;
    NSUInteger generation = ++gGeneration;
    pthread_mutex_unlock(&gLock);

    for (unsigned i = 0; names && i < bounded && installed < 64U; ++i) {
        Class cls = objc_getClass(names[i]);
        Method method = HFAClassOwnSecretMethod(cls);
        if (!method) continue;
        ++candidates;
        if (method_getNumberOfArguments(method) != 2U) { ++rejectedABI; continue; }
        char *returnType = method_copyReturnType(method);
        char lead = returnType && *returnType ? *returnType : 0;
        if (returnType) free(returnType);
        if (lead != '^' && lead != '*' && lead != '@') { ++rejectedABI; continue; }
        IMP original = method_getImplementation(method);
        Dl_info info = {};
        uintptr_t stripped = HFAStripCodePointer((uintptr_t)original);
        if (!stripped || !dladdr((const void *)stripped, &info) || !HFAPathMatchesSelected(info.dli_fname)) {
            ++rejectedOwner;
            continue;
        }
        pthread_mutex_lock(&gLock);
        if (!gActive || generation != gGeneration || gHookCount >= 64U) {
            pthread_mutex_unlock(&gLock);
            break;
        }
        gHooks[gHookCount++] = { cls, method, original };
        pthread_mutex_unlock(&gLock);
        method_setImplementation(method, (IMP)HFATargetedSecretReplacement);
        ++installed;
    }
    if (names) free(names);

    HFATSPLog("[TARGETED-SECRET-PROBE] arm image=%s classCount=%u inspected=%u secretCandidates=%u installed=%u rejectedOwner=%u rejectedABI=%u duration=%.1f policy=image-scoped-explicit-arm-no-global-scan\n",
              image.UTF8String, classCount, bounded, candidates, installed,
              rejectedOwner, rejectedABI, duration);

    NSTimeInterval seconds = duration > 0.0 ? duration : 8.0;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        pthread_mutex_lock(&gLock);
        BOOL same = gActive && generation == gGeneration;
        pthread_mutex_unlock(&gLock);
        if (same) HFAMapStopTargetedSecretProbe(@"timeout");
    });

    return @{ @"status": installed ? @"armed" : @"no-secret-methods",
              @"image": image, @"classCount": @(classCount), @"inspectedClassCount": @(bounded),
              @"secretCandidates": @(candidates), @"installed": @(installed),
              @"rejectedOwner": @(rejectedOwner), @"rejectedABI": @(rejectedABI),
              @"duration": @(seconds),
              @"policy": @"selected-image-only-explicit-arm-temporary-hook" };
}

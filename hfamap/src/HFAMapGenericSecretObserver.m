#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dispatch/dispatch.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

// HFAMap v2.4.3 GenericSecretObserver
//
// Purpose:
//   Observe existing `-secret` wrapper accesses without changing game values.
//   The observer calls the original getter first, validates the descriptor,
//   resolves the image-local decrypt routine by a bounded unique ARM64
//   fingerprint scan, invokes the same decrypt routine on a scratch copy, and
//   logs the resulting plaintext together with descriptor/caller provenance.
//
// Important boundaries:
//   * no hard-coded image name, class name, decrypt RVA, key slot or target RVA;
//   * no `getter + fixed delta` rule;
//   * no raw runtime key bytes are read or logged;
//   * decrypt is accepted only when the fingerprint is unique in __TEXT,__text;
//   * all descriptor reads use vm_read_overwrite and fail closed;
//   * original `-secret` behavior is preserved.

typedef int (*HFASecretDecryptFn)(void *, void *);

typedef struct {
    Class owner;
    IMP original;
} HFASecretHookEntry;

typedef struct {
    const void *imageBase;
    uintptr_t decryptAddress;
    unsigned matches;
} HFADecryptCacheEntry;

typedef struct {
    uintptr_t descriptor;
    uint32_t flags;
} HFASeenDescriptor;

static HFASecretHookEntry gSecretHooks[256];
static unsigned gSecretHookCount;
static HFADecryptCacheEntry gDecryptCache[64];
static unsigned gDecryptCacheCount;
static HFASeenDescriptor gSeenDescriptors[512];
static unsigned gSeenDescriptorCount;
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;
static int gScanScheduled;

static void HFAGSOLog(const char *fmt, ...) {
    @autoreleasepool {
        NSString *path = [NSHomeDirectory()
            stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];
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

static const char *HFABaseName(const char *path) {
    const char *slash = path ? strrchr(path, '/') : NULL;
    return slash ? slash + 1 : (path ? path : "?");
}

static uintptr_t HFAStripCodePointer(uintptr_t value) {
#if __has_feature(ptrauth_calls)
    return (uintptr_t)ptrauth_strip((void *)value, ptrauth_key_function_pointer);
#else
    return value;
#endif
}

static int HFASafeRead(uintptr_t address, void *output, size_t length) {
    if (!address || !output || !length) return 0;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                          (vm_address_t)address,
                                          (vm_size_t)length,
                                          (vm_address_t)output,
                                          &copied);
    return kr == KERN_SUCCESS && copied == length;
}

static int HFADecryptFingerprint(uintptr_t address) {
    uint32_t words[3] = {0};
    if (!HFASafeRead(address, &words[0], 4) ||
        !HFASafeRead(address + 0x30u, &words[1], 4) ||
        !HFASafeRead(address + 0x40u, &words[2], 4)) return 0;
    return words[0] == 0xD105C3FFu &&
           words[1] == 0xB9400408u &&
           words[2] == 0x53187D00u;
}

static int HFATextRangeForImage(const void *imageBase,
                                uintptr_t *startOut,
                                uintptr_t *endOut) {
    if (!imageBase || !startOut || !endOut) return 0;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)imageBase;
    if (mh->magic != MH_MAGIC_64) return 0;
    const uint8_t *cursor = (const uint8_t *)(mh + 1);
    uintptr_t slide = 0;
    int slideKnown = 0;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc->cmdsize || lc->cmdsize > 0x10000u) return 0;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cursor;
            if (!slideKnown && strncmp(seg->segname, "__TEXT", 16) == 0) {
                slide = (uintptr_t)imageBase - (uintptr_t)seg->vmaddr;
                slideKnown = 1;
            }
        }
        cursor += lc->cmdsize;
    }
    if (!slideKnown) return 0;

    cursor = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc->cmdsize || lc->cmdsize > 0x10000u) return 0;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cursor;
            const struct section_64 *sec =
                (const struct section_64 *)(seg + 1);
            for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
                if (strncmp(sec->segname, "__TEXT", 16) != 0 ||
                    strncmp(sec->sectname, "__text", 16) != 0) continue;
                uintptr_t start = slide + (uintptr_t)sec->addr;
                uintptr_t end = start + (uintptr_t)sec->size;
                if (end <= start || sec->size < 0x44u ||
                    sec->size > 0x4000000u) return 0;
                *startOut = start;
                *endOut = end;
                return 1;
            }
        }
        cursor += lc->cmdsize;
    }
    return 0;
}

static uintptr_t HFAResolveDecrypt(const void *imageBase, unsigned *matchesOut) {
    if (matchesOut) *matchesOut = 0;
    if (!imageBase) return 0;

    pthread_mutex_lock(&gLock);
    for (unsigned i = 0; i < gDecryptCacheCount; i++) {
        if (gDecryptCache[i].imageBase == imageBase) {
            uintptr_t address = gDecryptCache[i].decryptAddress;
            unsigned matches = gDecryptCache[i].matches;
            pthread_mutex_unlock(&gLock);
            if (matchesOut) *matchesOut = matches;
            return address;
        }
    }
    pthread_mutex_unlock(&gLock);

    uintptr_t start = 0, end = 0;
    if (!HFATextRangeForImage(imageBase, &start, &end)) return 0;
    uintptr_t found = 0;
    unsigned matches = 0;
    uintptr_t last = end - 0x44u;
    for (uintptr_t pc = (start + 3u) & ~(uintptr_t)3u;
         pc <= last; pc += 4u) {
        if (!HFADecryptFingerprint(pc)) continue;
        matches++;
        found = matches == 1u ? pc : 0;
        if (matches > 1u) {
            // Keep scanning only to report the true ambiguity count.
            found = 0;
        }
    }

    pthread_mutex_lock(&gLock);
    if (gDecryptCacheCount < sizeof(gDecryptCache) / sizeof(gDecryptCache[0])) {
        HFADecryptCacheEntry *entry = &gDecryptCache[gDecryptCacheCount++];
        entry->imageBase = imageBase;
        entry->decryptAddress = matches == 1u ? found : 0;
        entry->matches = matches;
    }
    pthread_mutex_unlock(&gLock);

    if (matchesOut) *matchesOut = matches;
    return matches == 1u ? found : 0;
}

static IMP HFAOriginalSecretForObject(id object) {
    Class cls = object ? object_getClass(object) : Nil;
    pthread_mutex_lock(&gLock);
    while (cls) {
        for (unsigned i = 0; i < gSecretHookCount; i++) {
            if (gSecretHooks[i].owner == cls) {
                IMP imp = gSecretHooks[i].original;
                pthread_mutex_unlock(&gLock);
                return imp;
            }
        }
        cls = class_getSuperclass(cls);
    }
    pthread_mutex_unlock(&gLock);
    return NULL;
}

static int HFAFirstObservation(uintptr_t descriptor, uint32_t flags) {
    pthread_mutex_lock(&gLock);
    for (unsigned i = 0; i < gSeenDescriptorCount; i++) {
        if (gSeenDescriptors[i].descriptor == descriptor &&
            gSeenDescriptors[i].flags == flags) {
            pthread_mutex_unlock(&gLock);
            return 0;
        }
    }
    if (gSeenDescriptorCount <
        sizeof(gSeenDescriptors) / sizeof(gSeenDescriptors[0])) {
        gSeenDescriptors[gSeenDescriptorCount].descriptor = descriptor;
        gSeenDescriptors[gSeenDescriptorCount].flags = flags;
        gSeenDescriptorCount++;
    }
    pthread_mutex_unlock(&gLock);
    return 1;
}

static int HFAPlainLooksUseful(const char *plain, size_t length) {
    if (!plain || !length) return 0;
    if (length >= 3 && plain[0] == '0' &&
        (plain[1] == 'x' || plain[1] == 'X')) return 1;
    size_t printable = 0;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)plain[i];
        if (!c) break;
        if (c >= 0x20 && c <= 0x7e) printable++;
        else return 0;
    }
    return printable > 0;
}

static void *HFASecretObserver(id self, SEL _cmd) {
    IMP original = HFAOriginalSecretForObject(self);
    if (!original) return NULL;
    void *secret = ((void *(*)(id, SEL))original)(self, _cmd);
    if (!secret) return NULL;

    uint32_t header[2] = {0};
    if (!HFASafeRead((uintptr_t)secret, header, sizeof(header))) return secret;
    uint32_t len = header[0];
    uint32_t flags = header[1];
    if (!len || len > 0x10000u) return secret;
    size_t blobSize = (size_t)(len & ~0xFu) + 0x28u;
    if (blobSize <= 0x28u) blobSize = 0x28u;
    if (blobSize > 0x11000u) return secret;
    if (!HFAFirstObservation((uintptr_t)secret, flags)) return secret;

    Dl_info getterInfo = {0};
    Dl_info secretInfo = {0};
    uintptr_t getter = HFAStripCodePointer((uintptr_t)original);
    if (!dladdr((const void *)getter, &getterInfo) || !getterInfo.dli_fbase)
        return secret;
    dladdr(secret, &secretInfo);

    unsigned matches = 0;
    uintptr_t decrypt = HFAResolveDecrypt(getterInfo.dli_fbase, &matches);
    uintptr_t getterRVA = getter - (uintptr_t)getterInfo.dli_fbase;
    uintptr_t descriptorRVA = 0;
    const char *descriptorImage = "?";
    if (secretInfo.dli_fbase) {
        descriptorRVA = (uintptr_t)secret - (uintptr_t)secretInfo.dli_fbase;
        descriptorImage = HFABaseName(secretInfo.dli_fname);
    }
    uintptr_t caller = HFAStripCodePointer(
        (uintptr_t)__builtin_return_address(0));
    Dl_info callerInfo = {0};
    dladdr((const void *)caller, &callerInfo);
    uintptr_t callerRVA = callerInfo.dli_fbase
        ? caller - (uintptr_t)callerInfo.dli_fbase : 0;

    unsigned slot = flags >> 24;
    if (!decrypt) {
        HFAGSOLog("[SECRET-OBSERVE-SKIP] class=%s image=%s getterRVA=%llX descriptorImage=%s descriptorRVA=%llX len=%u flags=%08X keySlot=%u decryptMatches=%u callerImage=%s callerRVA=%llX\n",
                  class_getName(object_getClass(self)),
                  HFABaseName(getterInfo.dli_fname),
                  (unsigned long long)getterRVA,
                  descriptorImage,
                  (unsigned long long)descriptorRVA,
                  len, flags, slot, matches,
                  callerInfo.dli_fname ? HFABaseName(callerInfo.dli_fname) : "?",
                  (unsigned long long)callerRVA);
        return secret;
    }

    void *copy = malloc(blobSize);
    char *plain = (char *)calloc(1, (size_t)len + 0x20u);
    if (!copy || !plain) {
        free(copy);
        free(plain);
        return secret;
    }
    if (!HFASafeRead((uintptr_t)secret, copy, blobSize)) {
        free(copy);
        free(plain);
        return secret;
    }

    int rc = ((HFASecretDecryptFn)decrypt)(copy, plain);
    plain[len] = 0;
    uintptr_t decryptRVA = decrypt - (uintptr_t)getterInfo.dli_fbase;
    const char *shown = rc == 0 && HFAPlainLooksUseful(plain, len) ? plain : "?";
    HFAGSOLog("[SECRET-PLAINTEXT] class=%s image=%s getterRVA=%llX decryptRVA=%llX descriptorImage=%s descriptorRVA=%llX descriptor=%p len=%u flags=%08X keySlot=%u rc=%d plain=%s callerImage=%s callerRVA=%llX\n",
              class_getName(object_getClass(self)),
              HFABaseName(getterInfo.dli_fname),
              (unsigned long long)getterRVA,
              (unsigned long long)decryptRVA,
              descriptorImage,
              (unsigned long long)descriptorRVA,
              secret, len, flags, slot, rc, shown,
              callerInfo.dli_fname ? HFABaseName(callerInfo.dli_fname) : "?",
              (unsigned long long)callerRVA);
    free(copy);
    free(plain);
    return secret;
}

static int HFAClassDefinesSecret(Class cls, Method *methodOut) {
    if (!cls) return 0;
    unsigned count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    if (!methods) return 0;
    SEL secret = sel_registerName("secret");
    Method found = NULL;
    for (unsigned i = 0; i < count; i++) {
        if (method_getName(methods[i]) == secret) {
            found = methods[i];
            break;
        }
    }
    free(methods);
    if (methodOut) *methodOut = found;
    return found != NULL;
}

static void HFAInstallSecretHooks(void) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0 || count > 200000) return;
    Class *classes = (Class *)calloc((size_t)count, sizeof(Class));
    if (!classes) return;
    count = objc_getClassList(classes, count);
    unsigned installed = 0;

    for (int i = 0; i < count; i++) {
        Class cls = classes[i];
        Method method = NULL;
        if (!HFAClassDefinesSecret(cls, &method) || !method) continue;
        const char *types = method_getTypeEncoding(method);
        if (!types || types[0] != '^') continue;
        IMP current = method_getImplementation(method);
        if (!current || current == (IMP)HFASecretObserver) continue;

        pthread_mutex_lock(&gLock);
        int known = 0;
        for (unsigned j = 0; j < gSecretHookCount; j++) {
            if (gSecretHooks[j].owner == cls) { known = 1; break; }
        }
        if (!known && gSecretHookCount <
            sizeof(gSecretHooks) / sizeof(gSecretHooks[0])) {
            gSecretHooks[gSecretHookCount].owner = cls;
            gSecretHooks[gSecretHookCount].original = current;
            gSecretHookCount++;
        }
        pthread_mutex_unlock(&gLock);
        if (known) continue;

        method_setImplementation(method, (IMP)HFASecretObserver);
        installed++;
        Dl_info info = {0};
        uintptr_t imp = HFAStripCodePointer((uintptr_t)current);
        dladdr((const void *)imp, &info);
        uintptr_t rva = info.dli_fbase ? imp - (uintptr_t)info.dli_fbase : 0;
        HFAGSOLog("[SECRET-HOOK] class=%s image=%s getterRVA=%llX installed=1\n",
                  class_getName(cls),
                  info.dli_fname ? HFABaseName(info.dli_fname) : "?",
                  (unsigned long long)rva);
    }
    free(classes);
    HFAGSOLog("[SECRET-OBSERVER] version=2.4.3 classes=%d installed=%u total=%u mode=unique-text-fingerprint noFixedDelta=1 rawKeysLogged=0\n",
              count, installed, gSecretHookCount);
}

static void HFAScheduleScan(void) {
    pthread_mutex_lock(&gLock);
    if (gScanScheduled) {
        pthread_mutex_unlock(&gLock);
        return;
    }
    gScanScheduled = 1;
    pthread_mutex_unlock(&gLock);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(500 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        HFAInstallSecretHooks();
        pthread_mutex_lock(&gLock);
        gScanScheduled = 0;
        pthread_mutex_unlock(&gLock);
    });
}

static void HFAImageAdded(const struct mach_header *header, intptr_t slide) {
    (void)header;
    (void)slide;
    HFAScheduleScan();
}

__attribute__((constructor))
static void HFAGenericSecretObserverInit(void) {
    _dyld_register_func_for_add_image(HFAImageAdded);
    HFAScheduleScan();
}

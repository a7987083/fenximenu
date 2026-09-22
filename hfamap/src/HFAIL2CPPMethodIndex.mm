#import "HFAIL2CPPMethodIndex.h"

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/vm_prot.h>
#include <dlfcn.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>

typedef void *(*HFADomainGetFn)(void);
typedef const void **(*HFADomainGetAssembliesFn)(const void *domain, size_t *size);
typedef const void *(*HFAAssemblyGetImageFn)(const void *assembly);
typedef const char *(*HFAImageGetNameFn)(const void *image);
typedef size_t (*HFAImageGetClassCountFn)(const void *image);
typedef void *(*HFAImageGetClassFn)(const void *image, size_t index);
typedef const char *(*HFAClassGetNameFn)(void *klass);
typedef const char *(*HFAClassGetNamespaceFn)(void *klass);
typedef const void *(*HFAClassGetMethodsFn)(void *klass, void **iter);
typedef const char *(*HFAMethodGetNameFn)(const void *method);
typedef uint32_t (*HFAMethodGetParamCountFn)(const void *method);
typedef void *(*HFAMethodGetPointerFn)(const void *method);

static const NSUInteger kHFAMaxAssemblies = 512;
static const NSUInteger kHFAMaxClasses = 4096;
static const NSUInteger kHFAMaxMethods = 32768;
static const NSUInteger kHFAMaxMethodsPerClass = 1024;

static pthread_mutex_t gHFAIndexLock = PTHREAD_MUTEX_INITIALIZER;
static NSMutableDictionary *gHFAMethodByAddress;
static NSDictionary *gHFAIndexSummary;
static BOOL gHFAIndexBuilt;

static NSString *HFASafeCString(const char *s) {
    if (!s) return @"";
    size_t n = strnlen(s, 512);
    if (!n || n >= 512) return @"";
    return [NSString stringWithUTF8String:s] ?: @"";
}

static uintptr_t HFAUnityImageBase(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *path = [NSString stringWithUTF8String:raw] ?: @"";
        NSString *name = path.lastPathComponent;
        if ([name isEqualToString:@"UnityFramework"] ||
            [path rangeOfString:@"UnityFramework.framework/UnityFramework" options:NSCaseInsensitiveSearch].location != NSNotFound)
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

static BOOL HFAExecutableUnityAddress(uintptr_t address) {
    uintptr_t imageBase = HFAUnityImageBase();
    if (!imageBase || !address) return NO;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)imageBase;
    if (mh->magic != MH_MAGIC_64 || mh->ncmds > 4096 || mh->sizeofcmds > 4U * 1024U * 1024U) return NO;

    const uint8_t *cursor = (const uint8_t *)(mh + 1);
    const uint8_t *end = cursor + mh->sizeofcmds;
    uint64_t imageVMBase = UINT64_MAX;
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (cursor + sizeof(struct load_command) > end) return NO;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) return NO;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (strncmp(seg->segname, SEG_TEXT, 16) == 0) imageVMBase = seg->vmaddr;
        }
        cursor += lc->cmdsize;
    }
    if (imageVMBase == UINT64_MAX) return NO;

    cursor = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (cursor + sizeof(struct load_command) > end) return NO;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) return NO;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if ((seg->initprot & VM_PROT_EXECUTE) && seg->vmaddr >= imageVMBase) {
                uintptr_t start = imageBase + (uintptr_t)(seg->vmaddr - imageVMBase);
                uintptr_t finish = start + (uintptr_t)seg->vmsize;
                if (address >= start && address < finish) return YES;
            }
        }
        cursor += lc->cmdsize;
    }
    return NO;
}

static void *HFAMethodPointer(const void *method, HFAMethodGetPointerFn getter,
                              NSString **sourceOut) {
    if (sourceOut) *sourceOut = @"unavailable";
    if (!method) return NULL;

    if (getter) {
        uintptr_t pointer = (uintptr_t)getter(method);
        if (HFAExecutableUnityAddress(pointer)) {
            if (sourceOut) *sourceOut = @"il2cpp_method_get_pointer";
            return (void *)pointer;
        }
    }

    uintptr_t words[2] = {0, 0};
    memcpy(words, method, sizeof(words));
    for (NSUInteger i = 0; i < 2; ++i) {
        if (HFAExecutableUnityAddress(words[i])) {
            if (sourceOut) *sourceOut = [NSString stringWithFormat:@"MethodInfo[%lu]", (unsigned long)i];
            return (void *)words[i];
        }
    }
    return NULL;
}

NSDictionary *HFAIL2CPPBuildMethodIndex(NSTimeInterval deadline) {
    pthread_mutex_lock(&gHFAIndexLock);
    if (gHFAIndexBuilt) {
        NSDictionary *cached = [gHFAIndexSummary retain];
        pthread_mutex_unlock(&gHFAIndexLock);
        return [cached autorelease];
    }
    pthread_mutex_unlock(&gHFAIndexLock);

    HFADomainGetFn domainGet = (HFADomainGetFn)dlsym(RTLD_DEFAULT, "il2cpp_domain_get");
    HFADomainGetAssembliesFn domainAssemblies = (HFADomainGetAssembliesFn)dlsym(RTLD_DEFAULT, "il2cpp_domain_get_assemblies");
    HFAAssemblyGetImageFn assemblyImage = (HFAAssemblyGetImageFn)dlsym(RTLD_DEFAULT, "il2cpp_assembly_get_image");
    HFAImageGetNameFn imageName = (HFAImageGetNameFn)dlsym(RTLD_DEFAULT, "il2cpp_image_get_name");
    HFAImageGetClassCountFn imageClassCount = (HFAImageGetClassCountFn)dlsym(RTLD_DEFAULT, "il2cpp_image_get_class_count");
    HFAImageGetClassFn imageClass = (HFAImageGetClassFn)dlsym(RTLD_DEFAULT, "il2cpp_image_get_class");
    HFAClassGetNameFn className = (HFAClassGetNameFn)dlsym(RTLD_DEFAULT, "il2cpp_class_get_name");
    HFAClassGetNamespaceFn classNamespace = (HFAClassGetNamespaceFn)dlsym(RTLD_DEFAULT, "il2cpp_class_get_namespace");
    HFAClassGetMethodsFn classMethods = (HFAClassGetMethodsFn)dlsym(RTLD_DEFAULT, "il2cpp_class_get_methods");
    HFAMethodGetNameFn methodName = (HFAMethodGetNameFn)dlsym(RTLD_DEFAULT, "il2cpp_method_get_name");
    HFAMethodGetParamCountFn methodParamCount = (HFAMethodGetParamCountFn)dlsym(RTLD_DEFAULT, "il2cpp_method_get_param_count");
    HFAMethodGetPointerFn methodPointer = (HFAMethodGetPointerFn)dlsym(RTLD_DEFAULT, "il2cpp_method_get_pointer");

    BOOL required = domainGet && domainAssemblies && assemblyImage && imageName &&
                    imageClassCount && imageClass && className && classMethods && methodName;
    if (!required) {
        NSDictionary *summary = @{
            @"schema": @"com.hfa.il2cpp-method-index/v1",
            @"status": @"required-il2cpp-exports-unavailable",
            @"analysisOnly": @YES, @"canonicalEligible": @NO,
            @"methodPointerExport": @(methodPointer != NULL),
            @"policy": @"read-only-il2cpp-metadata-enumeration-no-runtime-invoke-no-hook-no-memory-write"
        };
        pthread_mutex_lock(&gHFAIndexLock);
        gHFAIndexSummary = [summary copy];
        gHFAIndexBuilt = YES;
        pthread_mutex_unlock(&gHFAIndexLock);
        return summary;
    }

    void *domain = domainGet();
    size_t assemblyCountRaw = 0;
    const void **assemblies = domain ? domainAssemblies(domain, &assemblyCountRaw) : NULL;
    size_t assemblyCount = MIN(assemblyCountRaw, (size_t)kHFAMaxAssemblies);
    NSMutableDictionary *byAddress = [NSMutableDictionary dictionary];
    NSUInteger classesInspected = 0, methodsInspected = 0, indexed = 0;
    BOOL foundAssemblyCSharp = NO, hitLimit = NO, timedOut = NO;

    for (size_t ai = 0; assemblies && ai < assemblyCount; ++ai) {
        if (NSDate.date.timeIntervalSince1970 > deadline) { timedOut = YES; break; }
        const void *image = assemblyImage(assemblies[ai]);
        NSString *assembly = HFASafeCString(image ? imageName(image) : NULL);
        NSString *lower = assembly.lowercaseString;
        if (![lower hasPrefix:@"assembly-csharp"]) continue;
        foundAssemblyCSharp = YES;

        size_t classCountRaw = imageClassCount(image);
        size_t classCount = MIN(classCountRaw, (size_t)kHFAMaxClasses);
        if (classCountRaw > classCount) hitLimit = YES;
        for (size_t ci = 0; ci < classCount; ++ci) {
            if (NSDate.date.timeIntervalSince1970 > deadline) { timedOut = YES; break; }
            if (classesInspected >= kHFAMaxClasses || methodsInspected >= kHFAMaxMethods) {
                hitLimit = YES; break;
            }
            void *klass = imageClass(image, ci);
            if (!klass) continue;
            ++classesInspected;
            NSString *klassName = HFASafeCString(className(klass));
            NSString *namespaceName = classNamespace ? HFASafeCString(classNamespace(klass)) : @"";
            void *iter = NULL;
            for (NSUInteger mi = 0; mi < kHFAMaxMethodsPerClass && methodsInspected < kHFAMaxMethods; ++mi) {
                const void *method = classMethods(klass, &iter);
                if (!method) break;
                ++methodsInspected;
                NSString *methodNameValue = HFASafeCString(methodName(method));
                NSString *pointerSource = nil;
                void *pointer = HFAMethodPointer(method, methodPointer, &pointerSource);
                if (!pointer) continue;

                Dl_info info = {};
                NSString *imageValue = @"";
                NSString *rva = @"";
                if (dladdr(pointer, &info) && info.dli_fbase && info.dli_fname) {
                    NSString *path = [NSString stringWithUTF8String:info.dli_fname] ?: @"";
                    imageValue = path.lastPathComponent ?: @"";
                    rva = [NSString stringWithFormat:@"0x%llX",
                           (unsigned long long)((uintptr_t)pointer - (uintptr_t)info.dli_fbase)];
                }
                NSString *key = [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)pointer];
                if (!byAddress[key] && indexed < kHFAMaxMethods) {
                    byAddress[key] = @{
                        @"assembly": assembly ?: @"",
                        @"namespace": namespaceName ?: @"",
                        @"class": klassName ?: @"",
                        @"method": methodNameValue ?: @"",
                        @"parameterCount": methodParamCount ? @(methodParamCount(method)) : @(-1),
                        @"methodInfoToken": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)method],
                        @"methodPointerToken": key,
                        @"methodPointerSource": pointerSource ?: @"unknown",
                        @"implementationImage": imageValue,
                        @"implementationOffsetFromLoadBase": rva,
                        @"analysisOnly": @YES,
                        @"canonicalEligible": @NO
                    };
                    ++indexed;
                }
            }
        }
    }

    NSDictionary *summary = @{
        @"schema": @"com.hfa.il2cpp-method-index/v1",
        @"status": foundAssemblyCSharp ? @"indexed" : @"assembly-csharp-not-found",
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"assemblyCountRaw": @(assemblyCountRaw),
        @"classesInspected": @(classesInspected),
        @"methodsInspected": @(methodsInspected),
        @"indexedMethodPointers": @(indexed),
        @"methodPointerExport": @(methodPointer != NULL),
        @"methodPointerFallback": @YES,
        @"unityExecutableSegmentValidation": @YES,
        @"timedOut": @(timedOut),
        @"hitLimit": @(hitLimit),
        @"policy": @"read-only-il2cpp-metadata-enumeration-no-runtime-invoke-no-hook-no-memory-write"
    };

    pthread_mutex_lock(&gHFAIndexLock);
    gHFAMethodByAddress = [byAddress mutableCopy];
    gHFAIndexSummary = [summary copy];
    gHFAIndexBuilt = YES;
    pthread_mutex_unlock(&gHFAIndexLock);
    return summary;
}

NSDictionary *HFAIL2CPPMethodForRuntimeAddress(const void *address) {
    if (!address) return nil;
    NSString *key = [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)address];
    pthread_mutex_lock(&gHFAIndexLock);
    NSDictionary *result = [gHFAMethodByAddress[key] retain];
    pthread_mutex_unlock(&gHFAIndexLock);
    return [result autorelease];
}

#import "HFAIL2CPPMethodIndex.h"

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/vm_prot.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

typedef void *(*HFARangeDomainGetFn)(void);
typedef const void **(*HFARangeDomainGetAssembliesFn)(const void *domain, size_t *size);
typedef const void *(*HFARangeAssemblyGetImageFn)(const void *assembly);
typedef const char *(*HFARangeImageGetNameFn)(const void *image);
typedef size_t (*HFARangeImageGetClassCountFn)(const void *image);
typedef void *(*HFARangeImageGetClassFn)(const void *image, size_t index);
typedef const char *(*HFARangeClassGetNameFn)(void *klass);
typedef const char *(*HFARangeClassGetNamespaceFn)(void *klass);
typedef const void *(*HFARangeClassGetMethodsFn)(void *klass, void **iter);
typedef const char *(*HFARangeMethodGetNameFn)(const void *method);
typedef uint32_t (*HFARangeMethodGetParamCountFn)(const void *method);
typedef void *(*HFARangeMethodGetPointerFn)(const void *method);

static const NSUInteger kHFARangeMaxAssemblies = 512;
static const NSUInteger kHFARangeMaxClasses = 4096;
static const NSUInteger kHFARangeMaxMethods = 32768;
static const NSUInteger kHFARangeMaxMethodsPerClass = 1024;
static const uintptr_t kHFAMaxContainingMethodSpan = 0x10000;
static const NSTimeInterval kHFARangeBuildBudgetSeconds = 0.90;

static pthread_mutex_t gHFARangeLock = PTHREAD_MUTEX_INITIALIZER;
static NSArray *gHFARangeEntries;
static NSDictionary *gHFARangeSummary;
static BOOL gHFARangeBuilt;

static NSString *HFARangeSafeCString(const char *s) {
    if (!s) return @"";
    size_t n = strnlen(s, 512);
    if (!n || n >= 512) return @"";
    return [NSString stringWithUTF8String:s] ?: @"";
}

static uintptr_t HFARangeUnityImageBase(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *path = [NSString stringWithUTF8String:raw] ?: @"";
        if ([path.lastPathComponent isEqualToString:@"UnityFramework"] ||
            [path rangeOfString:@"UnityFramework.framework/UnityFramework" options:NSCaseInsensitiveSearch].location != NSNotFound)
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

static BOOL HFARangeExecutableBounds(uintptr_t address, uintptr_t *startOut, uintptr_t *endOut) {
    uintptr_t imageBase = HFARangeUnityImageBase();
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
                if (address >= start && address < finish) {
                    if (startOut) *startOut = start;
                    if (endOut) *endOut = finish;
                    return YES;
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return NO;
}

static void *HFARangeMethodPointer(const void *method, HFARangeMethodGetPointerFn getter,
                                   NSString **sourceOut) {
    if (sourceOut) *sourceOut = @"unavailable";
    if (!method) return NULL;
    if (getter) {
        uintptr_t pointer = (uintptr_t)getter(method);
        if (HFARangeExecutableBounds(pointer, NULL, NULL)) {
            if (sourceOut) *sourceOut = @"il2cpp_method_get_pointer";
            return (void *)pointer;
        }
    }
    uintptr_t words[2] = {0, 0};
    memcpy(words, method, sizeof(words));
    for (NSUInteger i = 0; i < 2; ++i) {
        if (HFARangeExecutableBounds(words[i], NULL, NULL)) {
            if (sourceOut) *sourceOut = [NSString stringWithFormat:@"MethodInfo[%lu]", (unsigned long)i];
            return (void *)words[i];
        }
    }
    return NULL;
}

static void HFABuildContainingMethodRanges(void) {
    pthread_mutex_lock(&gHFARangeLock);
    if (gHFARangeBuilt) { pthread_mutex_unlock(&gHFARangeLock); return; }
    pthread_mutex_unlock(&gHFARangeLock);

    NSTimeInterval deadline = NSDate.date.timeIntervalSince1970 + kHFARangeBuildBudgetSeconds;
    HFARangeDomainGetFn domainGet = (HFARangeDomainGetFn)dlsym(RTLD_DEFAULT, "il2cpp_domain_get");
    HFARangeDomainGetAssembliesFn domainAssemblies = (HFARangeDomainGetAssembliesFn)dlsym(RTLD_DEFAULT, "il2cpp_domain_get_assemblies");
    HFARangeAssemblyGetImageFn assemblyImage = (HFARangeAssemblyGetImageFn)dlsym(RTLD_DEFAULT, "il2cpp_assembly_get_image");
    HFARangeImageGetNameFn imageName = (HFARangeImageGetNameFn)dlsym(RTLD_DEFAULT, "il2cpp_image_get_name");
    HFARangeImageGetClassCountFn imageClassCount = (HFARangeImageGetClassCountFn)dlsym(RTLD_DEFAULT, "il2cpp_image_get_class_count");
    HFARangeImageGetClassFn imageClass = (HFARangeImageGetClassFn)dlsym(RTLD_DEFAULT, "il2cpp_image_get_class");
    HFARangeClassGetNameFn className = (HFARangeClassGetNameFn)dlsym(RTLD_DEFAULT, "il2cpp_class_get_name");
    HFARangeClassGetNamespaceFn classNamespace = (HFARangeClassGetNamespaceFn)dlsym(RTLD_DEFAULT, "il2cpp_class_get_namespace");
    HFARangeClassGetMethodsFn classMethods = (HFARangeClassGetMethodsFn)dlsym(RTLD_DEFAULT, "il2cpp_class_get_methods");
    HFARangeMethodGetNameFn methodName = (HFARangeMethodGetNameFn)dlsym(RTLD_DEFAULT, "il2cpp_method_get_name");
    HFARangeMethodGetParamCountFn methodParamCount = (HFARangeMethodGetParamCountFn)dlsym(RTLD_DEFAULT, "il2cpp_method_get_param_count");
    HFARangeMethodGetPointerFn methodPointer = (HFARangeMethodGetPointerFn)dlsym(RTLD_DEFAULT, "il2cpp_method_get_pointer");

    BOOL required = domainGet && domainAssemblies && assemblyImage && imageName && imageClassCount &&
                    imageClass && className && classMethods && methodName;
    NSMutableArray *entries = [NSMutableArray array];
    BOOL foundAssemblyCSharp = NO, timedOut = NO, hitLimit = NO;
    NSUInteger classesInspected = 0, methodsInspected = 0;
    size_t assemblyCountRaw = 0;

    if (required) {
        void *domain = domainGet();
        const void **assemblies = domain ? domainAssemblies(domain, &assemblyCountRaw) : NULL;
        size_t assemblyCount = MIN(assemblyCountRaw, (size_t)kHFARangeMaxAssemblies);
        for (size_t ai = 0; assemblies && ai < assemblyCount; ++ai) {
            if (NSDate.date.timeIntervalSince1970 > deadline) { timedOut = YES; break; }
            const void *image = assemblyImage(assemblies[ai]);
            NSString *assembly = HFARangeSafeCString(image ? imageName(image) : NULL);
            if (![assembly.lowercaseString hasPrefix:@"assembly-csharp"]) continue;
            foundAssemblyCSharp = YES;
            size_t classCountRaw = imageClassCount(image);
            size_t classCount = MIN(classCountRaw, (size_t)kHFARangeMaxClasses);
            if (classCountRaw > classCount) hitLimit = YES;
            for (size_t ci = 0; ci < classCount; ++ci) {
                if (NSDate.date.timeIntervalSince1970 > deadline) { timedOut = YES; break; }
                if (classesInspected >= kHFARangeMaxClasses || methodsInspected >= kHFARangeMaxMethods) { hitLimit = YES; break; }
                void *klass = imageClass(image, ci);
                if (!klass) continue;
                ++classesInspected;
                NSString *klassName = HFARangeSafeCString(className(klass));
                NSString *namespaceName = classNamespace ? HFARangeSafeCString(classNamespace(klass)) : @"";
                void *iter = NULL;
                for (NSUInteger mi = 0; mi < kHFARangeMaxMethodsPerClass && methodsInspected < kHFARangeMaxMethods; ++mi) {
                    const void *method = classMethods(klass, &iter);
                    if (!method) break;
                    ++methodsInspected;
                    NSString *pointerSource = nil;
                    void *pointer = HFARangeMethodPointer(method, methodPointer, &pointerSource);
                    if (!pointer) continue;
                    uintptr_t start = (uintptr_t)pointer;
                    Dl_info info = {};
                    NSString *imageValue = @"", *rva = @"";
                    if (dladdr(pointer, &info) && info.dli_fbase && info.dli_fname) {
                        NSString *path = [NSString stringWithUTF8String:info.dli_fname] ?: @"";
                        imageValue = path.lastPathComponent ?: @"";
                        rva = [NSString stringWithFormat:@"0x%llX", (unsigned long long)(start - (uintptr_t)info.dli_fbase)];
                    }
                    [entries addObject:@{
                        @"start": @(start), @"assembly": assembly ?: @"", @"namespace": namespaceName ?: @"",
                        @"class": klassName ?: @"", @"method": HFARangeSafeCString(methodName(method)) ?: @"",
                        @"parameterCount": methodParamCount ? @(methodParamCount(method)) : @(-1),
                        @"methodInfoToken": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)method],
                        @"methodPointerToken": [NSString stringWithFormat:@"0x%llX", (unsigned long long)start],
                        @"methodPointerSource": pointerSource ?: @"unknown", @"implementationImage": imageValue,
                        @"implementationOffsetFromLoadBase": rva, @"analysisOnly": @YES, @"canonicalEligible": @NO
                    }];
                }
            }
        }
    }

    [entries sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        unsigned long long av = [a[@"start"] unsignedLongLongValue], bv = [b[@"start"] unsignedLongLongValue];
        if (av < bv) return NSOrderedAscending;
        if (av > bv) return NSOrderedDescending;
        return NSOrderedSame;
    }];

    NSMutableArray *unique = [NSMutableArray array];
    uintptr_t previous = 0;
    for (NSDictionary *entry in entries) {
        uintptr_t start = (uintptr_t)[entry[@"start"] unsignedLongLongValue];
        if (!start || start == previous) continue;
        [unique addObject:entry];
        previous = start;
    }

    NSDictionary *summary = @{
        @"schema": @"com.hfa.il2cpp-method-range-index/v1",
        @"status": !required ? @"required-il2cpp-exports-unavailable" :
                    (foundAssemblyCSharp ? @"indexed" : @"assembly-csharp-not-found"),
        @"assemblyCountRaw": @(assemblyCountRaw), @"classesInspected": @(classesInspected),
        @"methodsInspected": @(methodsInspected), @"uniqueMethodStarts": @(unique.count),
        @"timedOut": @(timedOut), @"hitLimit": @(hitLimit),
        @"maxContainingSpan": [NSString stringWithFormat:@"0x%llX", (unsigned long long)kHFAMaxContainingMethodSpan],
        @"rangePolicy": @"sorted-method-start-next-start-same-exec-segment-bounded-span",
        @"referenceModel": @"h5gg-1.9.6-offset-to-cached-method-native-range-index",
        @"analysisOnly": @YES, @"canonicalEligible": @NO,
        @"policy": @"read-only-il2cpp-metadata-enumeration-no-runtime-invoke-no-hook-no-memory-write"
    };

    pthread_mutex_lock(&gHFARangeLock);
    if (!gHFARangeBuilt) {
        gHFARangeEntries = [unique copy];
        gHFARangeSummary = [summary copy];
        gHFARangeBuilt = YES;
    }
    pthread_mutex_unlock(&gHFARangeLock);
}

NSDictionary *HFAIL2CPPMethodContainingRuntimeAddress(const void *address) {
    uintptr_t query = (uintptr_t)address;
    if (!query || !HFARangeExecutableBounds(query, NULL, NULL)) return nil;
    HFABuildContainingMethodRanges();

    pthread_mutex_lock(&gHFARangeLock);
    NSArray *entries = [gHFARangeEntries retain];
    NSDictionary *summary = [gHFARangeSummary retain];
    pthread_mutex_unlock(&gHFARangeLock);
    if (entries.count < 2) { [entries release]; [summary release]; return nil; }

    NSInteger lo = 0, hi = (NSInteger)entries.count - 1, best = -1;
    while (lo <= hi) {
        NSInteger mid = lo + (hi - lo) / 2;
        uintptr_t start = (uintptr_t)[entries[mid][@"start"] unsignedLongLongValue];
        if (start <= query) { best = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    if (best < 0 || best + 1 >= (NSInteger)entries.count) { [entries release]; [summary release]; return nil; }

    NSDictionary *entry = entries[(NSUInteger)best];
    uintptr_t start = (uintptr_t)[entry[@"start"] unsignedLongLongValue];
    uintptr_t next = (uintptr_t)[entries[(NSUInteger)best + 1][@"start"] unsignedLongLongValue];
    uintptr_t segStart = 0, segEnd = 0, nextSegStart = 0, nextSegEnd = 0;
    BOOL sameExec = HFARangeExecutableBounds(start, &segStart, &segEnd) &&
                    HFARangeExecutableBounds(query, NULL, NULL) &&
                    HFARangeExecutableBounds(next, &nextSegStart, &nextSegEnd) &&
                    segStart == nextSegStart && segEnd == nextSegEnd;
    uintptr_t span = next > start ? next - start : 0;
    uintptr_t delta = query >= start ? query - start : UINTPTR_MAX;
    BOOL exact = query == start;
    BOOL valid = sameExec && span > 0 && span <= kHFAMaxContainingMethodSpan &&
                 query >= start && query < next && delta < span;
    if (!valid) { [entries release]; [summary release]; return nil; }

    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithDictionary:entry];
    [result removeObjectForKey:@"start"];
    result[@"matchType"] = exact ? @"exact-method-entry" : @"containing-method-range";
    result[@"instructionRuntime"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)query];
    result[@"methodStartRuntime"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)start];
    result[@"nextMethodStartRuntime"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)next];
    result[@"instructionDelta"] = @(delta);
    result[@"instructionDeltaHex"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)delta];
    result[@"methodRangeSpan"] = @(span);
    result[@"methodRangeSpanHex"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)span];
    result[@"rangeIndex"] = summary ?: @{};
    result[@"rangeValidation"] = @"same-unity-executable-segment-next-method-start-bounded-span";
    [entries release];
    [summary release];
    return result;
}

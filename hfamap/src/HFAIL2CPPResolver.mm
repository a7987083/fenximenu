#import "HFAIL2CPPResolver.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <dispatch/dispatch.h>
#include <string.h>

typedef void *(*HFADomainGetFn)(void);
typedef const void **(*HFADomainGetAssembliesFn)(const void *, size_t *);
typedef const void *(*HFAAssemblyGetImageFn)(const void *);
typedef const char *(*HFAImageGetNameFn)(const void *);
typedef size_t (*HFAImageGetClassCountFn)(const void *);
typedef void *(*HFAImageGetClassFn)(const void *, size_t);
typedef const char *(*HFAClassGetNameFn)(void *);
typedef const char *(*HFAClassGetNamespaceFn)(void *);
typedef const void *(*HFAClassGetMethodsFn)(void *, void **);
typedef const char *(*HFAMethodGetNameFn)(const void *);
typedef uint32_t (*HFAMethodGetParamCountFn)(const void *);
typedef void *(*HFAMethodGetPointerFn)(const void *);

static const NSUInteger kHFAIL2CPPResolverMaxAssemblies = 512;
static const NSUInteger kHFAIL2CPPResolverMaxClasses = 12000;
static const NSUInteger kHFAIL2CPPResolverMaxMethods = 180000;

static NSString *HFAString(const char *value) {
    if (!value) return @"";
    NSString *result = [NSString stringWithUTF8String:value];
    return result ?: @"";
}

static void *HFASymbol(const char *name) {
    return name ? dlsym(RTLD_DEFAULT, name) : NULL;
}

static NSDictionary *HFAExecutableLocation(uintptr_t address) {
    if (!address) return nil;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const struct mach_header_64 *header =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!header || header->magic != MH_MAGIC_64) continue;
        const uint8_t *cursor = (const uint8_t *)(header + 1);
        const uint8_t *end = cursor + header->sizeofcmds;
        uint64_t textVM = UINT64_MAX;
        for (uint32_t command = 0; command < header->ncmds; ++command) {
            if (cursor + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)cursor;
            if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) break;
            if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *segment =
                    (const struct segment_command_64 *)cursor;
                if (!strncmp(segment->segname, SEG_TEXT, 16)) textVM = segment->vmaddr;
            }
            cursor += lc->cmdsize;
        }
        if (textVM == UINT64_MAX) continue;
        cursor = (const uint8_t *)(header + 1);
        for (uint32_t command = 0; command < header->ncmds; ++command) {
            if (cursor + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)cursor;
            if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) break;
            if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *segment =
                    (const struct segment_command_64 *)cursor;
                if ((segment->initprot & VM_PROT_EXECUTE) && segment->vmaddr >= textVM) {
                    uintptr_t start = (uintptr_t)header + (uintptr_t)(segment->vmaddr - textVM);
                    uintptr_t finish = start + (uintptr_t)segment->vmsize;
                    if (address >= start && address < finish) {
                        NSString *path = HFAString(_dyld_get_image_name(i));
                        return @{
                            @"image": path.lastPathComponent ?: @"?",
                            @"path": path ?: @"",
                            @"imageIndex": @(i),
                            @"runtimeAddress": [NSString stringWithFormat:@"0x%llX",
                                (unsigned long long)address],
                            @"rva": [NSString stringWithFormat:@"0x%llX",
                                (unsigned long long)(address - (uintptr_t)header)],
                            @"addressSemantics": @"runtime-address-minus-load-base",
                            @"segment": HFAString(segment->segname)
                        };
                    }
                }
            }
            cursor += lc->cmdsize;
        }
    }
    return nil;
}

static uintptr_t HFAMethodPointer(const void *method, HFAMethodGetPointerFn getter,
                                  NSString **source, NSDictionary **location) {
    if (source) *source = @"unavailable";
    if (location) *location = nil;
    if (!method) return 0;
    if (getter) {
        uintptr_t pointer = (uintptr_t)getter(method);
        NSDictionary *where = HFAExecutableLocation(pointer);
        if (where) {
            if (source) *source = @"il2cpp_method_get_pointer";
            if (location) *location = where;
            return pointer;
        }
    }
    uintptr_t words[2] = {0, 0};
    vm_size_t copied = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)method, sizeof(words),
                          (vm_address_t)words, &copied) != KERN_SUCCESS ||
        copied != sizeof(words)) return 0;
    for (NSUInteger index = 0; index < 2; ++index) {
        NSDictionary *where = HFAExecutableLocation(words[index]);
        if (!where) continue;
        if (source) *source = [NSString stringWithFormat:@"MethodInfo[%lu]",
                               (unsigned long)index];
        if (location) *location = where;
        return words[index];
    }
    return 0;
}

static NSArray<NSString *> *HFAHintTokens(NSDictionary *context) {
    NSMutableOrderedSet *tokens = [NSMutableOrderedSet orderedSet];
    NSArray *hints = [context[@"runtimeFeatureHints"] isKindOfClass:NSArray.class]
        ? context[@"runtimeFeatureHints"] : @[];
    NSCharacterSet *split = [[NSCharacterSet alphanumericCharacterSet] invertedSet];
    for (id raw in hints) {
        if (![raw isKindOfClass:NSString.class]) continue;
        for (NSString *part in [[raw lowercaseString] componentsSeparatedByCharactersInSet:split])
            if (part.length >= 3 && part.length <= 40) [tokens addObject:part];
    }
    return tokens.array;
}

static NSInteger HFAMethodScore(NSString *assembly, NSString *namespaceName,
                                NSString *className, NSString *methodName,
                                NSArray<NSString *> *hints) {
    NSString *haystack = [[NSString stringWithFormat:@"%@ %@ %@ %@", assembly ?: @"",
                            namespaceName ?: @"", className ?: @"", methodName ?: @""] lowercaseString];
    NSInteger score = 0;
    for (NSString *hint in hints)
        if ([haystack containsString:hint]) score += 100;
    static NSArray<NSString *> *strong;
    static NSArray<NSString *> *medium;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        strong = [[NSArray alloc] initWithObjects:@"currency", @"money", @"coin", @"cash",
                  @"gold", @"gem", @"experience", @"reward", @"fuel", @"boost",
                  @"energy", @"stamina", @"unlock", @"purchase", @"claim", nil];
        medium = [[NSArray alloc] initWithObjects:@"add", @"gain", @"earn", @"grant",
                  @"receive", @"collect", @"refill", @"level", @"upgrade", @"damage",
                  @"health", @"attack", @"speed", @"advert", @"complete", @"finish", nil];
    });
    NSString *lowerMethod = methodName.lowercaseString;
    for (NSString *word in strong) if ([lowerMethod containsString:word]) score += 60;
    for (NSString *word in medium) if ([lowerMethod containsString:word]) score += 25;
    if ([lowerMethod hasPrefix:@"on"] || [lowerMethod containsString:@"click"] ||
        [lowerMethod containsString:@"button"]) score += 18;
    if ([lowerMethod isEqualToString:@"update"] ||
        [lowerMethod isEqualToString:@"fixedupdate"] ||
        [lowerMethod isEqualToString:@"lateupdate"]) score -= 200;
    if ([lowerMethod hasPrefix:@"get_"] || [lowerMethod hasPrefix:@"set_"]) score -= 8;
    return score;
}

NSDictionary *HFAIL2CPPResolveInstrumentCandidates(NSDictionary *context,
                                                    NSTimeInterval absoluteDeadline,
                                                    NSUInteger candidateLimit) {
    HFADomainGetFn domainGet = (HFADomainGetFn)HFASymbol("il2cpp_domain_get");
    HFADomainGetAssembliesFn domainGetAssemblies =
        (HFADomainGetAssembliesFn)HFASymbol("il2cpp_domain_get_assemblies");
    HFAAssemblyGetImageFn assemblyGetImage =
        (HFAAssemblyGetImageFn)HFASymbol("il2cpp_assembly_get_image");
    HFAImageGetNameFn imageGetName =
        (HFAImageGetNameFn)HFASymbol("il2cpp_image_get_name");
    HFAImageGetClassCountFn imageGetClassCount =
        (HFAImageGetClassCountFn)HFASymbol("il2cpp_image_get_class_count");
    HFAImageGetClassFn imageGetClass =
        (HFAImageGetClassFn)HFASymbol("il2cpp_image_get_class");
    HFAClassGetNameFn classGetName =
        (HFAClassGetNameFn)HFASymbol("il2cpp_class_get_name");
    HFAClassGetNamespaceFn classGetNamespace =
        (HFAClassGetNamespaceFn)HFASymbol("il2cpp_class_get_namespace");
    HFAClassGetMethodsFn classGetMethods =
        (HFAClassGetMethodsFn)HFASymbol("il2cpp_class_get_methods");
    HFAMethodGetNameFn methodGetName =
        (HFAMethodGetNameFn)HFASymbol("il2cpp_method_get_name");
    HFAMethodGetParamCountFn methodGetParamCount =
        (HFAMethodGetParamCountFn)HFASymbol("il2cpp_method_get_param_count");
    HFAMethodGetPointerFn methodGetPointer =
        (HFAMethodGetPointerFn)HFASymbol("il2cpp_method_get_pointer");

    NSDictionary *exports = @{
        @"il2cpp_domain_get": @(domainGet != NULL),
        @"il2cpp_domain_get_assemblies": @(domainGetAssemblies != NULL),
        @"il2cpp_assembly_get_image": @(assemblyGetImage != NULL),
        @"il2cpp_image_get_name": @(imageGetName != NULL),
        @"il2cpp_image_get_class_count": @(imageGetClassCount != NULL),
        @"il2cpp_image_get_class": @(imageGetClass != NULL),
        @"il2cpp_class_get_methods": @(classGetMethods != NULL),
        @"il2cpp_method_get_name": @(methodGetName != NULL),
        @"il2cpp_method_get_param_count": @(methodGetParamCount != NULL),
        @"il2cpp_method_get_pointer": @(methodGetPointer != NULL)
    };
    BOOL core = domainGet && domainGetAssemblies && assemblyGetImage && imageGetName &&
                imageGetClassCount && imageGetClass && classGetName && classGetNamespace &&
                classGetMethods && methodGetName;
    if (!core) return @{
        @"schema": @"com.hfa.il2cpp-runtime-resolver/v1",
        @"status": @"required-il2cpp-enumeration-exports-unavailable",
        @"exports": exports, @"candidates": @[], @"analysisOnly": @YES
    };
    void *domain = domainGet();
    size_t assemblyCount = 0;
    const void **assemblies = domain ? domainGetAssemblies(domain, &assemblyCount) : NULL;
    if (!assemblies || !assemblyCount) return @{
        @"schema": @"com.hfa.il2cpp-runtime-resolver/v1", @"status": @"domain-not-ready",
        @"exports": exports, @"candidates": @[], @"analysisOnly": @YES
    };

    NSArray<NSString *> *hints = HFAHintTokens(context ?: @{});
    NSMutableArray *candidates = [NSMutableArray array];
    NSMutableSet *seenPointers = [NSMutableSet set];
    NSUInteger classesScanned = 0, methodsScanned = 0, pointerRejected = 0;
    BOOL deadlineHit = NO, classLimitHit = NO, methodLimitHit = NO;
    size_t boundedAssemblies = MIN(assemblyCount, (size_t)kHFAIL2CPPResolverMaxAssemblies);
    NSMutableArray<NSNumber *> *order = [NSMutableArray arrayWithCapacity:boundedAssemblies];
    for (size_t i = 0; i < boundedAssemblies; ++i) {
        const void *image = assemblyGetImage(assemblies[i]);
        NSString *name = image ? HFAString(imageGetName(image)) : @"";
        if ([name.lowercaseString hasPrefix:@"assembly-csharp"]) [order insertObject:@(i) atIndex:0];
        else [order addObject:@(i)];
    }
    for (NSNumber *indexNumber in order) {
        if (NSDate.date.timeIntervalSince1970 >= absoluteDeadline) { deadlineHit = YES; break; }
        const void *image = assemblyGetImage(assemblies[indexNumber.unsignedIntegerValue]);
        if (!image) continue;
        NSString *assembly = HFAString(imageGetName(image));
        size_t classCount = imageGetClassCount(image);
        for (size_t ci = 0; ci < classCount; ++ci) {
            if (classesScanned >= kHFAIL2CPPResolverMaxClasses) { classLimitHit = YES; break; }
            if ((classesScanned & 0x3F) == 0 &&
                NSDate.date.timeIntervalSince1970 >= absoluteDeadline) { deadlineHit = YES; break; }
            ++classesScanned;
            void *klass = imageGetClass(image, ci);
            if (!klass) continue;
            NSString *className = HFAString(classGetName(klass));
            NSString *namespaceName = HFAString(classGetNamespace(klass));
            void *iterator = NULL;
            const void *method = NULL;
            while ((method = classGetMethods(klass, &iterator)) != NULL) {
                if (++methodsScanned >= kHFAIL2CPPResolverMaxMethods) { methodLimitHit = YES; break; }
                NSString *methodName = HFAString(methodGetName(method));
                NSInteger score = HFAMethodScore(assembly, namespaceName, className,
                                                  methodName, hints);
                if (score < 18) continue;
                NSString *pointerSource = nil;
                NSDictionary *location = nil;
                uintptr_t pointer = HFAMethodPointer(method, methodGetPointer,
                                                      &pointerSource, &location);
                if (!pointer || !location) { ++pointerRejected; continue; }
                NSNumber *pointerKey = @(pointer);
                if ([seenPointers containsObject:pointerKey]) continue;
                [seenPointers addObject:pointerKey];
                NSUInteger parameterCount = methodGetParamCount ? methodGetParamCount(method) : NSNotFound;
                NSString *classPath = namespaceName.length
                    ? [NSString stringWithFormat:@"%@.%@", namespaceName, className] : className;
                NSMutableDictionary *candidate = [@{
                    @"assembly": assembly ?: @"", @"namespace": namespaceName ?: @"",
                    @"class": className ?: @"", @"method": methodName ?: @"",
                    @"methodInfo": @((uintptr_t)method), @"methodPointer": pointerKey,
                    @"pointerSource": pointerSource ?: @"unavailable", @"score": @(score),
                    @"canonical": [NSString stringWithFormat:@"%@!%@::%@%@", assembly ?: @"?",
                        classPath ?: @"?", methodName ?: @"?",
                        parameterCount == NSNotFound ? @"" :
                        [NSString stringWithFormat:@"/%lu", (unsigned long)parameterCount]],
                    @"location": location
                } mutableCopy];
                if (parameterCount != NSNotFound) candidate[@"parameterCount"] = @(parameterCount);
                [candidates addObject:candidate];
                [candidate release];
            }
            if (methodLimitHit) break;
        }
        if (deadlineHit || classLimitHit || methodLimitHit) break;
    }
    [candidates sortUsingComparator:^NSComparisonResult(NSDictionary *lhs, NSDictionary *rhs) {
        NSInteger a = [lhs[@"score"] integerValue], b = [rhs[@"score"] integerValue];
        if (a != b) return a > b ? NSOrderedAscending : NSOrderedDescending;
        return [lhs[@"canonical"] compare:rhs[@"canonical"]];
    }];
    NSUInteger discovered = candidates.count;
    if (candidateLimit && candidates.count > candidateLimit)
        [candidates removeObjectsInRange:NSMakeRange(candidateLimit, candidates.count - candidateLimit)];
    NSString *status = candidates.count ? @"resolved" : @"no-instrumentable-method-candidates";
    return @{
        @"schema": @"com.hfa.il2cpp-runtime-resolver/v1", @"status": status,
        @"sourceBaseline": @"UnitXP_SP3-Moonstone@a3b8db8651eaea23ec0ae7e5fca497e8f67bcf6c",
        @"exports": exports, @"hints": hints, @"candidates": candidates,
        @"metrics": @{
            @"assemblyCount": @(assemblyCount), @"assembliesScanned": @(boundedAssemblies),
            @"classesScanned": @(classesScanned), @"methodsScanned": @(methodsScanned),
            @"discoveredCandidateCount": @(discovered),
            @"returnedCandidateCount": @(candidates.count),
            @"pointerRejectedCount": @(pointerRejected),
            @"deadlineHit": @(deadlineHit), @"classLimitHit": @(classLimitHit),
            @"methodLimitHit": @(methodLimitHit),
            @"candidateLimit": @(candidateLimit),
            @"truncated": @(discovered > candidates.count)
        },
        @"analysisOnly": @YES, @"managedMethodInvoked": @NO, @"gameStateWritten": @NO
    };
}

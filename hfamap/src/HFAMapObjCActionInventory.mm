#import "HFAMapObjCActionInventory.h"
#import "HFAMapStrippedActionAnalyzer.h"

#import <objc/runtime.h>
#import <dlfcn.h>

static const NSUInteger kHFAInventoryMaxClasses = 512;
static const NSUInteger kHFAInventoryMaxMethods = 256;
static const NSUInteger kHFAInventoryMaxRecords = 128;

static BOOL HFAInventoryExpired(NSTimeInterval deadline) {
    return [[NSDate date] timeIntervalSince1970] > deadline;
}

static void HFAInventoryMethodsForClass(Class cls,
                                        NSString *path,
                                        NSString *kind,
                                        NSTimeInterval deadline,
                                        NSMutableSet *seenIMPs,
                                        NSMutableArray *records,
                                        NSUInteger *inspected) {
    if (!cls || records.count >= kHFAInventoryMaxRecords || HFAInventoryExpired(deadline)) return;
    unsigned count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    for (unsigned i = 0; methods && i < count && *inspected < kHFAInventoryMaxMethods &&
         records.count < kHFAInventoryMaxRecords && !HFAInventoryExpired(deadline); ++i) {
        ++(*inspected);
        Method method = methods[i];
        IMP imp = method_getImplementation(method);
        if (!imp) continue;
        NSString *impKey = [NSString stringWithFormat:@"%p", imp];
        if ([seenIMPs containsObject:impKey]) continue;
        Dl_info info = {};
        if (!dladdr((const void *)imp, &info) || !info.dli_fname) continue;
        NSString *impPath = [NSString stringWithUTF8String:info.dli_fname];
        if (![impPath.lastPathComponent isEqualToString:path.lastPathComponent]) continue;
        [seenIMPs addObject:impKey];
        NSDictionary *analysis = HFAMapAnalyzeStrippedActionIMP((const void *)imp, impPath);
        NSArray *calls = analysis[@"calls"] ?: @[];
        NSArray *branches = analysis[@"branches"] ?: @[];
        BOOL interesting = calls.count || branches.count;
        if (!interesting) continue;
        SEL sel = method_getName(method);
        const char *types = method_getTypeEncoding(method);
        [records addObject:@{
            @"class": NSStringFromClass(cls) ?: @"?",
            @"methodKind": kind ?: @"?",
            @"selector": sel ? NSStringFromSelector(sel) : @"?",
            @"typeEncoding": types ? [NSString stringWithUTF8String:types] : @"?",
            @"analysis": analysis ?: @{},
            @"analysisOnly": @YES,
            @"canonicalEligible": @NO
        }];
    }
    if (methods) free(methods);
}

NSDictionary *HFAMapInventoryStrippedObjCActions(NSString *implementationPath,
                                                  NSTimeInterval deadline) {
    if (!implementationPath.length)
        return @{ @"schema": @"com.hfa.stripped-objc-inventory/v1",
                  @"status": @"missing-path", @"analysisOnly": @YES,
                  @"canonicalEligible": @NO };
    unsigned classCount = 0;
    const char **names = objc_copyClassNamesForImage(implementationPath.fileSystemRepresentation, &classCount);
    NSUInteger boundedClasses = MIN((NSUInteger)classCount, kHFAInventoryMaxClasses);
    NSUInteger inspectedMethods = 0;
    NSMutableArray *records = [NSMutableArray array];
    NSMutableSet *seenIMPs = [NSMutableSet set];
    for (NSUInteger i = 0; names && i < boundedClasses && inspectedMethods < kHFAInventoryMaxMethods &&
         records.count < kHFAInventoryMaxRecords && !HFAInventoryExpired(deadline); ++i) {
        Class cls = objc_getClass(names[i]);
        if (!cls) continue;
        HFAInventoryMethodsForClass(cls, implementationPath, @"instance", deadline,
                                    seenIMPs, records, &inspectedMethods);
        Class meta = object_getClass(cls);
        HFAInventoryMethodsForClass(meta, implementationPath, @"class", deadline,
                                    seenIMPs, records, &inspectedMethods);
    }
    if (names) free(names);
    return @{
        @"schema": @"com.hfa.stripped-objc-inventory/v1",
        @"status": records.count ? @"evidence-found" : @"no-evidence",
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"classCount": @(classCount),
        @"inspectedClassCount": @(boundedClasses),
        @"inspectedMethodCount": @(inspectedMethods),
        @"records": records,
        @"limits": @{ @"classes": @(kHFAInventoryMaxClasses),
                       @"methods": @(kHFAInventoryMaxMethods),
                       @"records": @(kHFAInventoryMaxRecords) },
        @"policy": @"objc-metadata-plus-read-only-arm64-local-dataflow"
    };
}

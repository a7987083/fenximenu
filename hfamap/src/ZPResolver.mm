#import "ZPResolver.h"
#import "HFAMapDiagnostics.h"
#import <objc/runtime.h>
#include <dlfcn.h>

static unsigned ZPDescriptorSelectorCount(Class cls, NSMutableArray<NSString *> *present) {
    static const char *selectors[] = {
        "identifier", "setIdentifier:", "active", "setActive:", "offset", "setOffset:",
        "signature", "setSignature:", "range", "setRange:", "type", "architecture", "searchDirection"
    };
    unsigned count = 0;
    for (unsigned i=0;i<sizeof(selectors)/sizeof(selectors[0]);++i) {
        if (class_getInstanceMethod(cls, sel_registerName(selectors[i]))) {
            ++count; if (present) [present addObject:[NSString stringWithUTF8String:selectors[i]]];
        }
    }
    return count;
}

static NSDictionary *ZPDescriptorRecord(NSDictionary *candidate) {
    NSString *path = candidate[@"path"];
    unsigned classCount = 0;
    const char **names = objc_copyClassNamesForImage(path.fileSystemRepresentation, &classCount);
    NSDictionary *best = nil;
    for (unsigned i=0; names && i<MIN(classCount, 512U); ++i) {
        Class cls = objc_getClass(names[i]);
        if (!cls || class_getInstanceSize(cls) != 0xA0) continue;
        NSMutableArray *selectors = [NSMutableArray array];
        unsigned sc = ZPDescriptorSelectorCount(cls, selectors);
        if (sc < 10) continue;
        NSMutableArray *ivars = [NSMutableArray array];
        unsigned ivarCount = 0; Ivar *list = class_copyIvarList(cls, &ivarCount);
        for (unsigned j=0; list && j<ivarCount; ++j) {
            const char *name = ivar_getName(list[j]);
            const char *type = ivar_getTypeEncoding(list[j]);
            [ivars addObject:@{ @"name": name ? [NSString stringWithUTF8String:name] : @"?",
                                @"offset": @((long long)ivar_getOffset(list[j])),
                                @"type": type ? [NSString stringWithUTF8String:type] : @"?" }];
        }
        free(list);
        best = @{ @"class": NSStringFromClass(cls) ?: @"?", @"classIndex": @(i),
                  @"instanceSize": @(class_getInstanceSize(cls)), @"selectorCount": @(sc),
                  @"selectors": selectors, @"ivars": ivars };
        break;
    }
    free(names);
    return best ?: @{};
}

static NSDictionary *ZPMethodOwner(Class cls, const char *selectorName) {
    if (!cls || !selectorName) return @{};
    SEL sel = sel_registerName(selectorName);
    Method method = class_getInstanceMethod(cls, sel);
    if (!method) method = class_getClassMethod(cls, sel);
    if (!method) return @{ @"selector": [NSString stringWithUTF8String:selectorName], @"present": @NO };
    IMP imp = method_getImplementation(method);
    Dl_info info = {0};
    BOOL ok = imp && dladdr((const void *)imp, &info) && info.dli_fbase && info.dli_fname;
    uintptr_t rva = ok ? ((uintptr_t)imp - (uintptr_t)info.dli_fbase) : 0;
    return @{ @"selector": [NSString stringWithUTF8String:selectorName], @"present": @YES,
              @"imp": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)imp],
              @"ownerImage": ok ? [NSString stringWithUTF8String:info.dli_fname].lastPathComponent : @"?",
              @"ownerPath": ok ? [NSString stringWithUTF8String:info.dli_fname] : @"?",
              @"ownerRVA": [NSString stringWithFormat:@"0x%llX", (unsigned long long)rva] };
}

static NSDictionary *ZPC4M0OwnerEvidence(NSDictionary *candidate) {
    Class cls = objc_getClass("C4M0Manager");
    if (!cls) return @{ @"status": @"missing-class" };
    const char *classPath = class_getImageName(cls);
    NSString *classImage = classPath ? [NSString stringWithUTF8String:classPath].lastPathComponent : @"?";
    NSDictionary *loadConfig = ZPMethodOwner(cls, "loadConfig:");
    NSDictionary *loadPolicies = ZPMethodOwner(cls, "loadPolicies");
    NSString *candidateImage = candidate[@"image"] ?: @"";
    NSString *owner = loadConfig[@"ownerImage"] ?: @"?";
    BOOL external = [loadConfig[@"present"] boolValue] && ![owner isEqualToString:candidateImage];
    return @{ @"status": @"resolved", @"class": NSStringFromClass(cls) ?: @"C4M0Manager",
              @"classImage": classImage ?: @"?", @"loadConfig": loadConfig,
              @"loadPolicies": loadPolicies, @"externalLoadConfigOwner": @(external) };
}

static NSDictionary *ZPLegacyEvidence(NSDictionary *descriptor) {
    NSArray *ivars = descriptor[@"ivars"] ?: @[];
    NSMutableDictionary *offsetTypes = [NSMutableDictionary dictionary];
    for (NSDictionary *ivar in ivars) {
        NSNumber *off = ivar[@"offset"]; NSString *type = ivar[@"type"];
        if (off && type) offsetTypes[[NSString stringWithFormat:@"0x%llX", off.unsignedLongLongValue]] = type;
    }
    return @{ @"knownABI": @{
                   @"active": @"0x0A", @"identifier": @"0x20", @"type": @"0x30",
                   @"architecture": @"0x38", @"offset": @"0x48", @"signature": @"0x58",
                   @"range": @"0x80", @"searchDirection": @"0x90" },
              @"observedIvarTypes": offsetTypes };
}

NSDictionary *ZPResolveCandidate(NSDictionary *candidate, NSTimeInterval deadline,
                                 NSMutableArray<NSDictionary *> *events) {
    if (NSDate.date.timeIntervalSince1970 > deadline)
        return @{ @"status": @"timeout", @"observations": @[], @"validatedFeatures": @[] };
    NSDictionary *descriptor = ZPDescriptorRecord(candidate);
    NSString *family = candidate[@"family"] ?: @"unknown";
    NSMutableArray *observations = [NSMutableArray array];
    if (descriptor.count) {
        [observations addObject:@{ @"kind": @"descriptor", @"evidence": descriptor,
                                   @"confidence": @"high" }];
        HFADiagnosticsLog(@"descriptor", @"located", descriptor);
    }
    // Family-specific observation is deliberately gated by the ABI-first classifier.
    // Presence of iGameGod/C4M0Manager elsewhere in the process is environment evidence,
    // not proof that the selected menu image belongs to C4M0.
    if ([family isEqualToString:@"c4m0"]) {
        NSDictionary *owner = ZPC4M0OwnerEvidence(candidate);
        [observations addObject:@{ @"kind": @"c4m0-owner", @"evidence": owner,
                                   @"confidence": [owner[@"externalLoadConfigOwner"] boolValue] ? @"high" : @"medium" }];
        HFADiagnosticsLog(@"c4m0-owner", @"resolved", owner);
    } else if ([family isEqualToString:@"legacy-ap"]) {
        NSDictionary *legacy = ZPLegacyEvidence(descriptor);
        [observations addObject:@{ @"kind": @"legacy-abi", @"evidence": legacy,
                                   @"confidence": @"high" }];
        HFADiagnosticsLog(@"legacy-abi", @"mapped", legacy);
    }
    [events addObject:@{ @"time": @(NSDate.date.timeIntervalSince1970), @"stage": @"resolve",
                         @"status": descriptor.count ? @"analysis-only" : @"descriptor-missing",
                         @"family": family, @"observationCount": @(observations.count) }];
    return @{ @"status": descriptor.count ? @"analysis-only" : @"incomplete",
              @"family": family, @"descriptor": descriptor, @"observations": observations,
              @"validatedFeatures": @[],
              @"canonicalEligible": @NO,
              @"canonicalReason": @"v0.1.1-does-not-export-unverified-patches" };
}

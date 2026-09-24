#import "HFAMapLoadedDylibEvidenceResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>

#include <stdint.h>
#include <string.h>

static const NSUInteger kHFALoadedMaxClasses = 256;
static const NSUInteger kHFALoadedMaxMethods = 1024;
static const NSUInteger kHFALoadedMaxIvars = 1024;
static const NSUInteger kHFALoadedMaxProperties = 1024;

static NSString *HFAUUIDString(const uint8_t uuid[16]) {
    return [NSString stringWithFormat:
        @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        uuid[0],uuid[1],uuid[2],uuid[3],uuid[4],uuid[5],uuid[6],uuid[7],
        uuid[8],uuid[9],uuid[10],uuid[11],uuid[12],uuid[13],uuid[14],uuid[15]];
}

static NSDictionary *HFAImageIdentity(const struct mach_header *mh, intptr_t slide) {
    if (!mh || mh->magic != MH_MAGIC_64) return nil;
    const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
    const uint8_t *cursor = (const uint8_t *)(h + 1);
    uint64_t preferredBase = UINT64_MAX;
    uint64_t runtimeLow = UINT64_MAX, runtimeHigh = 0;
    NSString *uuid = @"";
    for (uint32_t i = 0; i < h->ncmds; ++i) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc->cmdsize) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (seg->vmsize) {
                preferredBase = MIN(preferredBase, seg->vmaddr);
                uint64_t low = seg->vmaddr + (uint64_t)slide;
                uint64_t high = low + seg->vmsize;
                runtimeLow = MIN(runtimeLow, low);
                runtimeHigh = MAX(runtimeHigh, high);
            }
        } else if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            uuid = HFAUUIDString(((const struct uuid_command *)cursor)->uuid) ?: @"";
        }
        cursor += lc->cmdsize;
    }
    if (preferredBase == UINT64_MAX) preferredBase = 0;
    if (runtimeLow == UINT64_MAX) runtimeLow = (uint64_t)(uintptr_t)mh;
    uint64_t runtimeBase = preferredBase + (uint64_t)slide;
    return @{
        @"uuid": uuid,
        @"preferredBase": @(preferredBase),
        @"runtimeBase": @(runtimeBase),
        @"runtimeLow": @(runtimeLow),
        @"runtimeHigh": @(runtimeHigh),
        @"slide": @((long long)slide)
    };
}

static BOOL HFAAddressInImage(uint64_t address, NSDictionary *identity) {
    uint64_t low = [identity[@"runtimeLow"] unsignedLongLongValue];
    uint64_t high = [identity[@"runtimeHigh"] unsignedLongLongValue];
    return address >= low && address < high && high > low;
}

static NSString *HFAStructuralRole(NSString *name) {
    NSString *l = name.lowercaseString;
    if ([l containsString:@"offset"] || [l containsString:@"rva"] || [l containsString:@"address"]) return @"address-field";
    if ([l containsString:@"patch"] || [l containsString:@"bytes"] || [l containsString:@"instruction"]) return @"patch-field";
    if ([l containsString:@"image"] || [l containsString:@"library"] || [l containsString:@"module"] || [l containsString:@"path"]) return @"target-image-field";
    if ([l containsString:@"method"] || [l containsString:@"class"] || [l containsString:@"assembly"] || [l containsString:@"namespace"]) return @"managed-identity-field";
    if ([l containsString:@"feature"] || [l containsString:@"title"] || [l containsString:@"name"] || [l containsString:@"label"]) return @"feature-field";
    if ([l containsString:@"callback"] || [l containsString:@"handler"] || [l containsString:@"action"] || [l containsString:@"block"]) return @"callback-field";
    return @"field";
}

static NSDictionary *HFAFindLoadedImage(NSString *importedPath, NSError **error) {
    NSString *wanted = importedPath.stringByStandardizingPath;
    NSString *base = wanted.lastPathComponent.lowercaseString;
    NSMutableArray *basenameMatches = [NSMutableArray array];
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        NSString *path = [[NSString stringWithUTF8String:name] stringByStandardizingPath];
        const struct mach_header *mh = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        NSDictionary *identity = HFAImageIdentity(mh, slide) ?: @{};
        NSDictionary *record = @{ @"index": @(i), @"path": path ?: @"", @"identity": identity };
        if ([path isEqualToString:wanted]) return record;
        if ([path.lastPathComponent.lowercaseString isEqualToString:base]) [basenameMatches addObject:record];
    }
    if (basenameMatches.count == 1) return basenameMatches.firstObject;
    NSString *reason = basenameMatches.count ? @"ambiguous-loaded-basename" : @"selected-dylib-not-loaded";
    if (error) *error = [NSError errorWithDomain:@"com.hfa.loaded-dylib-evidence" code:2
                                         userInfo:@{NSLocalizedDescriptionKey: reason}];
    return nil;
}

static NSArray *HFAMethodRecordsForClass(Class cls, BOOL classMethods, NSDictionary *identity, NSUInteger *budget) {
    if (!cls || !budget || !*budget) return @[];
    Class owner = classMethods ? object_getClass(cls) : cls;
    unsigned int count = 0;
    Method *methods = class_copyMethodList(owner, &count);
    NSMutableArray *records = [NSMutableArray array];
    for (unsigned int i = 0; methods && i < count && *budget; ++i, --(*budget)) {
        Method m = methods[i];
        SEL sel = method_getName(m);
        IMP imp = method_getImplementation(m);
        uint64_t address = (uint64_t)(uintptr_t)imp;
        BOOL inImage = HFAAddressInImage(address, identity);
        uint64_t base = [identity[@"runtimeBase"] unsignedLongLongValue];
        NSMutableDictionary *r = [@{
            @"selector": sel ? NSStringFromSelector(sel) : @"",
            @"kind": classMethods ? @"class" : @"instance",
            @"implementation": [NSString stringWithFormat:@"0x%llX", (unsigned long long)address],
            @"implementationInImage": @(inImage),
            @"typeEncoding": method_getTypeEncoding(m) ? [NSString stringWithUTF8String:method_getTypeEncoding(m)] : @""
        } mutableCopy];
        if (inImage && address >= base) {
            uint64_t rva = address - base;
            r[@"implementationRVA"] = @(rva);
            r[@"implementationRVAHex"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)rva];
        }
        [records addObject:r];
        [r release];
    }
    if (methods) free(methods);
    return records;
}

NSDictionary *HFAMapResolveLoadedDylibEvidence(NSString *importedPath, NSDictionary *staticEvidence, NSError **error) {
    HFADiagnosticsLog(@"loaded-dylib-evidence", @"start", @{ @"path": importedPath ?: @"", @"policy": @"UNIVERSAL-ONLY" });
    NSDictionary *loaded = HFAFindLoadedImage(importedPath, error);
    if (!loaded) {
        HFADiagnosticsLog(@"loaded-dylib-evidence", @"not-loaded", @{ @"path": importedPath ?: @"" });
        return nil;
    }
    uint32_t imageIndex = [loaded[@"index"] unsignedIntValue];
    NSString *loadedPath = loaded[@"path"] ?: @"";
    NSDictionary *identity = loaded[@"identity"] ?: @{};
    const char *imageName = _dyld_get_image_name(imageIndex);

    unsigned int classNameCount = 0;
    const char **classNames = imageName ? objc_copyClassNamesForImage(imageName, &classNameCount) : NULL;
    NSMutableArray *classes = [NSMutableArray array];
    NSUInteger methodBudget = kHFALoadedMaxMethods;
    NSUInteger ivarBudget = kHFALoadedMaxIvars;
    NSUInteger propertyBudget = kHFALoadedMaxProperties;
    NSUInteger limit = MIN((NSUInteger)classNameCount, kHFALoadedMaxClasses);

    for (NSUInteger i = 0; classNames && i < limit; ++i) {
        const char *rawName = classNames[i];
        if (!rawName) continue;
        Class cls = objc_getClass(rawName);
        if (!cls) continue;
        NSMutableArray *ivars = [NSMutableArray array];
        unsigned int ic = 0; Ivar *ivarList = class_copyIvarList(cls, &ic);
        for (unsigned int j = 0; ivarList && j < ic && ivarBudget; ++j, --ivarBudget) {
            const char *n = ivar_getName(ivarList[j]);
            NSString *name = n ? [NSString stringWithUTF8String:n] : @"";
            const char *t = ivar_getTypeEncoding(ivarList[j]);
            [ivars addObject:@{ @"name": name,
                                @"role": HFAStructuralRole(name),
                                @"offset": @(ivar_getOffset(ivarList[j])),
                                @"typeEncoding": t ? [NSString stringWithUTF8String:t] : @"" }];
        }
        if (ivarList) free(ivarList);

        NSMutableArray *properties = [NSMutableArray array];
        unsigned int pc = 0; objc_property_t *propertyList = class_copyPropertyList(cls, &pc);
        for (unsigned int j = 0; propertyList && j < pc && propertyBudget; ++j, --propertyBudget) {
            const char *n = property_getName(propertyList[j]);
            NSString *name = n ? [NSString stringWithUTF8String:n] : @"";
            const char *a = property_getAttributes(propertyList[j]);
            [properties addObject:@{ @"name": name,
                                     @"role": HFAStructuralRole(name),
                                     @"attributes": a ? [NSString stringWithUTF8String:a] : @"" }];
        }
        if (propertyList) free(propertyList);

        NSArray *instanceMethods = HFAMethodRecordsForClass(cls, NO, identity, &methodBudget);
        NSArray *classMethods = HFAMethodRecordsForClass(cls, YES, identity, &methodBudget);
        [classes addObject:@{
            @"class": [NSString stringWithUTF8String:rawName] ?: @"",
            @"ivars": ivars,
            @"properties": properties,
            @"instanceMethods": instanceMethods,
            @"classMethods": classMethods
        }];
    }
    if (classNames) free(classNames);

    NSUInteger methodCount = 0, ivarCount = 0, propertyCount = 0, inImageMethodCount = 0;
    NSMutableArray *structuralFields = [NSMutableArray array];
    for (NSDictionary *c in classes) {
        NSArray *ims = c[@"instanceMethods"] ?: @[]; NSArray *cms = c[@"classMethods"] ?: @[];
        methodCount += ims.count + cms.count;
        ivarCount += [c[@"ivars"] count]; propertyCount += [c[@"properties"] count];
        for (NSDictionary *m in [ims arrayByAddingObjectsFromArray:cms]) if ([m[@"implementationInImage"] boolValue]) inImageMethodCount++;
        for (NSDictionary *f in c[@"ivars"] ?: @[]) if (![f[@"role"] isEqualToString:@"field"]) [structuralFields addObject:@{ @"class": c[@"class"] ?: @"", @"kind": @"ivar", @"field": f }];
        for (NSDictionary *f in c[@"properties"] ?: @[]) if (![f[@"role"] isEqualToString:@"field"]) [structuralFields addObject:@{ @"class": c[@"class"] ?: @"", @"kind": @"property", @"field": f }];
    }

    NSDictionary *evidence = @{
        @"schema": @"com.hfa.loaded-dylib-evidence/v1",
        @"version": @"2.5.8-dev-universal-loaded-dylib-evidence",
        @"policy": @"UNIVERSAL-ONLY-READ-ONLY-NO-SAMPLE-SPECIAL-CASES",
        @"loaded": @YES,
        @"source": @{ @"selectedPath": importedPath ?: @"", @"loadedPath": loadedPath, @"fileName": loadedPath.lastPathComponent ?: @"", @"uuid": identity[@"uuid"] ?: @"" },
        @"image": identity,
        @"classCount": @(classes.count),
        @"methodCount": @(methodCount),
        @"methodInImageCount": @(inImageMethodCount),
        @"ivarCount": @(ivarCount),
        @"propertyCount": @(propertyCount),
        @"inventoryTruncated": @((NSUInteger)classNameCount > limit || methodBudget == 0 || ivarBudget == 0 || propertyBudget == 0),
        @"classes": classes,
        @"structuralFields": structuralFields,
        @"staticEvidenceSummary": @{
            @"featureEvidenceCount": @([staticEvidence[@"featureEvidence"] count]),
            @"patchEvidenceCount": @([staticEvidence[@"patchEvidence"] count]),
            @"targetImageEvidenceCount": @([staticEvidence[@"targetImageEvidence"] count]),
            @"offsetEvidenceCount": @([staticEvidence[@"offsetEvidence"] count]),
            @"methodEvidenceCount": @([staticEvidence[@"methodEvidence"] count])
        },
        @"safety": @{ @"dlopenCalled": @NO, @"selectorInvoked": @NO, @"impReplaced": @NO, @"memoryWritten": @NO, @"objectInstanceDereferenced": @NO }
    };
    HFADiagnosticsLog(@"loaded-dylib-evidence", @"complete", @{
        @"loadedPath": loadedPath,
        @"classCount": @(classes.count),
        @"methodCount": @(methodCount),
        @"methodInImageCount": @(inImageMethodCount),
        @"structuralFieldCount": @(structuralFields.count),
        @"memoryWritten": @NO
    });
    return evidence;
}

BOOL HFAMapPersistLoadedDylibEvidence(NSDictionary *evidence, NSError **error) {
    if (!evidence) return NO;
    NSData *json = [NSJSONSerialization dataWithJSONObject:evidence options:NSJSONWritingPrettyPrinted error:error];
    if (!json) return NO;
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!docs.length) return NO;
    NSString *path = [docs stringByAppendingPathComponent:HFAOutputFileName(@"LoadedDylibEvidence.json")];
    BOOL ok = [json writeToFile:path options:NSDataWritingAtomic error:error];
    HFADiagnosticsLog(@"loaded-dylib-evidence", ok ? @"persisted" : @"persist-failed", @{ @"output": path ?: @"" });
    return ok;
}

#import "HFAMapLoadedDylibEvidenceResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <objc/runtime.h>

#include <stdint.h>
#include <string.h>

#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

static const NSUInteger kHFALoadedMaxClasses = 256;
static const NSUInteger kHFALoadedMaxMethods = 1024;
static const NSUInteger kHFALoadedMaxIvars = 1024;
static const NSUInteger kHFALoadedMaxProperties = 1024;
static const NSUInteger kHFALoadedMaxDataSections = 64;
static const NSUInteger kHFALoadedMaxGlobalSlots = 16384;
static const NSUInteger kHFALoadedMaxGlobalRelations = 2048;
static const NSUInteger kHFALoadedMaxInstances = 256;
static const NSUInteger kHFALoadedMaxInstanceFields = 2048;
static const NSUInteger kHFALoadedMaxRecordCandidates = 512;
static const uint64_t kHFALoadedMaxBytesPerSection = 512 * 1024;
static const uint64_t kHFALoadedMaxScannedDataBytes = 4 * 1024 * 1024;

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

static uint64_t HFANormalizeDataPointer(uint64_t raw) {
#if __has_feature(ptrauth_calls)
    return (uint64_t)(uintptr_t)ptrauth_strip((void *)(uintptr_t)raw, ptrauth_key_asda);
#else
    return raw;
#endif
}

static BOOL HFAReadMemory(uint64_t address, void *buffer, size_t size) {
    if (!address || !buffer || !size) return NO;
    mach_vm_size_t copied = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
                                              (mach_vm_address_t)address,
                                              (mach_vm_size_t)size,
                                              (mach_vm_address_t)(uintptr_t)buffer,
                                              &copied);
    return kr == KERN_SUCCESS && copied == (mach_vm_size_t)size;
}

static NSString *HFAHex64(uint64_t value) {
    return [NSString stringWithFormat:@"0x%llX", (unsigned long long)value];
}

static NSString *HFAReadableCString(uint64_t address) {
    if (!address) return nil;
    char buffer[97] = {0};
    if (!HFAReadMemory(address, buffer, 96)) return nil;
    NSUInteger length = 0;
    for (; length < 96; ++length) {
        unsigned char c = (unsigned char)buffer[length];
        if (!c) break;
        if (c < 0x20 || c > 0x7E) return nil;
    }
    if (!length || length == 96) return nil;
    return [[[NSString alloc] initWithBytes:buffer length:length encoding:NSUTF8StringEncoding] autorelease];
}

static NSArray *HFAAllLoadedImages(void) {
    NSMutableArray *images = [NSMutableArray array];
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name(i);
        const struct mach_header *mh = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        NSDictionary *identity = HFAImageIdentity(mh, slide);
        if (!identity) continue;
        NSString *path = name ? [NSString stringWithUTF8String:name] : @"";
        [images addObject:@{
            @"index": @(i),
            @"path": path ?: @"",
            @"fileName": path.lastPathComponent ?: @"",
            @"identity": identity
        }];
    }
    return images;
}

static NSDictionary *HFAImageRelation(uint64_t address, NSArray *images) {
    if (!address) return nil;
    for (NSDictionary *image in images) {
        NSDictionary *identity = image[@"identity"];
        if (!HFAAddressInImage(address, identity)) continue;
        uint64_t base = [identity[@"runtimeBase"] unsignedLongLongValue];
        NSMutableDictionary *relation = [@{
            @"path": image[@"path"] ?: @"",
            @"fileName": image[@"fileName"] ?: @"",
            @"uuid": identity[@"uuid"] ?: @"",
            @"runtimeVA": HFAHex64(address),
            @"runtimeVAValue": @(address)
        } mutableCopy];
        if (address >= base) {
            uint64_t rva = address - base;
            relation[@"rva"] = @(rva);
            relation[@"rvaHex"] = HFAHex64(rva);
        }
        return [relation autorelease];
    }
    return nil;
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
            @"implementation": HFAHex64(address),
            @"implementationInImage": @(inImage),
            @"typeEncoding": method_getTypeEncoding(m) ? [NSString stringWithUTF8String:method_getTypeEncoding(m)] : @""
        } mutableCopy];
        if (inImage && address >= base) {
            uint64_t rva = address - base;
            r[@"implementationRVA"] = @(rva);
            r[@"implementationRVAHex"] = HFAHex64(rva);
        }
        [records addObject:r];
        [r release];
    }
    if (methods) free(methods);
    return records;
}

static NSArray *HFADataSectionsForLoadedImage(const struct mach_header *mh, intptr_t slide) {
    if (!mh || mh->magic != MH_MAGIC_64) return @[];
    const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
    const uint8_t *cursor = (const uint8_t *)(h + 1);
    NSMutableArray *sections = [NSMutableArray array];
    for (uint32_t i = 0; i < h->ncmds && sections.count < kHFALoadedMaxDataSections; ++i) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc->cmdsize) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            BOOL readable = (seg->initprot & VM_PROT_READ) != 0;
            BOOL executable = (seg->initprot & VM_PROT_EXECUTE) != 0;
            if (readable && !executable && seg->nsects > 0) {
                const struct section_64 *sect = (const struct section_64 *)(seg + 1);
                uint32_t maxSections = (uint32_t)((lc->cmdsize - sizeof(*seg)) / sizeof(struct section_64));
                uint32_t count = MIN(seg->nsects, maxSections);
                for (uint32_t j = 0; j < count && sections.count < kHFALoadedMaxDataSections; ++j) {
                    if (!sect[j].size) continue;
                    NSString *segName = [[[NSString alloc] initWithBytes:sect[j].segname
                                                                  length:strnlen(sect[j].segname, 16)
                                                                encoding:NSUTF8StringEncoding] autorelease] ?: @"";
                    NSString *sectName = [[[NSString alloc] initWithBytes:sect[j].sectname
                                                                   length:strnlen(sect[j].sectname, 16)
                                                                 encoding:NSUTF8StringEncoding] autorelease] ?: @"";
                    uint64_t runtimeAddress = sect[j].addr + (uint64_t)slide;
                    [sections addObject:@{
                        @"segment": segName,
                        @"section": sectName,
                        @"runtimeAddress": @(runtimeAddress),
                        @"runtimeAddressHex": HFAHex64(runtimeAddress),
                        @"size": @(sect[j].size),
                        @"flags": @(sect[j].flags)
                    }];
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return sections;
}

static size_t HFAIvarReadWidth(const char *type) {
    if (!type || !type[0]) return sizeof(uint64_t);
    switch (type[0]) {
        case 'c': case 'C': case 'B': return 1;
        case 's': case 'S': return 2;
        case 'i': case 'I': case 'l': case 'L': case 'f': return 4;
        case 'q': case 'Q': case 'd': case '@': case '#': case ':': case '^': case '*': return 8;
        default: return 8;
    }
}

static NSDictionary *HFAReadIvarField(uint64_t objectAddress,
                                      Ivar ivar,
                                      NSArray *images,
                                      NSUInteger *fieldBudget) {
    if (!ivar || !fieldBudget || !*fieldBudget) return nil;
    ptrdiff_t offset = ivar_getOffset(ivar);
    if (offset < 0) return nil;
    const char *type = ivar_getTypeEncoding(ivar);
    size_t width = MIN(HFAIvarReadWidth(type), sizeof(uint64_t));
    uint64_t raw = 0;
    if (!HFAReadMemory(objectAddress + (uint64_t)offset, &raw, width)) return nil;
    --(*fieldBudget);
    const char *nameC = ivar_getName(ivar);
    NSString *name = nameC ? [NSString stringWithUTF8String:nameC] : @"";
    NSString *typeString = type ? [NSString stringWithUTF8String:type] : @"";
    NSMutableDictionary *field = [@{
        @"name": name ?: @"",
        @"role": HFAStructuralRole(name ?: @""),
        @"offset": @(offset),
        @"offsetHex": HFAHex64((uint64_t)offset),
        @"typeEncoding": typeString ?: @"",
        @"width": @(width),
        @"rawValue": @(raw),
        @"rawHex": HFAHex64(raw)
    } mutableCopy];
    if (width == sizeof(uint64_t)) {
        uint64_t pointerValue = HFANormalizeDataPointer(raw);
        NSDictionary *relation = HFAImageRelation(pointerValue, images);
        if (relation) field[@"pointerImageRelation"] = relation;
        NSString *cstring = relation ? nil : HFAReadableCString(pointerValue);
        if (cstring) field[@"cstring"] = cstring;
    }
    return [field autorelease];
}

static NSDictionary *HFAClassRecordByClassPointer(Class cls, NSDictionary *classRecordsByPointer) {
    return classRecordsByPointer[[NSValue valueWithPointer:(const void *)cls]];
}

static NSArray *HFARecordCandidatesFromSlotRecords(NSArray *slotRecords) {
    NSMutableArray *candidates = [NSMutableArray array];
    NSMutableArray *cluster = [NSMutableArray array];
    uint64_t previous = 0;
    for (NSDictionary *record in slotRecords) {
        uint64_t slot = [record[@"slotAddress"] unsignedLongLongValue];
        if (cluster.count && (slot <= previous || slot - previous > 0x40)) {
            if (cluster.count >= 2 && candidates.count < kHFALoadedMaxRecordCandidates) {
                NSDictionary *first = cluster.firstObject;
                NSDictionary *last = cluster.lastObject;
                [candidates addObject:@{
                    @"segment": first[@"segment"] ?: @"",
                    @"section": first[@"section"] ?: @"",
                    @"startSlot": first[@"slotAddressHex"] ?: @"",
                    @"endSlot": last[@"slotAddressHex"] ?: @"",
                    @"fieldCount": @(cluster.count),
                    @"fields": [NSArray arrayWithArray:cluster],
                    @"classification": @"metadata-record-candidate",
                    @"verified": @NO
                }];
            }
            [cluster removeAllObjects];
        }
        [cluster addObject:record];
        previous = slot;
    }
    if (cluster.count >= 2 && candidates.count < kHFALoadedMaxRecordCandidates) {
        NSDictionary *first = cluster.firstObject;
        NSDictionary *last = cluster.lastObject;
        [candidates addObject:@{
            @"segment": first[@"segment"] ?: @"",
            @"section": first[@"section"] ?: @"",
            @"startSlot": first[@"slotAddressHex"] ?: @"",
            @"endSlot": last[@"slotAddressHex"] ?: @"",
            @"fieldCount": @(cluster.count),
            @"fields": [NSArray arrayWithArray:cluster],
            @"classification": @"metadata-record-candidate",
            @"verified": @NO
        }];
    }
    return candidates;
}

static NSDictionary *HFAScanInitializedRuntimeState(const struct mach_header *mh,
                                                    intptr_t slide,
                                                    NSArray *images,
                                                    NSDictionary *classRecordsByPointer,
                                                    NSSet *knownClassPointers) {
    NSArray *sections = HFADataSectionsForLoadedImage(mh, slide);
    NSMutableArray *globalRelations = [NSMutableArray array];
    NSMutableArray *slotRecords = [NSMutableArray array];
    NSMutableDictionary *instancesByAddress = [NSMutableDictionary dictionary];
    NSUInteger slotBudget = kHFALoadedMaxGlobalSlots;
    NSUInteger relationBudget = kHFALoadedMaxGlobalRelations;
    NSUInteger fieldBudget = kHFALoadedMaxInstanceFields;
    uint64_t scannedBytes = 0;
    BOOL truncated = NO;

    for (NSDictionary *section in sections) {
        if (!slotBudget || scannedBytes >= kHFALoadedMaxScannedDataBytes) { truncated = YES; break; }
        uint64_t start = [section[@"runtimeAddress"] unsignedLongLongValue];
        uint64_t sectionSize = [section[@"size"] unsignedLongLongValue];
        uint64_t allowed = MIN(sectionSize, kHFALoadedMaxBytesPerSection);
        allowed = MIN(allowed, kHFALoadedMaxScannedDataBytes - scannedBytes);
        uint64_t slots = allowed / sizeof(uint64_t);
        for (uint64_t index = 0; index < slots && slotBudget; ++index, --slotBudget) {
            uint64_t slotAddress = start + index * sizeof(uint64_t);
            uint64_t raw = 0;
            if (!HFAReadMemory(slotAddress, &raw, sizeof(raw)) || raw == 0) continue;
            uint64_t value = HFANormalizeDataPointer(raw);
            if (!value) continue;

            NSMutableDictionary *slot = [@{
                @"segment": section[@"segment"] ?: @"",
                @"section": section[@"section"] ?: @"",
                @"slotAddress": @(slotAddress),
                @"slotAddressHex": HFAHex64(slotAddress),
                @"rawValue": @(raw),
                @"rawHex": HFAHex64(raw),
                @"normalizedValue": @(value),
                @"normalizedHex": HFAHex64(value)
            } mutableCopy];

            NSDictionary *imageRelation = HFAImageRelation(value, images);
            if (imageRelation) {
                slot[@"kind"] = @"image-pointer";
                slot[@"imageRelation"] = imageRelation;
                if (relationBudget) {
                    [globalRelations addObject:slot];
                    --relationBudget;
                }
                [slotRecords addObject:slot];
                [slot release];
                continue;
            }

            uint64_t firstWord = 0;
            if (HFAReadMemory(value, &firstWord, sizeof(firstWord))) {
                Class cls = object_getClass((id)(uintptr_t)value);
                NSValue *classKey = cls ? [NSValue valueWithPointer:(const void *)cls] : nil;
                if (classKey && [knownClassPointers containsObject:classKey]) {
                    NSDictionary *classRecord = HFAClassRecordByClassPointer(cls, classRecordsByPointer) ?: @{};
                    NSString *instanceKey = HFAHex64(value);
                    NSMutableDictionary *instance = instancesByAddress[instanceKey];
                    if (!instance && instancesByAddress.count < kHFALoadedMaxInstances) {
                        NSString *className = classRecord[@"class"] ?: @"";
                        NSUInteger instanceSize = class_getInstanceSize(cls);
                        NSMutableArray *fields = [NSMutableArray array];
                        unsigned int ivarCount = 0;
                        Ivar *ivars = class_copyIvarList(cls, &ivarCount);
                        for (unsigned int i = 0; ivars && i < ivarCount && fieldBudget; ++i) {
                            ptrdiff_t offset = ivar_getOffset(ivars[i]);
                            if (offset < 0 || (NSUInteger)offset >= instanceSize) continue;
                            NSDictionary *field = HFAReadIvarField(value, ivars[i], images, &fieldBudget);
                            if (field) [fields addObject:field];
                        }
                        if (ivars) free(ivars);
                        instance = [@{
                            @"address": @(value),
                            @"addressHex": HFAHex64(value),
                            @"class": className,
                            @"instanceSize": @(instanceSize),
                            @"fields": fields,
                            @"sourceSlots": [NSMutableArray array]
                        } mutableCopy];
                        instancesByAddress[instanceKey] = instance;
                        [instance release];
                    }
                    if (instance) {
                        NSMutableArray *sourceSlots = instance[@"sourceSlots"];
                        if (sourceSlots.count < 16) [sourceSlots addObject:slot[@"slotAddressHex"] ?: @""];
                        slot[@"kind"] = @"objc-instance-pointer";
                        slot[@"class"] = instance[@"class"] ?: @"";
                        slot[@"instanceAddress"] = instance[@"addressHex"] ?: @"";
                        if (relationBudget) {
                            [globalRelations addObject:slot];
                            --relationBudget;
                        }
                        [slotRecords addObject:slot];
                        [slot release];
                        continue;
                    }
                }
            }

            NSString *cstring = HFAReadableCString(value);
            if (cstring) {
                slot[@"kind"] = @"cstring-pointer";
                slot[@"cstring"] = cstring;
                if (relationBudget) {
                    [globalRelations addObject:slot];
                    --relationBudget;
                }
                [slotRecords addObject:slot];
            }
            [slot release];
        }
        scannedBytes += allowed;
        if (allowed < sectionSize) truncated = YES;
    }
    if (!slotBudget || !relationBudget || !fieldBudget) truncated = YES;

    NSArray *instances = [instancesByAddress.allValues sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        uint64_t av = [a[@"address"] unsignedLongLongValue];
        uint64_t bv = [b[@"address"] unsignedLongLongValue];
        if (av < bv) return NSOrderedAscending;
        if (av > bv) return NSOrderedDescending;
        return NSOrderedSame;
    }];
    NSArray *recordCandidates = HFARecordCandidatesFromSlotRecords(slotRecords);
    return @{
        @"dataSections": sections,
        @"scannedDataBytes": @(scannedBytes),
        @"globalRelations": globalRelations,
        @"instances": instances,
        @"recordCandidates": recordCandidates,
        @"runtimeStateTruncated": @(truncated)
    };
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
    const struct mach_header *mh = _dyld_get_image_header(imageIndex);
    intptr_t slide = _dyld_get_image_vmaddr_slide(imageIndex);

    unsigned int classNameCount = 0;
    const char **classNames = imageName ? objc_copyClassNamesForImage(imageName, &classNameCount) : NULL;
    NSMutableArray *classes = [NSMutableArray array];
    NSMutableDictionary *classRecordsByPointer = [NSMutableDictionary dictionary];
    NSMutableSet *knownClassPointers = [NSMutableSet set];
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
        NSDictionary *classRecord = @{
            @"class": [NSString stringWithUTF8String:rawName] ?: @"",
            @"classPointer": HFAHex64((uint64_t)(uintptr_t)cls),
            @"instanceSize": @(class_getInstanceSize(cls)),
            @"ivars": ivars,
            @"properties": properties,
            @"instanceMethods": instanceMethods,
            @"classMethods": classMethods
        };
        [classes addObject:classRecord];
        NSValue *key = [NSValue valueWithPointer:(const void *)cls];
        classRecordsByPointer[key] = classRecord;
        [knownClassPointers addObject:key];
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

    NSArray *images = HFAAllLoadedImages();
    NSDictionary *runtimeState = HFAScanInitializedRuntimeState(mh, slide, images, classRecordsByPointer, knownClassPointers);
    NSArray *instances = runtimeState[@"instances"] ?: @[];
    NSArray *globalRelations = runtimeState[@"globalRelations"] ?: @[];
    NSArray *recordCandidates = runtimeState[@"recordCandidates"] ?: @[];

    NSDictionary *evidence = @{
        @"schema": @"com.hfa.loaded-dylib-evidence/v2",
        @"version": @"2.5.8-dev-universal-initialized-runtime-state",
        @"policy": @"UNIVERSAL-ONLY-READ-ONLY-NO-SAMPLE-SPECIAL-CASES",
        @"loaded": @YES,
        @"source": @{ @"selectedPath": importedPath ?: @"", @"loadedPath": loadedPath, @"fileName": loadedPath.lastPathComponent ?: @"", @"uuid": identity[@"uuid"] ?: @"" },
        @"image": identity,
        @"classCount": @(classes.count),
        @"methodCount": @(methodCount),
        @"methodInImageCount": @(inImageMethodCount),
        @"ivarCount": @(ivarCount),
        @"propertyCount": @(propertyCount),
        @"instanceCount": @(instances.count),
        @"globalRelationCount": @(globalRelations.count),
        @"recordCandidateCount": @(recordCandidates.count),
        @"inventoryTruncated": @((NSUInteger)classNameCount > limit || methodBudget == 0 || ivarBudget == 0 || propertyBudget == 0 || [runtimeState[@"runtimeStateTruncated"] boolValue]),
        @"classes": classes,
        @"structuralFields": structuralFields,
        @"runtimeState": runtimeState,
        @"staticEvidenceSummary": @{
            @"featureEvidenceCount": @([staticEvidence[@"featureEvidence"] count]),
            @"patchEvidenceCount": @([staticEvidence[@"patchEvidence"] count]),
            @"targetImageEvidenceCount": @([staticEvidence[@"targetImageEvidence"] count]),
            @"offsetEvidenceCount": @([staticEvidence[@"offsetEvidence"] count]),
            @"methodEvidenceCount": @([staticEvidence[@"methodEvidence"] count])
        },
        @"safety": @{
            @"dlopenCalled": @NO,
            @"selectorInvoked": @NO,
            @"impReplaced": @NO,
            @"memoryWritten": @NO,
            @"objectInstanceDereferenced": @(instances.count > 0),
            @"instanceFieldsReadByIvarOffset": @(instances.count > 0),
            @"unknownFunctionInvoked": @NO
        }
    };
    HFADiagnosticsLog(@"loaded-dylib-evidence", @"complete", @{
        @"loadedPath": loadedPath,
        @"classCount": @(classes.count),
        @"methodCount": @(methodCount),
        @"methodInImageCount": @(inImageMethodCount),
        @"structuralFieldCount": @(structuralFields.count),
        @"instanceCount": @(instances.count),
        @"globalRelationCount": @(globalRelations.count),
        @"recordCandidateCount": @(recordCandidates.count),
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

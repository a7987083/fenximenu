#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <libkern/OSCacheControl.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <stdint.h>
#include <uuid/uuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static NSString *const HFAPCVersion = @"1.0.0";
static NSString *const HFAPCCommandName = @"HFAPatchPlayback.command.json";
static NSString *const HFAPCResultName = @"HFAPatchPlayback.result.json";
static NSString *const HFAPCLogName = @"HFAPatchPlayback.log";
static NSString *const HFAPCLastCommandName = @"HFAPatchPlayback.command.last.json";

static NSString *HFAPCDocuments(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static NSString *HFAPCPath(NSString *name) {
    return [HFAPCDocuments() stringByAppendingPathComponent:name];
}

static void HFAPCLog(NSString *format, ...) NS_FORMAT_FUNCTION(1,2);
static void HFAPCLog(NSString *format, ...) {
    va_list ap;
    va_start(ap, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:ap];
    va_end(ap);
    NSString *stamp = [[NSDate date] descriptionWithLocale:@"en_US_POSIX"];
    NSString *full = [NSString stringWithFormat:@"%@ %@\n", stamp, line ?: @""];
    NSData *data = [full dataUsingEncoding:NSUTF8StringEncoding];
    NSString *path = HFAPCPath(HFAPCLogName);
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) [fm createFileAtPath:path contents:nil attributes:nil];
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:path];
    if (h) {
        @try {
            [h seekToEndOfFile];
            [h writeData:data];
            [h synchronizeFile];
        } @catch (__unused NSException *e) {}
        [h closeFile];
    }
}

static NSDictionary *HFAPCReadJSON(NSString *path, NSString **errorOut) {
    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:nil];
    if (!data) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"cannot-read:%@", path.lastPathComponent];
        return nil;
    }
    NSError *error = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (![obj isKindOfClass:[NSDictionary class]]) {
        if (errorOut) *errorOut = error ? error.localizedDescription : @"root-not-dictionary";
        return nil;
    }
    return obj;
}

static BOOL HFAPCWriteJSON(NSDictionary *obj, NSString *path) {
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:obj options:NSJSONWritingPrettyPrinted error:&error];
    if (!data) {
        HFAPCLog(@"[RESULT-WRITE] status=fail reason=%@", error.localizedDescription ?: @"serialize");
        return NO;
    }
    return [data writeToFile:path options:NSDataWritingAtomic error:&error];
}

static const char *HFAPCBase(const char *path) {
    if (!path) return "";
    const char *q = strrchr(path, '/');
    return q ? q + 1 : path;
}

static NSString *HFAPCBaseString(const char *path) {
    return [NSString stringWithUTF8String:HFAPCBase(path)] ?: @"";
}

static NSString *HFAPCUUIDString(const uuid_t uuid) {
    if (!uuid) return nil;
    return [NSString stringWithFormat:@"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
            uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]];
}

static int HFAPCMainExecutableImageIndex(void) {
    NSString *bundlePath = NSBundle.mainBundle.executablePath;
    NSString *bundleBase = bundlePath.lastPathComponent;
    int unique = -1;
    unsigned matches = 0;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        if (!header || header->filetype != MH_EXECUTE) continue;
        const char *name = _dyld_get_image_name(i);
        NSString *path = name ? [NSString stringWithUTF8String:name] : nil;
        NSString *base = path.lastPathComponent;
        if (bundlePath.length && [path isEqualToString:bundlePath]) return (int)i;
        if (bundleBase.length && [base isEqualToString:bundleBase]) {
            unique = (int)i;
            matches++;
        } else if (unique < 0) {
            unique = (int)i;
            matches++;
        } else {
            matches++;
        }
    }
    if (matches == 1) return unique;
    return -1;
}

static int HFAPCImageIndexForDeclaredImage(NSString *value) {
    if (![value isKindOfClass:[NSString class]] || value.length == 0) return -1;
    if ([value isEqualToString:@"main"] || [value isEqualToString:@"@main"]) {
        return HFAPCMainExecutableImageIndex();
    }
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        NSString *base = HFAPCBaseString(name);
        if ([value isEqualToString:base]) return (int)i;
        NSString *stem = base.stringByDeletingPathExtension;
        if ([value isEqualToString:stem]) return (int)i;
    }
    return -1;
}

typedef struct {
    BOOL valid;
    uint32_t imageIndex;
    const struct mach_header_64 *header;
    intptr_t slide;
    NSString *resolvedImage;
    NSString *uuid;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint64_t preferredTextVMAddr;
    uint32_t cryptid;
    NSString *architecture;
} HFAPCImageIdentity;

static HFAPCImageIdentity HFAPCIdentityForImageIndex(uint32_t imageIndex) {
    HFAPCImageIdentity out = {0};
    const struct mach_header *mh = _dyld_get_image_header(imageIndex);
    if (!mh || mh->magic != MH_MAGIC_64) return out;
    const struct mach_header_64 *header = (const struct mach_header_64 *)mh;
    out.imageIndex = imageIndex;
    out.header = header;
    out.slide = _dyld_get_image_vmaddr_slide(imageIndex);
    out.resolvedImage = HFAPCBaseString(_dyld_get_image_name(imageIndex));
    out.cputype = header->cputype;
    out.cpusubtype = (header->cpusubtype & ~CPU_SUBTYPE_MASK);
    out.preferredTextVMAddr = UINT64_MAX;
    out.cryptid = 0;

    const uint8_t *cursor = (const uint8_t *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(struct load_command)) return (HFAPCImageIdentity){0};
        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uc = (const struct uuid_command *)lc;
            out.uuid = HFAPCUUIDString(uc->uuid);
        } else if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strncmp(seg->segname, "__TEXT", 16) == 0) out.preferredTextVMAddr = seg->vmaddr;
        } else if (lc->cmd == LC_ENCRYPTION_INFO_64 && lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            out.cryptid = ((const struct encryption_info_command_64 *)lc)->cryptid;
        } else if (lc->cmd == LC_ENCRYPTION_INFO && lc->cmdsize >= sizeof(struct encryption_info_command)) {
            out.cryptid = ((const struct encryption_info_command *)lc)->cryptid;
        }
        cursor += lc->cmdsize;
    }
    if (out.cputype == CPU_TYPE_ARM64) {
#ifdef CPU_SUBTYPE_ARM64E
        out.architecture = (out.cpusubtype == CPU_SUBTYPE_ARM64E) ? @"arm64e" : @"arm64";
#else
        out.architecture = @"arm64";
#endif
    } else {
        out.architecture = [NSString stringWithFormat:@"cpu-%d", out.cputype];
    }
    out.valid = (out.uuid.length > 0 && out.preferredTextVMAddr != UINT64_MAX);
    return out;
}

static BOOL HFAPCParseHexU64(NSString *text, uint64_t *valueOut) {
    if (![text isKindOfClass:[NSString class]] || text.length == 0 || !valueOut) return NO;
    const char *s = text.UTF8String;
    if (!s) return NO;
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(s, &end, 0);
    if (errno || end == s || *end != '\0') return NO;
    *valueOut = (uint64_t)value;
    return YES;
}

static NSData *HFAPCHexData(NSString *hex) {
    if (![hex isKindOfClass:[NSString class]] || hex.length == 0 || (hex.length & 1)) return nil;
    NSUInteger count = hex.length / 2;
    if (count == 0 || count > 256) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:count];
    uint8_t *bytes = data.mutableBytes;
    for (NSUInteger i = 0; i < count; i++) {
        unichar hi = [hex characterAtIndex:i * 2];
        unichar lo = [hex characterAtIndex:i * 2 + 1];
        int a = (hi >= '0' && hi <= '9') ? hi - '0' : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 : -1;
        int b = (lo >= '0' && lo <= '9') ? lo - '0' : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 : -1;
        if (a < 0 || b < 0) return nil;
        bytes[i] = (uint8_t)((a << 4) | b);
    }
    return data;
}

static NSString *HFAPCHexString(NSData *data) {
    if (!data) return @"";
    const uint8_t *bytes = data.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) [s appendFormat:@"%02X", bytes[i]];
    return s;
}

static NSData *HFAPCReadMemory(mach_vm_address_t address, mach_vm_size_t size, NSString **errorOut) {
    if (!address || !size || size > 256) {
        if (errorOut) *errorOut = @"invalid-read-range";
        return nil;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)size];
    mach_vm_size_t read = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), address, size,
                                               (mach_vm_address_t)data.mutableBytes, &read);
    if (kr != KERN_SUCCESS || read != size) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"mach_vm_read_overwrite:%d:%llu/%llu", kr, read, size];
        return nil;
    }
    return data;
}

static BOOL HFAPCWriteMemory(mach_vm_address_t address, NSData *data, NSString **errorOut) {
    if (!address || data.length == 0 || data.length > 256) {
        if (errorOut) *errorOut = @"invalid-write-range";
        return NO;
    }
    vm_size_t pageSize = 0;
    host_page_size(mach_host_self(), &pageSize);
    if (!pageSize) pageSize = 0x4000;
    mach_vm_address_t start = address & ~((mach_vm_address_t)pageSize - 1);
    mach_vm_address_t end = (address + data.length + pageSize - 1) & ~((mach_vm_address_t)pageSize - 1);
    mach_vm_size_t protectSize = end - start;

    mach_vm_address_t regionAddress = address;
    mach_vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &regionAddress, &regionSize,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    if (kr != KERN_SUCCESS || address < regionAddress || address + data.length > regionAddress + regionSize) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"mach_vm_region:%d", kr];
        return NO;
    }

    vm_prot_t writeProtection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY;
    kr = mach_vm_protect(mach_task_self(), start, protectSize, FALSE, writeProtection);
    if (kr != KERN_SUCCESS) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"mach_vm_protect-write:%d", kr];
        return NO;
    }

    kr = mach_vm_write(mach_task_self(), address, (vm_offset_t)data.bytes,
                       (mach_msg_type_number_t)data.length);
    kern_return_t restoreKR = mach_vm_protect(mach_task_self(), start, protectSize, FALSE, info.protection);
    if (kr != KERN_SUCCESS) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"mach_vm_write:%d restore:%d", kr, restoreKR];
        return NO;
    }
    if (restoreKR != KERN_SUCCESS) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"mach_vm_protect-restore:%d", restoreKR];
        return NO;
    }
    sys_icache_invalidate((void *)(uintptr_t)address, data.length);
    return YES;
}

static BOOL HFAPCPackageMatchesBundle(NSDictionary *package, NSString **errorOut) {
    NSDictionary *meta = package[@"package"];
    if (![meta isKindOfClass:[NSDictionary class]]) {
        if (errorOut) *errorOut = @"missing-package-metadata";
        return NO;
    }
    NSString *bundle = meta[@"bundleIdentifier"];
    NSString *shortVersion = meta[@"shortVersion"];
    NSString *buildVersion = meta[@"buildVersion"];
    NSDictionary *info = NSBundle.mainBundle.infoDictionary;
    NSString *actualBundle = NSBundle.mainBundle.bundleIdentifier ?: @"";
    NSString *actualShort = info[@"CFBundleShortVersionString"] ?: @"";
    NSString *actualBuild = info[@"CFBundleVersion"] ?: @"";
    if (bundle.length && ![bundle isEqualToString:actualBundle]) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"bundle-id-mismatch expected=%@ actual=%@", bundle, actualBundle];
        return NO;
    }
    if (shortVersion.length && actualShort.length && ![shortVersion isEqualToString:actualShort]) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"short-version-mismatch expected=%@ actual=%@", shortVersion, actualShort];
        return NO;
    }
    if (buildVersion.length && actualBuild.length && ![buildVersion isEqualToString:actualBuild]) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"build-version-mismatch expected=%@ actual=%@", buildVersion, actualBuild];
        return NO;
    }
    return YES;
}

static BOOL HFAPCIdentityPackageMatchesCanonical(NSDictionary *package, NSDictionary *identity, NSString **errorOut) {
    NSDictionary *a = package[@"package"];
    NSDictionary *b = identity[@"package"];
    if (![a isKindOfClass:[NSDictionary class]] || ![b isKindOfClass:[NSDictionary class]]) {
        if (errorOut) *errorOut = @"identity-package-metadata-missing";
        return NO;
    }
    for (NSString *key in @[@"bundleIdentifier", @"shortVersion", @"buildVersion"]) {
        NSString *av = a[key];
        NSString *bv = b[key];
        if (![av isKindOfClass:[NSString class]] || ![bv isKindOfClass:[NSString class]] || ![av isEqualToString:bv]) {
            if (errorOut) *errorOut = [NSString stringWithFormat:@"identity-package-mismatch:%@", key];
            return NO;
        }
    }
    return YES;
}

static BOOL HFAPCIdentityMatches(NSString *targetKey,
                                 NSString *declaredImage,
                                 NSDictionary *identityRoot,
                                 HFAPCImageIdentity actual,
                                 NSMutableDictionary *record,
                                 NSString **errorOut) {
    NSDictionary *targets = identityRoot[@"targets"];
    NSDictionary *expected = [targets isKindOfClass:[NSDictionary class]] ? targets[targetKey] : nil;
    if (![expected isKindOfClass:[NSDictionary class]]) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"identity-target-missing:%@", targetKey];
        return NO;
    }
    if (![identityRoot[@"schema"] isEqual:@"com.hfa.patch.identity/v1"] ||
        ![identityRoot[@"offsetSemantics"] isEqual:@"preferred-mach-o-vmaddr"]) {
        if (errorOut) *errorOut = @"identity-schema-or-offset-semantics";
        return NO;
    }
    NSString *status = expected[@"status"];
    NSString *uuid = expected[@"uuid"];
    NSString *arch = expected[@"architecture"];
    NSString *resolved = expected[@"resolvedImage"];
    NSString *declared = expected[@"declaredImage"];
    NSNumber *cputype = expected[@"cputype"];
    NSNumber *cpusubtype = expected[@"cpusubtype"];
    NSNumber *cryptid = expected[@"cryptid"];
    uint64_t textVM = 0;
    if (![status isEqual:@"resolved"] ||
        !HFAPCParseHexU64(expected[@"preferredTextVMAddr"], &textVM) ||
        ![uuid isKindOfClass:[NSString class]] || ![arch isKindOfClass:[NSString class]] ||
        ![cputype isKindOfClass:[NSNumber class]] || ![cpusubtype isKindOfClass:[NSNumber class]] ||
        ![cryptid isKindOfClass:[NSNumber class]]) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"identity-record-invalid:%@", targetKey];
        return NO;
    }
    BOOL uuidOK = actual.valid && actual.uuid.length > 0 &&
                  ([uuid caseInsensitiveCompare:actual.uuid] == NSOrderedSame);
    BOOL imageOK = (!resolved.length || [resolved isEqualToString:actual.resolvedImage]) &&
                   (!declared.length || [declared isEqualToString:declaredImage]);
    BOOL metaOK = actual.valid && actual.cputype == cputype.intValue &&
                  actual.cpusubtype == cpusubtype.intValue && actual.cryptid == cryptid.unsignedIntValue &&
                  actual.preferredTextVMAddr == textVM && [actual.architecture isEqualToString:arch];
    record[@"target"] = targetKey;
    record[@"declaredImage"] = declaredImage;
    record[@"resolvedImage"] = actual.resolvedImage ?: @"";
    record[@"uuid"] = actual.uuid ?: @"";
    record[@"architecture"] = actual.architecture ?: @"";
    record[@"cputype"] = @(actual.cputype);
    record[@"cpusubtype"] = @(actual.cpusubtype);
    record[@"preferredTextVMAddr"] = [NSString stringWithFormat:@"0x%llX", actual.preferredTextVMAddr];
    record[@"cryptid"] = @(actual.cryptid);
    record[@"imageIndex"] = @(actual.imageIndex);
    record[@"slide"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)actual.slide];
    if (!uuidOK || !imageOK || !metaOK) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"identity-mismatch target=%@ uuid=%d image=%d meta=%d", targetKey, uuidOK, imageOK, metaOK];
        return NO;
    }
    return YES;
}

@interface HFAPCPatchPlan : NSObject
@property(nonatomic, copy) NSString *featureId;
@property(nonatomic, copy) NSString *featureTitle;
@property(nonatomic, copy) NSString *targetKey;
@property(nonatomic, copy) NSString *declaredImage;
@property(nonatomic) uint64_t preferredVMAddr;
@property(nonatomic) mach_vm_address_t runtimeAddress;
@property(nonatomic, strong) NSData *original;
@property(nonatomic, strong) NSData *enabled;
@property(nonatomic, strong) NSData *expectedBefore;
@property(nonatomic, strong) NSData *desiredAfter;
@property(nonatomic, strong) NSMutableDictionary *record;
@end
@implementation HFAPCPatchPlan @end

static NSArray<NSDictionary *> *HFAPCSelectedFeatures(NSDictionary *package, NSArray *featureIds, NSString **errorOut) {
    NSArray *features = package[@"features"];
    if (![features isKindOfClass:[NSArray class]] || features.count == 0) {
        if (errorOut) *errorOut = @"features-missing";
        return nil;
    }
    if (featureIds.count == 0) return features;
    NSMutableArray *selected = [NSMutableArray array];
    NSMutableSet *wanted = [NSMutableSet set];
    for (id v in featureIds) if ([v isKindOfClass:[NSString class]]) [wanted addObject:v];
    for (NSDictionary *f in features) {
        if (![f isKindOfClass:[NSDictionary class]]) continue;
        NSString *fid = f[@"id"];
        if ([wanted containsObject:fid]) {
            [selected addObject:f];
            [wanted removeObject:fid];
        }
    }
    if (wanted.count) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"feature-id-not-found:%@", [[wanted allObjects] componentsJoinedByString:@","]];
        return nil;
    }
    return selected;
}

static BOOL HFAPCBuildPlan(NSDictionary *package,
                           NSDictionary *identity,
                           NSArray<NSDictionary *> *features,
                           NSString *action,
                           NSMutableArray<HFAPCPatchPlan *> *plans,
                           NSMutableArray *targetRecords,
                           NSString **errorOut) {
    NSDictionary *targets = package[@"targets"];
    if (![targets isKindOfClass:[NSDictionary class]] || targets.count == 0) {
        if (errorOut) *errorOut = @"targets-missing";
        return NO;
    }
    NSMutableDictionary<NSString *, NSNumber *> *imageIndexCache = [NSMutableDictionary dictionary];
    NSMutableSet *targetLogged = [NSMutableSet set];
    NSMutableSet *addressKeys = [NSMutableSet set];

    for (NSDictionary *feature in features) {
        NSString *fid = feature[@"id"];
        NSString *title = feature[@"title"];
        NSArray *patches = feature[@"patches"];
        if (![fid isKindOfClass:[NSString class]] || ![title isKindOfClass:[NSString class]] ||
            ![patches isKindOfClass:[NSArray class]] || patches.count == 0) {
            if (errorOut) *errorOut = @"feature-record-invalid";
            return NO;
        }
        for (NSDictionary *patch in patches) {
            NSString *targetKey = patch[@"target"];
            NSString *offset = patch[@"offset"];
            NSData *original = HFAPCHexData(patch[@"original"]);
            NSData *enabled = HFAPCHexData(patch[@"enabled"]);
            NSDictionary *targetDef = [targetKey isKindOfClass:[NSString class]] ? targets[targetKey] : nil;
            NSString *declaredImage = [targetDef isKindOfClass:[NSDictionary class]] ? targetDef[@"image"] : nil;
            uint64_t preferred = 0;
            if (![targetKey isKindOfClass:[NSString class]] || ![declaredImage isKindOfClass:[NSString class]] ||
                !HFAPCParseHexU64(offset, &preferred) || !original || !enabled || original.length != enabled.length) {
                if (errorOut) *errorOut = [NSString stringWithFormat:@"patch-record-invalid feature=%@", fid ?: @"?"];
                return NO;
            }

            NSNumber *cachedIndex = imageIndexCache[targetKey];
            int index = cachedIndex ? cachedIndex.intValue : HFAPCImageIndexForDeclaredImage(declaredImage);
            if (index < 0) {
                if (errorOut) *errorOut = [NSString stringWithFormat:@"target-unresolved:%@ image=%@", targetKey, declaredImage];
                return NO;
            }
            imageIndexCache[targetKey] = @(index);
            HFAPCImageIdentity actual = HFAPCIdentityForImageIndex((uint32_t)index);
            NSMutableDictionary *targetRecord = [NSMutableDictionary dictionary];
            NSString *identityError = nil;
            if (!HFAPCIdentityMatches(targetKey, declaredImage, identity, actual, targetRecord, &identityError)) {
                if (errorOut) *errorOut = identityError;
                return NO;
            }
            if (![targetLogged containsObject:targetKey]) {
                [targetRecords addObject:targetRecord];
                [targetLogged addObject:targetKey];
            }

            NSString *addressKey = [NSString stringWithFormat:@"%@:%llX", targetKey, preferred];
            if ([addressKeys containsObject:addressKey]) {
                if (errorOut) *errorOut = [NSString stringWithFormat:@"duplicate-patch-address:%@", addressKey];
                return NO;
            }
            [addressKeys addObject:addressKey];
            mach_vm_address_t runtime = (mach_vm_address_t)(preferred + actual.slide);
            NSData *expected = [action isEqualToString:@"restore"] ? enabled : original;
            NSData *desired = [action isEqualToString:@"restore"] ? original : enabled;
            NSString *readError = nil;
            NSData *current = HFAPCReadMemory(runtime, expected.length, &readError);
            if (!current || ![current isEqualToData:expected]) {
                if (errorOut) *errorOut = [NSString stringWithFormat:@"preflight-byte-mismatch feature=%@ target=%@ offset=%@ expected=%@ actual=%@ read=%@",
                                          fid, targetKey, offset, HFAPCHexString(expected), HFAPCHexString(current), readError ?: @"ok"];
                return NO;
            }

            HFAPCPatchPlan *plan = [HFAPCPatchPlan new];
            plan.featureId = fid;
            plan.featureTitle = title;
            plan.targetKey = targetKey;
            plan.declaredImage = declaredImage;
            plan.preferredVMAddr = preferred;
            plan.runtimeAddress = runtime;
            plan.original = original;
            plan.enabled = enabled;
            plan.expectedBefore = expected;
            plan.desiredAfter = desired;
            plan.record = [@{
                @"featureId": fid,
                @"featureTitle": title,
                @"target": targetKey,
                @"image": declaredImage,
                @"offset": offset,
                @"runtimeAddress": [NSString stringWithFormat:@"0x%llX", runtime],
                @"expectedBefore": HFAPCHexString(expected),
                @"actualBefore": HFAPCHexString(current),
                @"desiredAfter": HFAPCHexString(desired),
                @"preflight": @"pass"
            } mutableCopy];
            [plans addObject:plan];
        }
    }
    return plans.count > 0;
}

static BOOL HFAPCExecuteTransaction(NSMutableArray<HFAPCPatchPlan *> *plans,
                                    NSMutableArray *patchRecords,
                                    NSString **errorOut) {
    NSMutableArray<HFAPCPatchPlan *> *written = [NSMutableArray array];
    for (HFAPCPatchPlan *plan in plans) {
        NSString *writeError = nil;
        BOOL ok = HFAPCWriteMemory(plan.runtimeAddress, plan.desiredAfter, &writeError);
        if (ok) {
            NSString *readError = nil;
            NSData *after = HFAPCReadMemory(plan.runtimeAddress, plan.desiredAfter.length, &readError);
            ok = after && [after isEqualToData:plan.desiredAfter];
            plan.record[@"actualAfter"] = HFAPCHexString(after);
            plan.record[@"write"] = ok ? @"pass" : @"readback-mismatch";
            if (!ok) writeError = readError ?: @"readback-mismatch";
        } else {
            plan.record[@"write"] = @"fail";
        }
        [patchRecords addObject:plan.record];
        if (!ok) {
            HFAPCLog(@"[ROLLBACK-BEGIN] count=%lu", (unsigned long)written.count);
            for (HFAPCPatchPlan *done in [written reverseObjectEnumerator]) {
                NSString *rollbackError = nil;
                BOOL rollbackOK = HFAPCWriteMemory(done.runtimeAddress, done.expectedBefore, &rollbackError);
                NSData *verify = rollbackOK ? HFAPCReadMemory(done.runtimeAddress, done.expectedBefore.length, nil) : nil;
                rollbackOK = rollbackOK && [verify isEqualToData:done.expectedBefore];
                done.record[@"rollback"] = rollbackOK ? @"pass" : (rollbackError ?: @"fail");
                HFAPCLog(@"[ROLLBACK] feature=%@ offset=0x%llX status=%@", done.featureId,
                         done.preferredVMAddr, rollbackOK ? @"pass" : @"fail");
            }
            if (errorOut) *errorOut = [NSString stringWithFormat:@"write-transaction-failed feature=%@ offset=0x%llX reason=%@",
                                      plan.featureId, plan.preferredVMAddr, writeError ?: @"unknown"];
            return NO;
        }
        [written addObject:plan];
    }
    return YES;
}

static NSDictionary *HFAPCResultBase(NSString *status, NSString *action, NSString *reason) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"schema"] = @"com.hfa.patch.playback.result/v1";
    result[@"consumerVersion"] = HFAPCVersion;
    result[@"status"] = status ?: @"fail";
    result[@"action"] = action ?: @"unknown";
    result[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
    if (reason.length) result[@"reason"] = reason;
    return result;
}

static void HFAPCProcessCommand(void) {
    @autoreleasepool {
        NSString *commandPath = HFAPCPath(HFAPCCommandName);
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:commandPath]) return;
        NSString *lastPath = HFAPCPath(HFAPCLastCommandName);
        [fm removeItemAtPath:lastPath error:nil];
        NSError *moveError = nil;
        if (![fm moveItemAtPath:commandPath toPath:lastPath error:&moveError]) {
            HFAPCLog(@"[COMMAND-CLAIM] status=fail reason=%@", moveError.localizedDescription ?: @"move-failed");
            return;
        }
        NSString *error = nil;
        NSDictionary *command = HFAPCReadJSON(lastPath, &error);
        if (!command) {
            HFAPCWriteJSON(HFAPCResultBase(@"fail", @"unknown", error), HFAPCPath(HFAPCResultName));
            return;
        }
        NSString *action = command[@"action"];
        if (![action isEqualToString:@"preflight"] && ![action isEqualToString:@"apply"] && ![action isEqualToString:@"restore"]) {
            error = @"action-must-be-preflight-apply-or-restore";
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
        NSString *packageName = command[@"package"];
        if (![packageName isKindOfClass:[NSString class]] || packageName.length == 0 || [packageName containsString:@"/"]) {
            error = @"invalid-package-filename";
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
        NSString *identityName = command[@"identity"];
        if (![identityName isKindOfClass:[NSString class]] || identityName.length == 0) {
            if ([packageName hasSuffix:@".hfapatch.json"]) {
                identityName = [[packageName substringToIndex:packageName.length - @".hfapatch.json".length]
                                stringByAppendingString:@".hfapatch.identity.json"];
            }
        }
        if (!identityName.length || [identityName containsString:@"/"]) {
            error = @"invalid-identity-filename";
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
        NSDictionary *package = HFAPCReadJSON(HFAPCPath(packageName), &error);
        if (!package || ![package[@"schema"] isEqual:@"com.hfa.patch/v1"]) {
            error = error ?: @"package-schema-not-com.hfa.patch/v1";
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
        NSDictionary *identity = HFAPCReadJSON(HFAPCPath(identityName), &error);
        if (!identity) {
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
        if (!HFAPCPackageMatchesBundle(package, &error) || !HFAPCIdentityPackageMatchesCanonical(package, identity, &error)) {
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
        NSArray *featureIds = [command[@"featureIds"] isKindOfClass:[NSArray class]] ? command[@"featureIds"] : @[];
        NSArray<NSDictionary *> *features = HFAPCSelectedFeatures(package, featureIds, &error);
        if (!features) {
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
        NSMutableArray<HFAPCPatchPlan *> *plans = [NSMutableArray array];
        NSMutableArray *targetRecords = [NSMutableArray array];
        if (!HFAPCBuildPlan(package, identity, features, action, plans, targetRecords, &error)) {
            NSMutableDictionary *result = [HFAPCResultBase(@"fail", action, error) mutableCopy];
            result[@"package"] = packageName;
            result[@"identity"] = identityName;
            result[@"featureIds"] = featureIds;
            result[@"targets"] = targetRecords;
            HFAPCWriteJSON(result, HFAPCPath(HFAPCResultName));
            HFAPCLog(@"[PREFLIGHT] action=%@ status=fail reason=%@", action, error);
            return;
        }

        NSMutableArray *patchRecords = [NSMutableArray array];
        BOOL ok = YES;
        if (![action isEqualToString:@"preflight"]) {
            ok = HFAPCExecuteTransaction(plans, patchRecords, &error);
        } else {
            for (HFAPCPatchPlan *plan in plans) [patchRecords addObject:plan.record];
        }
        NSMutableDictionary *result = [HFAPCResultBase(ok ? @"pass" : @"fail", action, error) mutableCopy];
        result[@"package"] = packageName;
        result[@"identity"] = identityName;
        result[@"featureIds"] = featureIds;
        result[@"selectedFeatureCount"] = @(features.count);
        result[@"patchCount"] = @(plans.count);
        result[@"targets"] = targetRecords;
        result[@"patches"] = patchRecords;
        result[@"behaviorConfirmed"] = @NO;
        result[@"behaviorNote"] = @"Set by human observation after apply/restore; consumer verifies bytes, not gameplay semantics.";
        HFAPCWriteJSON(result, HFAPCPath(HFAPCResultName));
        HFAPCLog(@"[PLAYBACK] action=%@ status=%@ features=%lu patches=%lu reason=%@",
                 action, ok ? @"pass" : @"fail", (unsigned long)features.count,
                 (unsigned long)plans.count, error ?: @"none");
    }
}

static dispatch_source_t gHFAPCTimer;

__attribute__((constructor)) static void HFAPCInit(void) {
    HFAPCLog(@"[LOAD] HFAPatchConsumerPlayback v%@ pid=%d", HFAPCVersion, getpid());
    dispatch_queue_t queue = dispatch_queue_create("com.hfa.patchconsumer.playback", DISPATCH_QUEUE_SERIAL);
    gHFAPCTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    dispatch_source_set_timer(gHFAPCTimer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                              (uint64_t)(1 * NSEC_PER_SEC),
                              (uint64_t)(100 * NSEC_PER_MSEC));
    dispatch_source_set_event_handler(gHFAPCTimer, ^{
        HFAPCProcessCommand();
    });
    dispatch_resume(gHFAPCTimer);
}

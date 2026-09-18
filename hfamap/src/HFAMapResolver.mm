#import "HFAMapResolver.h"
#import "HFAMapDiagnostics.h"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/vm_prot.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static const NSUInteger kHFAMaxViews = 768, kHFAMaxTargets = 192;
static const NSUInteger kHFAMaxContainers = 256, kHFAMaxItems = 128;

static void HFAResolveEvent(NSMutableArray *events, NSString *status, NSDictionary *details) {
    NSMutableDictionary *event = [@{ @"time": @([[NSDate date] timeIntervalSince1970]),
                                      @"stage": @"feature-resolution", @"status": status } mutableCopy];
    if (details) [event addEntriesFromDictionary:details];
    [events addObject:event];
}

static NSData *HFAHexData(NSString *text) {
    if (![text isKindOfClass:NSString.class]) return nil;
    NSString *clean = [[text stringByReplacingOccurrencesOfString:@"0x" withString:@""]
                       stringByReplacingOccurrencesOfString:@" " withString:@""];
    clean = [clean stringByReplacingOccurrencesOfString:@"_" withString:@""];
    if (!clean.length || clean.length % 2 || clean.length > 512) return nil;
    NSMutableData *data = [NSMutableData dataWithCapacity:clean.length / 2];
    for (NSUInteger i = 0; i < clean.length; i += 2) {
        unsigned value = 0;
        NSScanner *scanner = [NSScanner scannerWithString:[clean substringWithRange:NSMakeRange(i, 2)]];
        if (![scanner scanHexInt:&value] || !scanner.isAtEnd) return nil;
        uint8_t byte = (uint8_t)value; [data appendBytes:&byte length:1];
    }
    return data;
}

static NSData *HFABytesValue(id value) {
    if ([value isKindOfClass:NSData.class]) return value;
    if ([value isKindOfClass:NSString.class]) return HFAHexData(value);
    if (![value isKindOfClass:NSArray.class] || [value count] > 256) return nil;
    NSMutableData *data = [NSMutableData dataWithCapacity:[value count]];
    for (id item in value) {
        if (![item isKindOfClass:NSNumber.class] || [item unsignedIntegerValue] > 255) return nil;
        uint8_t byte = [item unsignedCharValue]; [data appendBytes:&byte length:1];
    }
    return data.length ? data : nil;
}

static NSNumber *HFAOffsetValue(id value) {
    if ([value isKindOfClass:NSNumber.class]) return @([value unsignedLongLongValue]);
    if (![value isKindOfClass:NSString.class]) return nil;
    NSString *text = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    const char *raw = text.UTF8String; if (!raw || !*raw || raw[0] == '-') return nil;
    errno = 0; char *end = NULL; unsigned long long number = strtoull(raw, &end, 0);
    return errno == 0 && end && *end == '\0' ? @(number) : nil;
}

static id HFAValueForAliases(NSDictionary *dictionary, NSArray<NSString *> *aliases) {
    for (id key in dictionary) {
        if (![key isKindOfClass:NSString.class]) continue;
        NSString *lower = [[key lowercaseString] stringByTrimmingCharactersInSet:
                           [NSCharacterSet characterSetWithCharactersInString:@"_"]];
        for (NSString *alias in aliases) if ([lower isEqualToString:alias]) return dictionary[key];
    }
    return nil;
}

static BOOL HFADescriptorSignal(NSDictionary *dictionary) {
    static NSSet<NSString *> *signals; static dispatch_once_t once;
    dispatch_once(&once, ^{ signals = [NSSet setWithArray:@[
        @"label", @"title", @"name", @"identifier", @"displayname",
        @"offset", @"offsets", @"patchoffset", @"targetoffset", @"address", @"rva",
        @"enabled", @"enabledbytes", @"disabled", @"disabledbytes",
        @"patch", @"patches", @"patchbytes", @"bytes", @"instruction"
    ]]; });
    for (id key in dictionary) {
        if (![key isKindOfClass:NSString.class]) continue;
        NSString *normalized = [[key lowercaseString] stringByTrimmingCharactersInSet:
                                [NSCharacterSet characterSetWithCharactersInString:@"_"]];
        if ([signals containsObject:normalized]) return YES;
    }
    return NO;
}

static BOOL HFACandidateOwnedObject(id value, NSString *candidateImage) {
    if (!value || !candidateImage.length) return NO;
    const char *path = class_getImageName(object_getClass(value));
    NSString *image = path ? [NSString stringWithUTF8String:path].lastPathComponent : @"";
    return [image isEqualToString:candidateImage];
}

static NSDictionary *HFADictionaryFromObject(id object) {
    if (!object) return nil;
    if ([object isKindOfClass:NSDictionary.class]) return object;
    NSMutableDictionary *values = [NSMutableDictionary dictionary];
    Class cursor = object_getClass(object);
    for (NSUInteger depth = 0; cursor && depth < 12 && cursor != NSObject.class;
         ++depth, cursor = class_getSuperclass(cursor)) {
        unsigned count = 0; Ivar *ivars = class_copyIvarList(cursor, &count); count = MIN(count, 64U);
        for (unsigned i = 0; ivars && i < count; ++i) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            const char *name = ivar_getName(ivars[i]);
            if (!type || !name) continue;
            NSString *key = [NSString stringWithUTF8String:name];
            if (type[0] == '@') {
                id value = nil; @try { value = object_getIvar(object, ivars[i]); } @catch (...) {}
                if (value) values[key] = value;
                continue;
            }
            ptrdiff_t offset = ivar_getOffset(ivars[i]);
            size_t instanceSize = class_getInstanceSize(cursor);
            unsigned long long scalar = 0; size_t width = 0;
            switch (type[0]) {
                case 'B': case 'c': case 'C': width = 1; break;
                case 's': case 'S': width = 2; break;
                case 'i': case 'I': case 'l': case 'L': width = 4; break;
                case 'q': case 'Q': width = 8; break;
                default: break;
            }
            if (offset < 0 || !width || (size_t)offset + width > instanceSize) continue;
            const uint8_t *address = (const uint8_t *)(__bridge const void *)object + offset;
            memcpy(&scalar, address, width); values[key] = @(scalar);
        }
        free(ivars);
    }
    return values.count ? values : nil;
}

static NSString *HFALabelForControl(UIControl *control) {
    if ([control isKindOfClass:UIButton.class]) {
        NSString *title = [(UIButton *)control titleForState:UIControlStateNormal];
        if (title.length) return title;
    }
    if (control.accessibilityLabel.length) return control.accessibilityLabel;
    UIView *scope = control;
    for (NSUInteger depth = 0; scope && depth < 3; ++depth, scope = scope.superview) {
        NSMutableArray<UIView *> *queue = [NSMutableArray arrayWithObject:scope];
        for (NSUInteger i = 0; i < queue.count && i < 32; ++i) {
            UIView *view = queue[i];
            if ([view isKindOfClass:UILabel.class] && [(UILabel *)view text].length)
                return [(UILabel *)view text];
            for (UIView *child in view.subviews) if (queue.count < 32) [queue addObject:child];
        }
    }
    return nil;
}

static NSArray *HFACollectRoots(NSTimeInterval deadline) {
    NSMutableArray *roots = [NSMutableArray array], *queue = [NSMutableArray array];
    for (UIWindow *window in UIApplication.sharedApplication.windows) if (window) [queue addObject:window];
    NSHashTable *seen = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    while (queue.count && roots.count < kHFAMaxViews && [NSDate.date timeIntervalSince1970] <= deadline) {
        UIView *view = queue.firstObject; [queue removeObjectAtIndex:0];
        if ([seen containsObject:view]) continue; [seen addObject:view]; [roots addObject:view];
        for (UIView *child in view.subviews) if (queue.count + roots.count < kHFAMaxViews) [queue addObject:child];
    }
    return roots;
}

static NSArray<NSDictionary *> *HFAExecutableImages(void) {
    NSMutableArray *images = [NSMutableArray array];
    NSString *bundle = NSBundle.mainBundle.bundlePath.stringByStandardizingPath;
    for (uint32_t i = 0, n = MIN(_dyld_image_count(), 512U); i < n; ++i) {
        const char *raw = _dyld_get_image_name(i);
        const struct mach_header_64 *h = reinterpret_cast<const struct mach_header_64 *>(_dyld_get_image_header(i));
        if (!raw || !h || h->magic != MH_MAGIC_64) continue;
        NSString *path = [NSString stringWithUTF8String:raw];
        if (![path.stringByStandardizingPath hasPrefix:bundle]) continue;
        const uint8_t *p = (const uint8_t *)(h + 1), *end = p + h->sizeofcmds;
        for (uint32_t c = 0; c < h->ncmds && p + sizeof(struct load_command) <= end; ++c) {
            const struct load_command *lc = reinterpret_cast<const struct load_command *>(p);
            if (lc->cmdsize < sizeof(*lc) || p + lc->cmdsize > end) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = reinterpret_cast<const struct segment_command_64 *>(p);
                if ((seg->initprot & VM_PROT_EXECUTE) && seg->vmsize)
                    [images addObject:@{ @"image": path.lastPathComponent, @"path": path,
                                         @"vmaddr": @(seg->vmaddr), @"vmsize": @(seg->vmsize),
                                         @"slide": @(_dyld_get_image_vmaddr_slide(i)) }];
            }
            p += lc->cmdsize;
        }
    }
    return images;
}

static NSDictionary *HFAValidatedFeature(NSDictionary *source, NSString *fallbackLabel,
                                         NSArray<NSDictionary *> *execImages, NSString **reason) {
    id labelValue = HFAValueForAliases(source, @[@"label",@"title",@"name",@"identifier",@"displayname"]);
    NSString *label = [labelValue isKindOfClass:NSString.class] ? labelValue : fallbackLabel;
    NSNumber *offset = HFAOffsetValue(HFAValueForAliases(source, @[@"offset",@"patchoffset",@"targetoffset",@"address",@"rva"]));
    id patchValue = HFAValueForAliases(source, @[@"enabled",@"enabledbytes",@"patch",@"patchbytes",@"bytes",@"instruction"]);
    NSData *patch = HFABytesValue(patchValue);
    id declaredImageValue = HFAValueForAliases(source, @[@"image",@"targetimage",@"module",@"binary"]);
    NSString *declaredImage = [declaredImageValue isKindOfClass:NSString.class] ?
        [(NSString *)declaredImageValue lastPathComponent] : nil;
    if (!label.length) { if (reason) *reason = @"missing-label"; return nil; }
    if (!offset) { if (reason) *reason = @"missing-offset"; return nil; }
    if (!patch.length || patch.length > 256) { if (reason) *reason = @"missing-or-invalid-patch"; return nil; }
    NSMutableArray *matches = [NSMutableArray array]; uint64_t rva = offset.unsignedLongLongValue;
    for (NSDictionary *image in execImages) {
        if (declaredImage.length && ![declaredImage isEqualToString:image[@"image"]] &&
            ![declaredImage.stringByDeletingPathExtension
              isEqualToString:[image[@"image"] stringByDeletingPathExtension]]) continue;
        uint64_t vmaddr = [image[@"vmaddr"] unsignedLongLongValue], size = [image[@"vmsize"] unsignedLongLongValue];
        if (rva >= vmaddr && rva + patch.length <= vmaddr + size) [matches addObject:image];
    }
    if (matches.count != 1) { if (reason) *reason = matches.count ? @"ambiguous-target-image" : @"offset-outside-executable-range"; return nil; }
    NSDictionary *image = matches.firstObject;
    uintptr_t address = (uintptr_t)(rva + [image[@"slide"] longLongValue]);
    NSData *current = [NSData dataWithBytes:(const void *)address length:patch.length];
    id originalValue = HFAValueForAliases(source, @[@"original",@"originalbytes",@"disabled",@"disabledbytes"]);
    NSData *original = HFABytesValue(originalValue);
    NSString *(^hex)(NSData *) = ^NSString *(NSData *data) {
        const uint8_t *b = static_cast<const uint8_t *>(data.bytes);
        NSMutableString *s = [NSMutableString stringWithCapacity:data.length * 2];
        for (NSUInteger i=0;i<data.length;i++) [s appendFormat:@"%02X",b[i]]; return s;
    };
    NSMutableDictionary *result = [@{ @"name": label, @"offset": [NSString stringWithFormat:@"0x%llX", rva],
              @"patch": hex(patch), @"currentBytes": hex(current), @"targetImage": image[@"image"],
              @"offsetSemantics": @"preferred-mach-o-vmaddr",
              @"canonicalEligible": @YES, @"confidence": @"byte-validated",
              @"evidence": @[@"same-descriptor", @"executable-range", @"live-current-bytes"] } mutableCopy];
    if (original.length == patch.length) result[@"original"] = hex(original);
    return result;
}

NSDictionary *HFAMapCaptureFeatureSeeds(NSDictionary *candidate, NSTimeInterval deadline,
                                        NSMutableArray<NSDictionary *> *events) {
    HFAResolveEvent(events, @"snapshot-start", @{ @"image": candidate[@"image"] ?: @"" });
    NSArray *views = HFACollectRoots(deadline);
    NSHashTable *seenTargets = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSMutableArray *seeds = [NSMutableArray array];
    for (UIView *view in views) {
        if (NSDate.date.timeIntervalSince1970 > deadline) break;
        if (![view isKindOfClass:UIControl.class]) continue;
        UIControl *control = (UIControl *)view;
        NSString *label = HFALabelForControl(control);
        for (id target in control.allTargets) {
            if (seenTargets.count >= kHFAMaxTargets || [seenTargets containsObject:target]) continue;
            const char *ownerPath = class_getImageName(object_getClass(target));
            NSString *ownerImage = ownerPath ? [NSString stringWithUTF8String:ownerPath].lastPathComponent : @"";
            if (![ownerImage isEqualToString:candidate[@"image"]]) continue;
            [seenTargets addObject:target];
            [seeds addObject:@{ @"value": target, @"label": label ?: @"",
                                @"class": NSStringFromClass(object_getClass(target)) ?: @"?" }];
            HFADiagnosticsLog(@"ui-target", @"captured", @{
                @"label": label ?: @"", @"class": NSStringFromClass(object_getClass(target)) ?: @"?",
                @"image": ownerImage
            });
        }
    }
    NSString *status = NSDate.date.timeIntervalSince1970 > deadline ? @"timeout" : @"complete";
    NSDictionary *metrics = @{ @"views": @(views.count), @"targets": @(seenTargets.count),
                                @"seedCount": @(seeds.count), @"budgetMs": @350 };
    HFAResolveEvent(events, [@"snapshot-" stringByAppendingString:status], metrics);
    return @{ @"seeds": seeds, @"metrics": metrics, @"status": status };
}

NSDictionary *HFAMapResolveFeatureSeeds(NSDictionary *candidate, NSDictionary *snapshot,
                                        NSTimeInterval deadline,
                                        NSMutableArray<NSDictionary *> *events) {
    HFAResolveEvent(events, @"start", @{ @"image": candidate[@"image"] ?: @"" });
    NSArray *execImages = HFAExecutableImages();
    NSMutableArray *features = [NSMutableArray array], *unresolved = [NSMutableArray array];
    NSMutableSet *featureKeys = [NSMutableSet set], *unresolvedKeys = [NSMutableSet set];
    NSHashTable *seenContainers = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSMutableArray *containers = [NSMutableArray arrayWithArray:snapshot[@"seeds"] ?: @[]];
    for (NSUInteger cursor = 0; cursor < containers.count && cursor < kHFAMaxContainers; ++cursor) {
        if ([NSDate.date timeIntervalSince1970] > deadline) break;
        id object = containers[cursor][@"value"]; NSString *label = containers[cursor][@"label"];
        if ([seenContainers containsObject:object]) continue; [seenContainers addObject:object];
        NSDictionary *dictionary = HFADictionaryFromObject(object); if (!dictionary) continue;
        NSString *reason = nil; NSDictionary *feature = HFAValidatedFeature(dictionary, label, execImages, &reason);
        if (feature) {
            NSMutableDictionary *enriched = [feature mutableCopy];
            enriched[@"descriptorClass"] = NSStringFromClass(object_getClass(object)) ?: @"?";
            enriched[@"descriptorInstanceSize"] = @(class_getInstanceSize(object_getClass(object)));
            enriched[@"sourceFamily"] = candidate[@"family"] ?: @"unknown";
            feature = enriched;
            NSString *key = [NSString stringWithFormat:@"%@:%@:%@", feature[@"targetImage"], feature[@"offset"], feature[@"patch"]];
            if (![featureKeys containsObject:key]) {
                [featureKeys addObject:key]; [features addObject:feature];
                HFADiagnosticsLog(@"feature", @"accepted", feature);
            }
        } else if (label.length && HFADescriptorSignal(dictionary)) {
            NSString *className = NSStringFromClass(object_getClass(object)) ?: @"?";
            NSString *key = [NSString stringWithFormat:@"%@:%@:%@", label, reason ?: @"no-static-descriptor", className];
            if (![unresolvedKeys containsObject:key]) { [unresolvedKeys addObject:key];
                NSArray *fieldNames = [[dictionary.allKeys filteredArrayUsingPredicate:
                    [NSPredicate predicateWithBlock:^BOOL(id key, __unused NSDictionary *bindings) {
                        return [key isKindOfClass:NSString.class];
                    }]] sortedArrayUsingSelector:@selector(compare:)];
                NSDictionary *record = @{ @"name": label, @"reason": reason ?: @"no-static-descriptor",
                                           @"canonicalEligible": @NO, @"class": className,
                                           @"instanceSize": @(class_getInstanceSize(object_getClass(object))),
                                           @"fieldNames": [fieldNames subarrayWithRange:
                                               NSMakeRange(0, MIN(fieldNames.count, 64U))],
                                           @"sourceFamily": candidate[@"family"] ?: @"unknown" };
                [unresolved addObject:record];
                HFADiagnosticsLog(@"feature", @"rejected", record);
            }
        }
        for (id value in dictionary.allValues) {
            if (containers.count >= kHFAMaxContainers) break;
            if ([value isKindOfClass:NSArray.class]) {
                for (id item in [(NSArray *)value subarrayWithRange:NSMakeRange(0, MIN([value count], kHFAMaxItems))])
                    if ([item isKindOfClass:NSDictionary.class] || [item isKindOfClass:NSArray.class] ||
                        HFACandidateOwnedObject(item, candidate[@"image"]))
                        [containers addObject:@{ @"value": item, @"label": label ?: @"" }];
            } else if ([value isKindOfClass:NSDictionary.class]) {
                [containers addObject:@{ @"value": value, @"label": label ?: @"" }];
            } else if (![value isKindOfClass:NSString.class] && ![value isKindOfClass:NSNumber.class] &&
                       ![value isKindOfClass:NSData.class]) {
                if (HFACandidateOwnedObject(value, candidate[@"image"]))
                    [containers addObject:@{ @"value": value, @"label": label ?: @"" }];
            }
        }
    }
    NSString *status = [NSDate.date timeIntervalSince1970] > deadline ? @"timeout" : @"complete";
    NSDictionary *snapshotMetrics = snapshot[@"metrics"] ?: @{};
    HFAResolveEvent(events, status, @{ @"views": snapshotMetrics[@"views"] ?: @0,
                                      @"targets": snapshotMetrics[@"targets"] ?: @0,
                                      @"containers": @(MIN(containers.count,kHFAMaxContainers)),
                                      @"validated": @(features.count), @"unresolved": @(unresolved.count) });
    NSDictionary *metrics = @{ @"views": snapshotMetrics[@"views"] ?: @0,
                                @"targets": snapshotMetrics[@"targets"] ?: @0,
                                @"containers": @(MIN(containers.count,kHFAMaxContainers)),
                                @"executableSegments": @(execImages.count),
                                @"validated": @(features.count), @"unresolved": @(unresolved.count) };
    HFADiagnosticsLog(@"feature-resolution", status, metrics);
    return @{ @"status": status, @"features": features, @"unresolved": unresolved,
              @"metrics": metrics };
}

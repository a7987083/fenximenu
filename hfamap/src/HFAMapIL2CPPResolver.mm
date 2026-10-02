#import "HFAMapIL2CPPResolver.h"
#import <mach/mach.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef void HFAIl2CppDomain;
typedef void HFAIl2CppAssembly;
typedef void HFAIl2CppImage;
typedef void HFAIl2CppClass;
typedef void HFAIl2CppMethod;
typedef void HFAIl2CppType;

typedef HFAIl2CppDomain *(*HFA_il2cpp_domain_get_t)(void);
typedef const HFAIl2CppAssembly **(*HFA_il2cpp_domain_get_assemblies_t)(const HFAIl2CppDomain *, size_t *);
typedef const HFAIl2CppImage *(*HFA_il2cpp_assembly_get_image_t)(const HFAIl2CppAssembly *);
typedef const char *(*HFA_il2cpp_image_get_name_t)(const HFAIl2CppImage *);
typedef size_t (*HFA_il2cpp_image_get_class_count_t)(const HFAIl2CppImage *);
typedef HFAIl2CppClass *(*HFA_il2cpp_image_get_class_t)(const HFAIl2CppImage *, size_t);
typedef const char *(*HFA_il2cpp_class_get_name_t)(HFAIl2CppClass *);
typedef const char *(*HFA_il2cpp_class_get_namespace_t)(HFAIl2CppClass *);
typedef const HFAIl2CppMethod *(*HFA_il2cpp_class_get_methods_t)(HFAIl2CppClass *, void **);
typedef const char *(*HFA_il2cpp_method_get_name_t)(const HFAIl2CppMethod *);
typedef uint32_t (*HFA_il2cpp_method_get_param_count_t)(const HFAIl2CppMethod *);
typedef const HFAIl2CppType *(*HFA_il2cpp_method_get_param_t)(const HFAIl2CppMethod *, uint32_t);
typedef const HFAIl2CppType *(*HFA_il2cpp_method_get_return_type_t)(const HFAIl2CppMethod *);
typedef char *(*HFA_il2cpp_type_get_name_t)(const HFAIl2CppType *);
typedef void (*HFA_il2cpp_free_t)(void *);

typedef struct {
    HFA_il2cpp_domain_get_t domain_get;
    HFA_il2cpp_domain_get_assemblies_t domain_get_assemblies;
    HFA_il2cpp_assembly_get_image_t assembly_get_image;
    HFA_il2cpp_image_get_name_t image_get_name;
    HFA_il2cpp_image_get_class_count_t image_get_class_count;
    HFA_il2cpp_image_get_class_t image_get_class;
    HFA_il2cpp_class_get_name_t class_get_name;
    HFA_il2cpp_class_get_namespace_t class_get_namespace;
    HFA_il2cpp_class_get_methods_t class_get_methods;
    HFA_il2cpp_method_get_name_t method_get_name;
    HFA_il2cpp_method_get_param_count_t method_get_param_count;
    HFA_il2cpp_method_get_param_t method_get_param;
    HFA_il2cpp_method_get_return_type_t method_get_return_type;
    HFA_il2cpp_type_get_name_t type_get_name;
    HFA_il2cpp_free_t il2cpp_free;
} HFAIL2CPPAPI;

static void *HFASymbol(const char *name) { return dlsym(RTLD_DEFAULT, name); }

static BOOL HFALoadIL2CPPAPI(HFAIL2CPPAPI *api) {
    memset(api, 0, sizeof(*api));
#define HFA_LOAD(field, symbol) api->field = reinterpret_cast<decltype(api->field)>(HFASymbol(symbol))
    HFA_LOAD(domain_get, "il2cpp_domain_get");
    HFA_LOAD(domain_get_assemblies, "il2cpp_domain_get_assemblies");
    HFA_LOAD(assembly_get_image, "il2cpp_assembly_get_image");
    HFA_LOAD(image_get_name, "il2cpp_image_get_name");
    HFA_LOAD(image_get_class_count, "il2cpp_image_get_class_count");
    HFA_LOAD(image_get_class, "il2cpp_image_get_class");
    HFA_LOAD(class_get_name, "il2cpp_class_get_name");
    HFA_LOAD(class_get_namespace, "il2cpp_class_get_namespace");
    HFA_LOAD(class_get_methods, "il2cpp_class_get_methods");
    HFA_LOAD(method_get_name, "il2cpp_method_get_name");
    HFA_LOAD(method_get_param_count, "il2cpp_method_get_param_count");
    HFA_LOAD(method_get_param, "il2cpp_method_get_param");
    HFA_LOAD(method_get_return_type, "il2cpp_method_get_return_type");
    HFA_LOAD(type_get_name, "il2cpp_type_get_name");
    HFA_LOAD(il2cpp_free, "il2cpp_free");
#undef HFA_LOAD
    return api->domain_get && api->domain_get_assemblies && api->assembly_get_image &&
           api->image_get_name && api->image_get_class_count && api->image_get_class &&
           api->class_get_name && api->class_get_namespace && api->class_get_methods &&
           api->method_get_name && api->method_get_param_count && api->method_get_param &&
           api->method_get_return_type && api->type_get_name;
}

static NSString *HFAString(const char *text) {
    if (!text || !*text) return @"";
    NSString *value = [NSString stringWithUTF8String:text];
    return value ?: @"";
}

static BOOL HFAReadPointer(const void *base, uintptr_t *value) {
    if (!base || !value) return NO;
    mach_vm_size_t outSize = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)base,
                                               sizeof(uintptr_t),
                                               (mach_vm_address_t)value, &outSize);
    return kr == KERN_SUCCESS && outSize == sizeof(uintptr_t);
}

static NSDictionary *HFAExecutableImageForAddress(uintptr_t address, NSArray<NSDictionary *> *images) {
    for (NSDictionary *image in images) {
        uint64_t vmaddr = [image[@"vmaddr"] unsignedLongLongValue];
        int64_t slide = [image[@"slide"] longLongValue];
        uint64_t size = [image[@"vmsize"] unsignedLongLongValue];
        uintptr_t start = (uintptr_t)(vmaddr + slide);
        if (address >= start && address - start < size) return image;
    }
    return nil;
}

static NSNumber *HFARuntimeAddressForRecord(NSDictionary *record, NSArray<NSDictionary *> *images) {
    NSString *offsetText = [record[@"offset"] isKindOfClass:NSString.class] ? record[@"offset"] : nil;
    NSString *targetImage = [record[@"targetImage"] isKindOfClass:NSString.class] ? record[@"targetImage"] : nil;
    if (!offsetText.length || !targetImage.length) return nil;
    const char *raw = offsetText.UTF8String;
    if (!raw) return nil;
    char *end = NULL;
    unsigned long long preferred = strtoull(raw, &end, 0);
    if (!end || *end != '\0') return nil;
    for (NSDictionary *image in images) {
        NSString *name = image[@"image"];
        if (![name isEqualToString:targetImage] &&
            ![name.stringByDeletingPathExtension isEqualToString:targetImage.stringByDeletingPathExtension]) continue;
        uint64_t vmaddr = [image[@"vmaddr"] unsignedLongLongValue];
        uint64_t size = [image[@"vmsize"] unsignedLongLongValue];
        if (preferred < vmaddr || preferred - vmaddr >= size) continue;
        return @((uintptr_t)(preferred + [image[@"slide"] longLongValue]));
    }
    return nil;
}

static NSString *HFATypeName(const HFAIL2CPPAPI *api, const HFAIl2CppType *type) {
    if (!type) return @"?";
    char *raw = api->type_get_name(type);
    if (!raw) return @"?";
    NSString *name = HFAString(raw);
    if (api->il2cpp_free) api->il2cpp_free(raw);
    return name.length ? name : @"?";
}

static NSDictionary *HFAMethodRecord(const HFAIL2CPPAPI *api, const HFAIl2CppMethod *method,
                                     HFAIl2CppClass *klass, const HFAIl2CppImage *image,
                                     uintptr_t methodPointer, NSDictionary *pointerImage) {
    NSString *methodName = HFAString(api->method_get_name(method));
    NSString *className = HFAString(api->class_get_name(klass));
    NSString *namespaceName = HFAString(api->class_get_namespace(klass));
    NSString *assembly = HFAString(api->image_get_name(image));
    uint32_t count = api->method_get_param_count(method);
    NSMutableArray *params = [NSMutableArray arrayWithCapacity:MIN(count, 32U)];
    for (uint32_t i = 0; i < count && i < 32; ++i)
        [params addObject:HFATypeName(api, api->method_get_param(method, i))];
    NSString *returnType = HFATypeName(api, api->method_get_return_type(method));
    NSString *signature = [NSString stringWithFormat:@"%@ %@(%@)", returnType, methodName,
                             [params componentsJoinedByString:@", "]];
    uint64_t preferred = methodPointer - (uintptr_t)[pointerImage[@"slide"] longLongValue];
    return @{ @"image": assembly.length ? assembly : @"?",
              @"namespace": namespaceName ?: @"",
              @"class": className.length ? className : @"?",
              @"name": methodName.length ? methodName : @"?",
              @"returnType": returnType ?: @"?",
              @"parameters": params,
              @"signature": signature,
              @"methodInfo": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)method],
              @"methodPointer": [NSString stringWithFormat:@"0x%llX", (unsigned long long)methodPointer],
              @"preferredVMAddr": [NSString stringWithFormat:@"0x%llX", (unsigned long long)preferred],
              @"nativeImage": pointerImage[@"image"] ?: @"?",
              @"nativeUUID": pointerImage[@"uuid"] ?: @"unknown",
              @"match": @"exact-method-pointer",
              @"status": @"runtime_verified" };
}

NSDictionary *HFAMapResolveIL2CPPMethods(NSArray<NSDictionary *> *records,
                                         NSArray<NSDictionary *> *executableImages,
                                         NSTimeInterval deadline) {
    NSMutableDictionary<NSString *, NSMutableArray<NSNumber *> *> *targets = [NSMutableDictionary dictionary];
    for (NSUInteger i = 0; i < records.count; ++i) {
        NSNumber *address = HFARuntimeAddressForRecord(records[i], executableImages);
        if (!address) continue;
        NSString *key = [NSString stringWithFormat:@"0x%llX", address.unsignedLongLongValue];
        if (!targets[key]) targets[key] = [NSMutableArray array];
        [targets[key] addObject:@(i)];
    }
    if (!targets.count) return @{ @"status": @"no-targets", @"records": @[], @"resolvedCount": @0 };

    HFAIL2CPPAPI api;
    if (!HFALoadIL2CPPAPI(&api))
        return @{ @"status": @"il2cpp-exports-unavailable", @"records": @[],
                  @"targetCount": @(targets.count), @"resolvedCount": @0 };

    HFAIl2CppDomain *domain = api.domain_get();
    if (!domain) return @{ @"status": @"domain-unavailable", @"records": @[],
                           @"targetCount": @(targets.count), @"resolvedCount": @0 };
    size_t assemblyCount = 0;
    const HFAIl2CppAssembly **assemblies = api.domain_get_assemblies(domain, &assemblyCount);
    if (!assemblies || !assemblyCount)
        return @{ @"status": @"assemblies-unavailable", @"records": @[],
                  @"targetCount": @(targets.count), @"resolvedCount": @0 };

    NSMutableDictionary<NSString *, NSDictionary *> *resolvedByAddress = [NSMutableDictionary dictionary];
    NSUInteger classesVisited = 0, methodsVisited = 0;
    const NSUInteger kMaxClasses = 50000, kMaxMethods = 500000;
    for (size_t a = 0; a < assemblyCount && resolvedByAddress.count < targets.count; ++a) {
        if (NSDate.date.timeIntervalSince1970 > deadline) break;
        const HFAIl2CppImage *image = api.assembly_get_image(assemblies[a]);
        if (!image) continue;
        size_t classCount = api.image_get_class_count(image);
        for (size_t ci = 0; ci < classCount && classesVisited < kMaxClasses && resolvedByAddress.count < targets.count; ++ci) {
            if ((classesVisited & 0x7F) == 0 && NSDate.date.timeIntervalSince1970 > deadline) break;
            ++classesVisited;
            HFAIl2CppClass *klass = api.image_get_class(image, ci);
            if (!klass) continue;
            void *iter = NULL;
            const HFAIl2CppMethod *method = NULL;
            while ((method = api.class_get_methods(klass, &iter)) != NULL && methodsVisited < kMaxMethods) {
                ++methodsVisited;
                uintptr_t methodPointer = 0;
                if (!HFAReadPointer(method, &methodPointer) || !methodPointer) continue;
                NSString *key = [NSString stringWithFormat:@"0x%llX", (unsigned long long)methodPointer];
                if (!targets[key] || resolvedByAddress[key]) continue;
                NSDictionary *pointerImage = HFAExecutableImageForAddress(methodPointer, executableImages);
                if (!pointerImage) continue;
                resolvedByAddress[key] = HFAMethodRecord(&api, method, klass, image, methodPointer, pointerImage);
                if (resolvedByAddress.count >= targets.count) break;
            }
        }
    }

    NSMutableArray *output = [NSMutableArray arrayWithCapacity:records.count];
    NSUInteger resolvedCount = 0;
    for (NSDictionary *record in records) {
        NSMutableDictionary *copy = [record mutableCopy];
        NSNumber *address = HFARuntimeAddressForRecord(record, executableImages);
        NSString *key = address ? [NSString stringWithFormat:@"0x%llX", address.unsignedLongLongValue] : nil;
        NSDictionary *method = key ? resolvedByAddress[key] : nil;
        if (address) copy[@"runtimeAddress"] = key;
        if (method) {
            copy[@"method"] = method;
            copy[@"methodResolutionStatus"] = @"runtime_verified";
            ++resolvedCount;
        } else if (address) {
            copy[@"methodResolutionStatus"] = @"unresolved";
        }
        [output addObject:copy];
        [copy release];
    }
    NSString *status = NSDate.date.timeIntervalSince1970 > deadline ? @"timeout" : @"complete";
    return @{ @"status": status,
              @"resolver": @"il2cpp-export-api+exact-method-pointer",
              @"targetCount": @(targets.count),
              @"resolvedCount": @(resolvedCount),
              @"classesVisited": @(classesVisited),
              @"methodsVisited": @(methodsVisited),
              @"records": output,
              @"exactMatchOnly": @YES,
              @"methodInfoLayout": @"first-pointer-candidate-validated-by-executable-range-and-exact-target" };
}

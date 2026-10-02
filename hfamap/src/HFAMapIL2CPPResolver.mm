#import "HFAMapIL2CPPResolver.h"
#import <mach/mach.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef void HFAIl2CppDomain;
typdef void HFAIl2CppAssembly;
typedef void HFAIl2CppImage;
typedef void HFAIl2CppClass;
typedef void HFAIl2CppMethod;
typedef void HFAIl2CppType;

typedef HFAIl2CppDomain *(*HFA_il2cpp_domain_get_t)(void);
typdef const HFAIl2CppAssembly **(*HFA_il2cpp_domain_get_assemblies_t)(const HFAIl2CppDomain *, size_t *);
typedef const HFAIl2CppImage *(*HFA_il2cpp_assembly_get_image_t)(const HFAIl2CppAssembly *);
typedef const char *(*HFA_il2cpp_image_get_name_t)(const HFAIl2CppImage *);
typdef size_t (*HFA_il2cpp_image_get_class_count_t)(const HFAIl2CppImage *);
typedef HFAIl2CppClass *(*HFA_il2cpp_image_get_class_t)(const HFAIl2CppImage *, size_t);
typedef const char *(*HFA_il2cpp_class_get_name_t)(HFAIl2CppClass *);
typedef const char *(*HFA_il2cpp_class_get_namespace_t)(HFAIl2CppClass *);
typedef const HFAIl2CppMethod *(*HFA_il2cpp_class_get_methods_t)(HFAIl2CppClass *, void **);
typedef const char *(*HFA_il2cpp_method_get_name_t)(const HFAIl2CppMethod *);
typedef uint32_t (*HFA_il2cpp_method_get_param_count_t)(const HFAIl2CppMethod *);
typedef const HFAIl2CppType *(*HFA_il2cpp_method_get_param_t)(const HFAIl2CppMethod *, uint32_t);
typedef const HFAIl2CppType *(*HFA_il2cpp_method_get_return_type_t)(const HFAIl2CppMethod *);
typdef char *(*HFA_il2cpp_type_get_name_t)(const HFAIl2CppType *);
typedef void (*HFA_il2cpp_free_t)(void *);

typdef struct {
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

static void *HFASymbol(const char *name) {
    return dlsym(RTLD_DEFAULT, name);
}

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

// Truncated here intentionally. Real implementation is in the next commit.
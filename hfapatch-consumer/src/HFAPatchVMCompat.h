#pragma once

#include <mach/mach.h>
#include <mach/vm_map.h>

/*
 * The modern iPhoneOS SDK exposes the legacy vm_* MIG entry points in public
 * user headers while XNU implements those as wrappers over mach_vm_*.
 * Keep the consumer's internal 64-bit address model, but bridge explicitly to
 * the SDK-declared interfaces so compilation never relies on implicit symbols.
 */
static inline kern_return_t HFAPC_vm_read_overwrite64(vm_map_t map,
                                                       mach_vm_address_t address,
                                                       mach_vm_size_t size,
                                                       mach_vm_address_t data,
                                                       mach_vm_size_t *dataSizeOut) {
    vm_size_t actual = 0;
    kern_return_t kr = vm_read_overwrite(map,
                                         (vm_address_t)address,
                                         (vm_size_t)size,
                                         (vm_address_t)data,
                                         &actual);
    if (dataSizeOut) *dataSizeOut = (mach_vm_size_t)actual;
    return kr;
}

static inline kern_return_t HFAPC_vm_region64(vm_map_t map,
                                               mach_vm_address_t *address,
                                               mach_vm_size_t *size,
                                               vm_region_flavor_t flavor,
                                               vm_region_info_t info,
                                               mach_msg_type_number_t *count,
                                               mach_port_t *objectName) {
    if (!address || !size) return KERN_INVALID_ARGUMENT;
    vm_address_t legacyAddress = (vm_address_t)*address;
    vm_size_t legacySize = (vm_size_t)*size;
    kern_return_t kr = vm_region_64(map,
                                    &legacyAddress,
                                    &legacySize,
                                    flavor,
                                    info,
                                    count,
                                    objectName);
    *address = (mach_vm_address_t)legacyAddress;
    *size = (mach_vm_size_t)legacySize;
    return kr;
}

static inline kern_return_t HFAPC_vm_protect64(vm_map_t map,
                                                mach_vm_address_t address,
                                                mach_vm_size_t size,
                                                boolean_t setMaximum,
                                                vm_prot_t protection) {
    return vm_protect(map,
                      (vm_address_t)address,
                      (vm_size_t)size,
                      setMaximum,
                      protection);
}

static inline kern_return_t HFAPC_vm_write64(vm_map_t map,
                                              mach_vm_address_t address,
                                              vm_offset_t data,
                                              mach_msg_type_number_t size) {
    return vm_write(map,
                    (vm_address_t)address,
                    data,
                    size);
}

#define mach_vm_read_overwrite HFAPC_vm_read_overwrite64
#define mach_vm_region HFAPC_vm_region64
#define mach_vm_protect HFAPC_vm_protect64
#define mach_vm_write HFAPC_vm_write64

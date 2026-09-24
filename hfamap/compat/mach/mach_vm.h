#pragma once

// iPhoneOS SDK compatibility shim.
// Xcode 16.4 / iPhoneOS 18.5 deliberately marks the public SDK's
// <mach/mach_vm.h> as unsupported for iOS targets. HFAMap only needs a
// same-process, read-only memory copy, so map the narrow API surface used by
// the resolver onto the supported <mach/vm_map.h> interface.

#include <mach/mach.h>
#include <mach/vm_map.h>

typedef vm_address_t mach_vm_address_t;
typedef vm_size_t mach_vm_size_t;

static inline kern_return_t mach_vm_read_overwrite(task_t target_task,
                                                    mach_vm_address_t address,
                                                    mach_vm_size_t size,
                                                    mach_vm_address_t data,
                                                    mach_vm_size_t *outsize) {
    return vm_read_overwrite(target_task,
                             (vm_address_t)address,
                             (vm_size_t)size,
                             (vm_address_t)data,
                             (vm_size_t *)outsize);
}

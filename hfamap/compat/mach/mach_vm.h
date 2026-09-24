#pragma once

// iPhoneOS SDK compatibility shim.
// Xcode 16.4 / iPhoneOS 18.5 deliberately marks the SDK's public
// <mach/mach_vm.h> as unsupported for iOS targets. The ARM Mach headers still
// provide mach_vm_address_t / mach_vm_size_t; HFAMap only needs a same-process,
// read-only memory copy, so bridge the one used function to <mach/vm_map.h>.

#include <mach/mach.h>
#include <mach/vm_map.h>

static inline kern_return_t mach_vm_read_overwrite(task_t target_task,
                                                    mach_vm_address_t address,
                                                    mach_vm_size_t size,
                                                    mach_vm_address_t data,
                                                    mach_vm_size_t *outsize) {
    vm_size_t actual = 0;
    kern_return_t kr = vm_read_overwrite(target_task,
                                         (vm_address_t)address,
                                         (vm_size_t)size,
                                         (vm_address_t)data,
                                         &actual);
    if (outsize) *outsize = (mach_vm_size_t)actual;
    return kr;
}

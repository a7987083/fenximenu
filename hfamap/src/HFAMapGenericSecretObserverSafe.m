#import <Foundation/Foundation.h>
#include <stdio.h>

// HFAMap v2.4.3 crash hotfix.
//
// The first GenericSecretObserver implementation enumerated the entire ObjC
// runtime with objc_getClassList() shortly after process launch. On Swift-heavy
// apps this forces realization of classes whose Swift metadata may still be in
// the middle of initialization. Device crash reports from MeChat,
// ProDragon-mobile and Twitter all show the same path:
//   HFAMap injected image -> objc_getClassList -> realizeAllClasses ->
//   realizeClassMaybeSwiftMaybeRelock -> swift metadata -> PC=0.
//
// This safe shim intentionally performs NO global class enumeration, NO class
// realization, NO swizzle, NO dyld add-image callback and NO decrypt call.
// It preserves the v2.4.2 startup model while keeping an explicit runtime
// marker so the hotfix can be distinguished from the unsafe build.

static void HFAGSOSafeLog(void) {
    @autoreleasepool {
        NSString *path = [NSHomeDirectory()
            stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];
        FILE *f = fopen(path.fileSystemRepresentation, "a");
        if (!f) return;
        fprintf(f,
                "[SECRET-OBSERVER] version=2.4.3 mode=safe-disabled-global-scan "
                "objcGetClassList=0 dyldCallback=0 swizzle=0 decryptInvoke=0\n");
        fflush(f);
        fclose(f);
    }
}

__attribute__((constructor))
static void HFAGenericSecretObserverSafeInit(void) {
    // Logging only. No Objective-C runtime enumeration is allowed here.
    HFAGSOSafeLog();
}

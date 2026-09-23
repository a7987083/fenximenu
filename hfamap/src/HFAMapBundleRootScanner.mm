#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "HFAMapStaticCatalog.h"

static const NSUInteger kHFABundleScanMaxDepth = 12;
static const NSUInteger kHFABundleScanMaxFiles = 512;
static const NSUInteger kHFABundlePickerMaxItems = 128;

static UIViewController *HFABundleTopController(void) {
    UIApplication *app = UIApplication.sharedApplication;
    UIWindow *window = nil;
    for (UIWindow *candidate in app.windows) {
        if (candidate.isKeyWindow && !candidate.hidden && candidate.alpha > 0.0) {
            window = candidate;
            break;
        }
    }
    if (!window) window = app.keyWindow ?: app.windows.lastObject;
    UIViewController *controller = window.rootViewController;
    while (controller.presentedViewController) controller = controller.presentedViewController;
    if ([controller isKindOfClass:UINavigationController.class])
        controller = [(UINavigationController *)controller topViewController];
    if ([controller isKindOfClass:UITabBarController.class])
        controller = [(UITabBarController *)controller selectedViewController];
    return controller;
}

static void HFAAppendDylibsFromRoot(NSString *root,
                                    NSString *rootLabel,
                                    NSMutableArray<NSDictionary *> *results,
                                    NSMutableSet<NSString *> *seen) {
    if (!root.length || results.count >= kHFABundleScanMaxFiles) return;
    NSURL *rootURL = [NSURL fileURLWithPath:root isDirectory:YES];
    NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager]
        enumeratorAtURL:rootURL
        includingPropertiesForKeys:@[NSURLIsRegularFileKey, NSURLFileSizeKey, NSURLIsSymbolicLinkKey]
        options:NSDirectoryEnumerationSkipsHiddenFiles
        errorHandler:^BOOL(__unused NSURL *url, __unused NSError *error) { return YES; }];

    for (NSURL *url in enumerator) {
        if (results.count >= kHFABundleScanMaxFiles) break;
        NSString *path = url.path ?: @"";
        if (!path.length || path.length <= root.length) continue;
        NSString *relative = [path substringFromIndex:MIN(root.length + 1, path.length)];
        NSUInteger depth = relative.pathComponents.count;
        if (depth > kHFABundleScanMaxDepth) {
            [enumerator skipDescendants];
            continue;
        }

        NSNumber *regular = nil;
        NSNumber *symlink = nil;
        NSNumber *size = nil;
        [url getResourceValue:&regular forKey:NSURLIsRegularFileKey error:nil];
        [url getResourceValue:&symlink forKey:NSURLIsSymbolicLinkKey error:nil];
        if (![regular boolValue] || [symlink boolValue]) continue;
        if (![url.pathExtension.lowercaseString isEqualToString:@"dylib"]) continue;
        if ([seen containsObject:path]) continue;
        [url getResourceValue:&size forKey:NSURLFileSizeKey error:nil];
        [seen addObject:path];
        [results addObject:@{
            @"name": url.lastPathComponent ?: @"?",
            @"path": path,
            @"relativePath": relative ?: @"",
            @"size": size ?: @0,
            @"root": root ?: @"",
            @"rootLabel": rootLabel ?: @"ROOT",
            @"depth": @(depth)
        }];
    }
}

static NSArray<NSDictionary *> *HFADeepBundleDylibInventory(void) {
    NSMutableArray<NSDictionary *> *results = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];

    NSString *bundleRoot = NSBundle.mainBundle.bundlePath;
    HFAAppendDylibsFromRoot(bundleRoot, @"APP", results, seen);

    NSString *dataRoot = NSHomeDirectory();
    if (dataRoot.length && ![dataRoot isEqualToString:bundleRoot])
        HFAAppendDylibsFromRoot(dataRoot, @"DATA", results, seen);

    [results sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSString *la = a[@"rootLabel"] ?: @"";
        NSString *lb = b[@"rootLabel"] ?: @"";
        if (![la isEqualToString:lb]) {
            if ([la isEqualToString:@"APP"]) return NSOrderedAscending;
            if ([lb isEqualToString:@"APP"]) return NSOrderedDescending;
        }
        NSUInteger da = [a[@"depth"] unsignedIntegerValue];
        NSUInteger db = [b[@"depth"] unsignedIntegerValue];
        if (da < db) return NSOrderedAscending;
        if (da > db) return NSOrderedDescending;
        return [(a[@"relativePath"] ?: @"") compare:(b[@"relativePath"] ?: @"")
                                              options:NSCaseInsensitiveSearch];
    }];
    return results;
}

static void HFAPresentStaticAnalysisResult(UIViewController *controller,
                                           NSDictionary *catalog,
                                           NSError *error) {
    NSString *message = nil;
    if (catalog) {
        message = [NSString stringWithFormat:@"Catalog READY ✅\n%@\n%@ runtime methods\nSame-session loaded",
                   catalog[@"source"][@"fileName"] ?: @"dylib",
                   catalog[@"runtimeMethodCount"] ?: @0];
    } else {
        message = [NSString stringWithFormat:@"Static analysis failed\n%@",
                   error.localizedDescription ?: @"unknown error"];
    }
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"HFAMap v2.5.4"
                                                                    message:message
                                                             preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [controller presentViewController:alert animated:YES completion:nil];
}

static void HFAStaticAnalyzeBundleRootReplacement(__unused id self, __unused SEL _cmd) {
    UIViewController *controller = HFABundleTopController();
    if (!controller) return;

    UIAlertController *scanning = [UIAlertController alertControllerWithTitle:@"Static Analyze Dylib"
        message:@"Deep scanning .app Bundle root…"
        preferredStyle:UIAlertControllerStyleAlert];
    [controller presentViewController:scanning animated:YES completion:nil];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSArray<NSDictionary *> *files = HFADeepBundleDylibInventory();
        dispatch_async(dispatch_get_main_queue(), ^{
            [scanning dismissViewControllerAnimated:NO completion:^{
                UIViewController *top = HFABundleTopController();
                if (!top) return;
                if (!files.count) {
                    UIAlertController *empty = [UIAlertController alertControllerWithTitle:@"Static Analyze Dylib"
                        message:@"No .dylib found under APP Bundle or DATA container."
                        preferredStyle:UIAlertControllerStyleAlert];
                    [empty addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                    [top presentViewController:empty animated:YES completion:nil];
                    return;
                }

                // Compact picker: no title/message header. Each item already carries [APP]/[DATA].
                // This avoids wasting a large block of vertical space above the dylib list.
                UIAlertController *picker = [UIAlertController alertControllerWithTitle:nil
                    message:nil preferredStyle:UIAlertControllerStyleActionSheet];
                NSUInteger limit = MIN(files.count, kHFABundlePickerMaxItems);
                for (NSUInteger i = 0; i < limit; ++i) {
                    NSDictionary *entry = files[i];
                    NSString *title = [NSString stringWithFormat:@"[%@] %@",
                                       entry[@"rootLabel"] ?: @"?",
                                       entry[@"relativePath"] ?: entry[@"name"] ?: @"dylib"];
                    [picker addAction:[UIAlertAction actionWithTitle:title
                                                                  style:UIAlertActionStyleDefault
                                                                handler:^(__unused UIAlertAction *action) {
                        NSString *path = entry[@"path"];
                        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                            NSError *analysisError = nil;
                            NSDictionary *catalog = HFAMapStaticCatalogAnalyzeFile(path, &analysisError);
                            NSError *persistError = nil;
                            BOOL registered = catalog && HFAMapStaticCatalogRegisterAndPersist(catalog, &persistError);
                            NSError *finalError = analysisError ?: persistError;
                            dispatch_async(dispatch_get_main_queue(), ^{
                                HFAPresentStaticAnalysisResult(HFABundleTopController(),
                                                               registered ? catalog : nil,
                                                               finalError);
                            });
                        });
                    }]];
                }
                [picker addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
                UIPopoverPresentationController *popover = picker.popoverPresentationController;
                if (popover) {
                    popover.sourceView = top.view;
                    popover.sourceRect = CGRectMake(CGRectGetMidX(top.view.bounds), CGRectGetMidY(top.view.bounds), 1, 1);
                    popover.permittedArrowDirections = 0;
                }
                [top presentViewController:picker animated:YES completion:nil];
            }];
        });
    });
}

static void HFAInstallBundleRootScannerOverride(void) {
    Class cls = NSClassFromString(@"HFAMapFloatingTarget");
    if (!cls) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ HFAInstallBundleRootScannerOverride(); });
        return;
    }
    Method method = class_getInstanceMethod(cls, @selector(staticAnalyze));
    if (!method) return;
    method_setImplementation(method, (IMP)HFAStaticAnalyzeBundleRootReplacement);
    NSLog(@"[HFAMap] v2.5.4 APP Bundle deep scanner installed root=%@ depth=%lu maxFiles=%lu",
          NSBundle.mainBundle.bundlePath,
          (unsigned long)kHFABundleScanMaxDepth,
          (unsigned long)kHFABundleScanMaxFiles);
}

__attribute__((constructor))
static void HFABundleRootScannerConstructor(void) {
    dispatch_async(dispatch_get_main_queue(), ^{ HFAInstallBundleRootScannerOverride(); });
}

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "HFAMapCore.h"
#import "HFAMapOutputName.h"
#import "HFAMapStaticCatalog.h"

static UIView *gHFAMapPanel = nil;
static UIButton *gHFAMapButton = nil;
static UILabel *gHFAMapStatus = nil;

static UIWindow *HFAMapFindWindow(void)
{
    UIApplication *app = UIApplication.sharedApplication;
    for (UIWindow *window in app.windows)
        if (window.isKeyWindow && !window.hidden && window.alpha > 0.0) return window;
    for (UIWindow *window in [app.windows reverseObjectEnumerator])
        if (!window.hidden && window.alpha > 0.0 && window.windowLevel == UIWindowLevelNormal) return window;
    return app.keyWindow;
}

static UIViewController *HFAMapTopController(void)
{
    UIWindow *window = HFAMapFindWindow();
    UIViewController *controller = window.rootViewController;
    while (controller.presentedViewController) controller = controller.presentedViewController;
    if ([controller isKindOfClass:UINavigationController.class]) controller = [(UINavigationController *)controller topViewController];
    if ([controller isKindOfClass:UITabBarController.class]) controller = [(UITabBarController *)controller selectedViewController];
    return controller;
}

// UI-only file picker scope. Static analysis itself remains pure file parsing in HFAMapStaticCatalog.
// Start at the app data-container root so a user can drop a dylib at the root, Documents, Library,
// or another ordinary sandbox subdirectory without moving it specifically into Documents.
static NSArray<NSDictionary *> *HFAMapListSandboxRootDylibs(void)
{
    NSString *root = NSHomeDirectory();
    if (!root.length) return @[];
    static const NSUInteger kMaxFiles = 128;
    static const NSUInteger kMaxDepth = 4;
    NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:root]
        includingPropertiesForKeys:@[NSURLIsRegularFileKey, NSURLFileSizeKey]
        options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:^BOOL(__unused NSURL *url, __unused NSError *error) { return YES; }];
    NSMutableArray *results = [NSMutableArray array];
    for (NSURL *url in enumerator) {
        if (results.count >= kMaxFiles) break;
        NSString *relative = [url.path substringFromIndex:MIN(root.length + 1, url.path.length)];
        if (relative.pathComponents.count > kMaxDepth + 1) { [enumerator skipDescendants]; continue; }
        NSNumber *regular = nil, *size = nil;
        [url getResourceValue:&regular forKey:NSURLIsRegularFileKey error:nil];
        if (![regular boolValue] || ![url.pathExtension.lowercaseString isEqualToString:@"dylib"]) continue;
        [url getResourceValue:&size forKey:NSURLFileSizeKey error:nil];
        [results addObject:@{ @"name": url.lastPathComponent ?: @"?",
                              @"path": url.path ?: @"",
                              @"relativePath": relative ?: @"",
                              @"size": size ?: @0,
                              @"enumerationRoot": @"NSHomeDirectory" }];
    }
    [results sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"relativePath"] compare:b[@"relativePath"] options:NSCaseInsensitiveSearch];
    }];
    return results;
}

static void HFAMapTogglePanel(void)
{
    if (gHFAMapPanel) gHFAMapPanel.hidden = !gHFAMapPanel.hidden;
}

@interface HFAMapFloatingTarget : NSObject
+ (instancetype)shared;
- (void)toggle;
- (void)discover;
- (void)analyze;
- (void)probe;
- (void)staticAnalyze;
@end

@implementation HFAMapFloatingTarget
+ (instancetype)shared
{
    static HFAMapFloatingTarget *obj;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ obj = [HFAMapFloatingTarget new]; });
    return obj;
}
- (void)toggle { HFAMapTogglePanel(); }

- (void)discover
{
    gHFAMapStatus.text = @"Searching all app-owned loaded images…";
    HFAMapRunMenuDiscovery(^(NSDictionary *summary) {
        NSDictionary *selected = summary[@"selected"];
        NSString *reason = summary[@"reason"];
        if ([summary[@"status"] isEqualToString:@"selected"] && [selected isKindOfClass:NSDictionary.class]) {
            gHFAMapStatus.text = [NSString stringWithFormat:@"Found: %@\nScore %@ · %@ candidates\nNext: Deep Analyze Menu",
                                  selected[@"image"] ?: @"?", selected[@"score"] ?: @0,
                                  summary[@"candidateCount"] ?: @0];
        } else {
            gHFAMapStatus.text = [NSString stringWithFormat:@"Discovery incomplete: %@\nSee %@",
                                  reason.length ? reason : @"no candidate", HFAOutputFileName(@"Discovery.json")];
        }
    });
}

- (void)analyze
{
    gHFAMapStatus.text = @"Analyzing feature ownership + static catalog…";
    HFAMapRunSelectedDeepAnalysis(^(NSDictionary *summary) {
        NSString *status = summary[@"status"] ?: @"?";
        if ([status isEqualToString:@"no-selected-menu"]) {
            gHFAMapStatus.text = @"No selected menu. Run Search Menu first.";
            return;
        }
        NSDictionary *graph = summary[@"featureHandlerGraph"] ?: @{};
        gHFAMapStatus.text = [NSString stringWithFormat:
            @"Analysis %@ — %@ handlers matched\n%@ static runtime methods",
            status,
            graph[@"staticCatalogMatchedBlockCount"] ?: @0,
            graph[@"staticCatalogMatchedRuntimeMethodCount"] ?: @0];
    });
}

- (void)probe
{
    if (HFAMapRuntimeProbeIsActive()) {
        gHFAMapStatus.text = @"Stopping runtime probe…";
        HFAMapStopActiveRuntimeProbe(@"manual-stop");
        return;
    }
    gHFAMapStatus.text = HFAMapStaticCatalogCurrent()
        ? @"Runtime Probe armed for 8s.\nStatic Catalog: loaded ✅"
        : @"Runtime Probe armed for 8s.\nStatic Catalog: none";
    HFAMapArmLastSelectedRuntimeProbe(^(NSDictionary *summary) {
        NSString *status = summary[@"status"] ?: @"?";
        if ([status isEqualToString:@"no-selected-menu"]) {
            gHFAMapStatus.text = @"No selected menu. Run Search Menu first.";
            return;
        }
        if ([status isEqualToString:@"complete"] || [summary[@"featureDirectedAnalysisCount"] unsignedIntegerValue] > 0)
            gHFAMapStatus.text = [NSString stringWithFormat:@"Probe done — %@ events\n%@ method links",
                                  summary[@"eventCount"] ?: @0,
                                  summary[@"featureDirectedCorrelationCount"] ?: @0];
        else
            gHFAMapStatus.text = [NSString stringWithFormat:@"Probe stopped: %@", status];
    });
}

- (void)staticAnalyze
{
    NSArray<NSDictionary *> *files = HFAMapListSandboxRootDylibs();
    if (!files.count) {
        gHFAMapStatus.text = @"No .dylib found under game root.";
        return;
    }
    UIViewController *controller = HFAMapTopController();
    if (!controller) {
        gHFAMapStatus.text = @"Unable to present dylib picker.";
        return;
    }

    UIAlertController *picker = [UIAlertController alertControllerWithTitle:@"Static Analyze Dylib"
        message:@"Scanning game root. Read-only file analysis; selected dylib is NOT loaded or executed."
        preferredStyle:UIAlertControllerStyleActionSheet];
    NSUInteger limit = MIN(files.count, 32U);
    for (NSUInteger i = 0; i < limit; ++i) {
        NSDictionary *entry = files[i];
        NSString *title = entry[@"relativePath"] ?: entry[@"name"] ?: @"dylib";
        [picker addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
            NSString *path = entry[@"path"];
            gHFAMapStatus.text = [NSString stringWithFormat:@"Static analyzing %@…", entry[@"name"] ?: @"dylib"];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                NSError *analysisError = nil;
                NSDictionary *catalog = HFAMapStaticCatalogAnalyzeFile(path, &analysisError);
                NSError *persistError = nil;
                BOOL registered = catalog && HFAMapStaticCatalogRegisterAndPersist(catalog, &persistError);
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (!registered) {
                        NSError *error = analysisError ?: persistError;
                        gHFAMapStatus.text = [NSString stringWithFormat:@"Static analysis failed:\n%@",
                                              error.localizedDescription ?: @"unknown error"];
                        return;
                    }
                    gHFAMapStatus.text = [NSString stringWithFormat:
                        @"Catalog READY ✅ %@\n%@ methods · same-session loaded",
                        catalog[@"source"][@"fileName"] ?: @"dylib",
                        catalog[@"runtimeMethodCount"] ?: @0];
                });
            });
        }]];
    }
    if (files.count > limit)
        picker.message = [picker.message stringByAppendingFormat:@"\nShowing first %lu of %lu files.",
                          (unsigned long)limit, (unsigned long)files.count];
    [picker addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    if (picker.popoverPresentationController) {
        picker.popoverPresentationController.sourceView = gHFAMapPanel ?: controller.view;
        picker.popoverPresentationController.sourceRect = gHFAMapPanel ? gHFAMapPanel.bounds : controller.view.bounds;
    }
    [controller presentViewController:picker animated:YES completion:nil];
}
@end

static UIButton *HFAMakeActionButton(CGRect frame, NSString *title, SEL action)
{
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.frame = frame;
    button.backgroundColor = [UIColor colorWithWhite:0.18 alpha:1.0];
    button.layer.cornerRadius = 8.0;
    [button setTitle:title forState:UIControlStateNormal];
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [button addTarget:[HFAMapFloatingTarget shared] action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}

static BOOL HFAMapInstallFloatingUI(void)
{
    if (gHFAMapButton.superview) return YES;
    UIWindow *window = HFAMapFindWindow();
    if (!window) return NO;

    CGFloat y = MAX(80.0, window.safeAreaInsets.top + 36.0);
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.frame = CGRectMake(18.0, y, 56.0, 56.0);
    button.layer.cornerRadius = 28.0;
    button.layer.masksToBounds = YES;
    button.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.92];
    [button setTitle:@"HFA" forState:UIControlStateNormal];
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:15.0];
    button.layer.borderWidth = 1.0;
    button.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.35].CGColor;
    [button addTarget:[HFAMapFloatingTarget shared] action:@selector(toggle)
      forControlEvents:UIControlEventTouchUpInside];

    UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(84.0, y, 264.0, 354.0)];
    panel.backgroundColor = [UIColor colorWithWhite:0.06 alpha:0.94];
    panel.layer.cornerRadius = 12.0;
    panel.layer.borderWidth = 1.0;
    panel.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.22].CGColor;
    panel.hidden = YES;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(14.0, 10.0, 236.0, 28.0)];
    title.text = @"HFAMap v2.5.3-dev Static Catalog";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:16.0];
    [panel addSubview:title];

    UIButton *discover = HFAMakeActionButton(CGRectMake(14.0, 46.0, 236.0, 42.0),
                                              @"1. Search Menu", @selector(discover));
    discover.backgroundColor = [UIColor colorWithRed:0.15 green:0.34 blue:0.70 alpha:1.0];
    [panel addSubview:discover];

    UIButton *analyze = HFAMakeActionButton(CGRectMake(14.0, 96.0, 236.0, 42.0),
                                             @"2. Deep Analyze Menu", @selector(analyze));
    analyze.backgroundColor = [UIColor colorWithRed:0.16 green:0.48 blue:0.42 alpha:1.0];
    [panel addSubview:analyze];

    UIButton *probe = HFAMakeActionButton(CGRectMake(14.0, 146.0, 236.0, 42.0),
                                           @"3. Runtime Probe (8s)", @selector(probe));
    probe.backgroundColor = [UIColor colorWithRed:0.46 green:0.24 blue:0.66 alpha:1.0];
    [panel addSubview:probe];

    UIButton *staticAnalyze = HFAMakeActionButton(CGRectMake(14.0, 196.0, 236.0, 42.0),
                                                   @"4. Static Analyze Dylib", @selector(staticAnalyze));
    staticAnalyze.backgroundColor = [UIColor colorWithRed:0.56 green:0.34 blue:0.16 alpha:1.0];
    [panel addSubview:staticAnalyze];

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(14.0, 246.0, 236.0, 94.0)];
    status.text = @"4 Static = game root dylib → Catalog\nCatalog is registered immediately\n2/3 reuse it in the same game session";
    status.numberOfLines = 5;
    status.textColor = [UIColor colorWithWhite:0.88 alpha:1.0];
    status.font = [UIFont systemFontOfSize:12.5];
    [panel addSubview:status];
    gHFAMapStatus = status;

    [window addSubview:panel];
    [window addSubview:button];
    [window bringSubviewToFront:panel];
    [window bringSubviewToFront:button];
    gHFAMapPanel = panel;
    gHFAMapButton = button;
    NSLog(@"[HFAMap] v2.5.3 offline static catalog UI installed on window=%@", window);
    return YES;
}

static void HFAMapScheduleInstall(NSUInteger attempt)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (HFAMapInstallFloatingUI()) return;
        if (attempt >= 20) return;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ HFAMapScheduleInstall(attempt + 1); });
    });
}

__attribute__((constructor))
static void HFAMapConstructor(void)
{
    @autoreleasepool {
        NSLog(@"[HFAMap] Theos build entry loaded");
        HFAMapScheduleInstall(0);
    }
}

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "HFAMapCore.h"
#import "HFAMapOutputName.h"
#import "HFAMapTargetedSecretProbe.h"

static UIView *gHFAMapPanel = nil;
static UIButton *gHFAMapButton = nil;
static UILabel *gHFAMapStatus = nil;

static UIWindow *HFAMapFindWindow(void)
{
    UIApplication *app = UIApplication.sharedApplication;

    for (UIWindow *window in app.windows) {
        if (window.isKeyWindow && !window.hidden && window.alpha > 0.0) {
            return window;
        }
    }

    for (UIWindow *window in [app.windows reverseObjectEnumerator]) {
        if (!window.hidden && window.alpha > 0.0 && window.windowLevel == UIWindowLevelNormal) {
            return window;
        }
    }

    return app.keyWindow;
}

static void HFAMapTogglePanel(void)
{
    if (!gHFAMapPanel) return;
    gHFAMapPanel.hidden = !gHFAMapPanel.hidden;
}

@interface HFAMapFloatingTarget : NSObject
+ (instancetype)shared;
- (void)toggle;
- (void)scan;
- (void)probe;
@end

@implementation HFAMapFloatingTarget
+ (instancetype)shared
{
    static HFAMapFloatingTarget *obj;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ obj = [HFAMapFloatingTarget new]; });
    return obj;
}
- (void)toggle
{
    HFAMapTogglePanel();
}
- (void)scan
{
    gHFAMapStatus.text = @"Scanning loaded images…";
    HFAMapRunBoundedScan(^(NSDictionary *summary) {
        NSString *status = summary[@"status"] ?: @"?";
        NSArray *features = summary[@"features"] ?: @[];
        NSArray *registry = summary[@"registry"] ?: @[];
        NSArray *unresolved = summary[@"unresolved"] ?: @[];
        NSString *reason = summary[@"reason"];
        if (reason.length)
            gHFAMapStatus.text = [NSString stringWithFormat:@"Stopped: %@\nSee %@", reason, HFAOutputFileName(@"Analysis.json")];
        else
            gHFAMapStatus.text = [NSString stringWithFormat:@"%@ — %lu registry, %lu validated, %lu unresolved\nRead-only JSON and logs exported",
                                  status, (unsigned long)registry.count, (unsigned long)features.count,
                                  (unsigned long)unresolved.count];
    });
}
- (void)probe
{
    if (HFAMapRuntimeProbeIsActive() || HFAMapTargetedSecretProbeIsActive()) {
        gHFAMapStatus.text = @"Stopping runtime probes…";
        HFAMapStopTargetedSecretProbe(@"manual-stop");
        HFAMapStopActiveRuntimeProbe(@"manual-stop");
        return;
    }

    NSDictionary *targeted = HFAMapArmTargetedSecretProbe(nil, 8.0);
    NSNumber *installed = targeted[@"installed"] ?: @0;
    NSString *targetImage = targeted[@"image"] ?: @"no unique menu image";
    gHFAMapStatus.text = [NSString stringWithFormat:
        @"Runtime probes armed for 8s.\nTarget: %@ — %@ secret hook(s).\nTap one original menu control.",
        targetImage, installed];

    HFAMapArmLastSelectedRuntimeProbe(^(NSDictionary *summary) {
        NSString *status = summary[@"status"] ?: @"?";
        if ([status isEqualToString:@"complete"])
            gHFAMapStatus.text = [NSString stringWithFormat:
                @"Probe complete — %@ events.\nSee %@ + HFAMap_Learn.log",
                summary[@"eventCount"] ?: @0, HFAOutputFileName(@"RuntimeProbe.json")];
        else
            gHFAMapStatus.text = [NSString stringWithFormat:@"Probe stopped: %@", status];
    });
}
@end

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
    [button addTarget:[HFAMapFloatingTarget shared]
               action:@selector(toggle)
     forControlEvents:UIControlEventTouchUpInside];

    UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(84.0, y, 250.0, 264.0)];
    panel.backgroundColor = [UIColor colorWithWhite:0.06 alpha:0.94];
    panel.layer.cornerRadius = 12.0;
    panel.layer.borderWidth = 1.0;
    panel.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.22].CGColor;
    panel.hidden = YES;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(14.0, 12.0, 222.0, 26.0)];
    title.text = @"HFAMap v2.4.3-dev Verify Architecture";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:17.0];
    [panel addSubview:title];

    UIButton *scan = [UIButton buttonWithType:UIButtonTypeSystem];
    scan.frame = CGRectMake(14.0, 46.0, 222.0, 42.0);
    scan.backgroundColor = [UIColor colorWithRed:0.15 green:0.34 blue:0.70 alpha:1.0];
    scan.layer.cornerRadius = 8.0;
    [scan setTitle:@"Scan Menu (5s budget)" forState:UIControlStateNormal];
    [scan setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [scan addTarget:[HFAMapFloatingTarget shared] action:@selector(scan)
      forControlEvents:UIControlEventTouchUpInside];
    [panel addSubview:scan];

    UIButton *probe = [UIButton buttonWithType:UIButtonTypeSystem];
    probe.frame = CGRectMake(14.0, 96.0, 222.0, 42.0);
    probe.backgroundColor = [UIColor colorWithRed:0.46 green:0.24 blue:0.66 alpha:1.0];
    probe.layer.cornerRadius = 8.0;
    [probe setTitle:@"Arm Targeted Runtime Probe (8s)" forState:UIControlStateNormal];
    [probe setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [probe addTarget:[HFAMapFloatingTarget shared] action:@selector(probe)
      forControlEvents:UIControlEventTouchUpInside];
    [panel addSubview:probe];

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(14.0, 146.0, 222.0, 104.0)];
    status.text = @"Open original menu, then scan.\nRuntime probe is explicit and temporary.\nIt only inspects the selected menu image;\nno process-wide Objective-C class scan.";
    status.numberOfLines = 5;
    status.textColor = [UIColor colorWithWhite:0.88 alpha:1.0];
    status.font = [UIFont systemFontOfSize:13.0];
    [panel addSubview:status];
    gHFAMapStatus = status;

    [window addSubview:panel];
    [window addSubview:button];
    [window bringSubviewToFront:panel];
    [window bringSubviewToFront:button];

    gHFAMapPanel = panel;
    gHFAMapButton = button;

    NSLog(@"[HFAMap] floating UI installed on window=%@", window);
    return YES;
}

static void HFAMapScheduleInstall(NSUInteger attempt)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (HFAMapInstallFloatingUI()) return;
        if (attempt >= 20) {
            NSLog(@"[HFAMap] floating UI install failed: no usable UIWindow");
            return;
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            HFAMapScheduleInstall(attempt + 1);
        });
    });
}

static void HFAMapInitialize(void)
{
    NSLog(@"[HFAMap] v2.4.3 Verify Architecture entry loaded");
    HFAMapScheduleInstall(0);
}

__attribute__((constructor))
static void HFAMapConstructor(void)
{
    @autoreleasepool {
        HFAMapInitialize();
    }
}

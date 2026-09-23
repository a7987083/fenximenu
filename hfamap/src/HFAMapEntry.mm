#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "HFAMapCore.h"
#import "HFAMapOutputName.h"

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
    gHFAMapStatus.text = @"Analyzing selected menu + feature handlers…";
    HFAMapRunSelectedDeepAnalysis(^(NSDictionary *summary) {
        NSString *status = summary[@"status"] ?: @"?";
        if ([status isEqualToString:@"no-selected-menu"]) {
            gHFAMapStatus.text = @"No selected menu. Run Search Menu first.";
            return;
        }
        NSArray *features = summary[@"features"] ?: @[];
        NSArray *registry = summary[@"registry"] ?: @[];
        NSArray *unresolved = summary[@"unresolved"] ?: @[];
        NSDictionary *graph = summary[@"featureHandlerGraph"] ?: @{};
        gHFAMapStatus.text = [NSString stringWithFormat:@"Analysis %@ — %lu registry\n%lu validated · %lu method candidates",
                              status, (unsigned long)registry.count, (unsigned long)features.count,
                              (unsigned long)[graph[@"runtimeMethodCandidateCount"] unsignedIntegerValue]];
    });
}

- (void)probe
{
    if (HFAMapRuntimeProbeIsActive()) {
        gHFAMapStatus.text = @"Stopping runtime probe…";
        HFAMapStopActiveRuntimeProbe(@"manual-stop");
        return;
    }
    gHFAMapStatus.text = @"Runtime Probe armed for 8s.\nTap one original menu control.";
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

    UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(84.0, y, 264.0, 304.0)];
    panel.backgroundColor = [UIColor colorWithWhite:0.06 alpha:0.94];
    panel.layer.cornerRadius = 12.0;
    panel.layer.borderWidth = 1.0;
    panel.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.22].CGColor;
    panel.hidden = YES;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(14.0, 10.0, 236.0, 28.0)];
    title.text = @"HFAMap v2.5.1-dev Generic Handler";
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

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(14.0, 196.0, 236.0, 94.0)];
    status.text = @"1 Search = frozen fast discovery\n2 Analyze = feature→handler→method descriptor\n3 Probe = exact callback runtime correlation";
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
    NSLog(@"[HFAMap] v2.5.1 generic feature handler/method descriptor UI installed on window=%@", window);
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

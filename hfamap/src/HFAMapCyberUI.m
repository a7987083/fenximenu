#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import "HFAMapCore.h"
#import "HFAMapBuildInfo.h"
#import "HFAMapOutputName.h"

static UIView *gHFACyberPanel = nil;
static UITextView *gHFACyberLogTextView = nil;
static id gHFACyberController = nil;

static UIColor *HFACyberColor(CGFloat r, CGFloat g, CGFloat b, CGFloat a) {
    return [UIColor colorWithRed:r green:g blue:b alpha:a];
}

static NSString *HFARealMainExecutable(void) {
    NSString *name = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleExecutable"];
    if (![name isKindOfClass:NSString.class] || !name.length)
        name = NSBundle.mainBundle.executablePath.lastPathComponent;
    return name.length ? name : @"MainExecutable";
}

void HFACyberUIAppendLog(NSString *text) {
    if (![text isKindOfClass:NSString.class] || !text.length) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gHFACyberLogTextView) return;
        NSString *line = [text hasSuffix:@"\n"] ? text : [text stringByAppendingString:@"\n"];
        NSAttributedString *chunk = [[[NSAttributedString alloc] initWithString:line attributes:@{
            NSForegroundColorAttributeName: HFACyberColor(0.90, 0.93, 0.96, 1.0),
            NSFontAttributeName: [UIFont fontWithName:@"CourierNewPSMT" size:11.0]
                ?: [UIFont systemFontOfSize:11.0]
        }] autorelease];
        [gHFACyberLogTextView.textStorage appendAttributedString:chunk];
        if (gHFACyberLogTextView.textStorage.length > 120000)
            [gHFACyberLogTextView.textStorage deleteCharactersInRange:NSMakeRange(0, MIN((NSUInteger)30000, gHFACyberLogTextView.textStorage.length))];
        [gHFACyberLogTextView scrollRangeToVisible:NSMakeRange(gHFACyberLogTextView.textStorage.length, 0)];
    });
}

static UIViewController *HFATopController(void) {
    UIWindow *window = UIApplication.sharedApplication.keyWindow;
    if (!window) for (UIWindow *w in UIApplication.sharedApplication.windows) if (w.isKeyWindow) { window = w; break; }
    UIViewController *vc = window.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    if ([vc isKindOfClass:UINavigationController.class]) vc = [(UINavigationController *)vc topViewController];
    if ([vc isKindOfClass:UITabBarController.class]) vc = [(UITabBarController *)vc selectedViewController];
    return vc;
}

@interface HFACyberUIController : NSObject
@end

@implementation HFACyberUIController

- (void)handleCyberPan:(UIPanGestureRecognizer *)gesture {
    UIView *target = gesture.view, *superview = target.superview;
    if (!target || !superview) return;
    if (gesture.state == UIGestureRecognizerStateBegan || gesture.state == UIGestureRecognizerStateChanged) {
        CGPoint t = [gesture translationInView:superview], c = target.center;
        c.x += t.x; c.y += t.y;
        CGFloat hw = target.bounds.size.width * 0.5, hh = target.bounds.size.height * 0.5;
        c.x = MAX(hw, MIN(superview.bounds.size.width - hw, c.x));
        c.y = MAX(hh, MIN(superview.bounds.size.height - hh, c.y));
        target.center = c;
        [gesture setTranslation:CGPointZero inView:superview];
    }
}

- (void)presentAmbiguousCandidates:(NSArray *)candidates {
    UIViewController *vc = HFATopController();
    if (!vc || !candidates.count) {
        HFACyberUIAppendLog(@"[SELECT] ambiguous candidates; UI picker unavailable");
        return;
    }
    UIAlertController *picker = [UIAlertController alertControllerWithTitle:@"检测到多个菜单候选"
        message:@"仅在候选证据接近时需要人工选择。主程序和 UnityFramework 不需要选择。"
        preferredStyle:UIAlertControllerStyleActionSheet];
    NSUInteger limit = MIN((NSUInteger)8, candidates.count);
    for (NSUInteger i=0;i<limit;i++) {
        NSDictionary *candidate = candidates[i];
        NSString *title = [NSString stringWithFormat:@"%@  score=%@",
                           candidate[@"image"] ?: @"?", candidate[@"score"] ?: @0];
        [picker addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a) {
            if (HFAMapSelectMenuCandidate(candidate)) {
                HFACyberUIAppendLog([NSString stringWithFormat:@"[SELECT] manual menu=%@", candidate[@"image"] ?: @"?"]);
                HFACyberUIAppendLog(@"[NEXT] 点击“解析并导出”");
            }
        }]];
    }
    [picker addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    UIPopoverPresentationController *pop = picker.popoverPresentationController;
    if (pop) { pop.sourceView = gHFACyberPanel; pop.sourceRect = gHFACyberPanel.bounds; }
    [vc presentViewController:picker animated:YES completion:nil];
}

- (void)actionCyberScan:(UIButton *)sender {
    sender.enabled = NO;
    HFACyberUIAppendLog(@"\n[COMMAND] 扫描菜单模块");
    HFACyberUIAppendLog([NSString stringWithFormat:@"[HOST] main=%@ bundle=%@",
                         HFARealMainExecutable(), NSBundle.mainBundle.bundleIdentifier ?: @"?"]);
    HFACyberUIAppendLog(@"[DISCOVERY] 主程序/UnityFramework 自动识别；扫描菜单候选...");
    HFAMapRunMenuDiscovery(^(NSDictionary *summary) {
        sender.enabled = YES;
        NSString *status = summary[@"status"] ?: @"?";
        if ([status isEqualToString:@"selected"]) {
            NSDictionary *selected = summary[@"selected"] ?: @{};
            HFACyberUIAppendLog([NSString stringWithFormat:@"[SELECT] %@ score=%@ candidates=%@",
                                 selected[@"image"] ?: @"?", selected[@"score"] ?: @0,
                                 summary[@"candidateCount"] ?: @0]);
            HFACyberUIAppendLog(@"[NEXT] 点击“解析并导出”");
            return;
        }
        NSString *reason = summary[@"reason"] ?: @"";
        HFACyberUIAppendLog([NSString stringWithFormat:@"[DISCOVERY-END] incomplete reason=%@", reason]);
        if ([reason isEqualToString:@"ambiguous-top-candidates"])
            [self presentAmbiguousCandidates:summary[@"candidates"] ?: @[]];
    });
}

- (void)actionCyberExport:(UIButton *)sender {
    sender.enabled = NO;
    HFACyberUIAppendLog(@"\n[COMMAND] 解析并导出");
    HFACyberUIAppendLog(@"[ANALYZE] ownership → handler → dispatcher → IL2CPP method index...");
    HFAMapRunSelectedDeepAnalysis(^(NSDictionary *summary) {
        NSString *status = summary[@"status"] ?: @"?";
        if ([status isEqualToString:@"no-selected-menu"]) {
            HFACyberUIAppendLog(@"[ERROR] 尚未选择菜单，请先点击“扫描菜单模块”");
            sender.enabled = YES;
            return;
        }
        NSArray *features = summary[@"features"] ?: @[];
        NSArray *runtime = summary[@"runtimeRecords"] ?: @[];
        NSArray *unresolved = summary[@"unresolved"] ?: @[];
        HFACyberUIAppendLog([NSString stringWithFormat:@"[ANALYZE-END] status=%@ features=%lu runtime=%lu unresolved=%lu",
                             status, (unsigned long)features.count, (unsigned long)runtime.count,
                             (unsigned long)unresolved.count]);
        HFACyberUIAppendLog([NSString stringWithFormat:@"[EXPORT] %@ / %@ / %@",
                             HFAOutputFileName(@"Analysis.json"),
                             HFAOutputFileName(@"FeatureRegistry.json"),
                             HFAOutputFileName(@"Patches.json")]);

        if (runtime.count || unresolved.count) {
            HFACyberUIAppendLog(@"[RUNTIME] 自动进入 8s Trace；只操作一次目标功能（如 Damage Multiplier）");
            HFAMapArmLastSelectedRuntimeProbe(^(NSDictionary *probe) {
                HFACyberUIAppendLog([NSString stringWithFormat:@"[RUNTIME-END] status=%@ events=%@ links=%@",
                                     probe[@"status"] ?: @"?",
                                     probe[@"eventCount"] ?: @0,
                                     probe[@"featureDirectedCorrelationCount"] ?: @0]);
                NSDictionary *exact = probe[@"il2cppRuntimeProbe"][@"exactRuntimeMethodTrace"];
                if ([exact isKindOfClass:NSDictionary.class])
                    HFACyberUIAppendLog([NSString stringWithFormat:@"[METHOD] exact events=%@ output=%@",
                                         exact[@"eventCount"] ?: @0,
                                         HFAOutputFileName(@"ExactRuntimeMethods.json")]);
                sender.enabled = YES;
            });
        } else {
            HFACyberUIAppendLog(@"[DONE] 静态证据已闭环，无需 Runtime Trace");
            sender.enabled = YES;
        }
    });
}
@end

static UIButton *HFACyberButton(NSString *title, UIColor *accent, CGRect frame, SEL action) {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
    button.frame = frame;
    [button setTitle:title forState:UIControlStateNormal];
    [button setTitleColor:accent forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:13.0];
    button.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.50];
    button.layer.cornerRadius = 7.0;
    button.layer.borderWidth = 1.2;
    button.layer.borderColor = accent.CGColor;
    [button addTarget:gHFACyberController action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}

id HFACyberUICreatePanel(id hostWindow) {
    if (gHFACyberPanel) return gHFACyberPanel;
    UIWindow *window = [hostWindow isKindOfClass:UIWindow.class] ? hostWindow : nil;
    if (!window) return nil;
    if (!gHFACyberController) gHFACyberController = [HFACyberUIController new];

    CGRect wb = window.bounds;
    CGFloat w = MIN(500.0, MAX(320.0, wb.size.width - 20.0));
    CGFloat h = MIN(330.0, MAX(250.0, wb.size.height - 100.0));
    UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(MAX(10.0,(wb.size.width-w)*0.5), MAX(55.0,(wb.size.height-h)*0.20), w, h)];
    panel.backgroundColor = HFACyberColor(0.02,0.02,0.05,0.94);
    panel.layer.cornerRadius = 10.0;
    panel.layer.borderWidth = 1.5;
    panel.layer.borderColor = HFACyberColor(0.0,1.0,1.0,0.75).CGColor;
    panel.hidden = YES;
    [panel addGestureRecognizer:[[[UIPanGestureRecognizer alloc] initWithTarget:gHFACyberController action:@selector(handleCyberPan:)] autorelease]];

    UILabel *header = [[UILabel alloc] initWithFrame:CGRectMake(12,6,w-24,30)];
    header.text = [NSString stringWithFormat:@"HFAMap %@ · Unified Resolver", HFAMapBuildVersion()];
    header.textColor = HFACyberColor(0.2,1.0,0.2,1.0);
    header.font = [UIFont fontWithName:@"CourierNewPS-BoldMT" size:13.0] ?: [UIFont boldSystemFontOfSize:13.0];
    [panel addSubview:header];

    CGFloat left = MIN(155.0, MAX(125.0, w*0.33));
    UIView *leftPanel = [[UIView alloc] initWithFrame:CGRectMake(0,40,left,h-40)];
    [panel addSubview:leftPanel];

    [leftPanel addSubview:HFACyberButton(@"扫描菜单模块", UIColor.magentaColor, CGRectMake(10,24,left-20,42), @selector(actionCyberScan:))];
    [leftPanel addSubview:HFACyberButton(@"解析并导出", UIColor.cyanColor, CGRectMake(10,86,left-20,42), @selector(actionCyberExport:))];

    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(10,150,left-20,70)];
    hint.text = @"主程序：自动\nUnityFramework：自动\n菜单：自动，歧义才选择";
    hint.numberOfLines = 3;
    hint.textColor = [UIColor colorWithWhite:0.75 alpha:1.0];
    hint.font = [UIFont systemFontOfSize:10.5];
    [leftPanel addSubview:hint];

    UITextView *log = [[UITextView alloc] initWithFrame:CGRectMake(left+2,40,w-left-4,h-42)];
    log.backgroundColor = UIColor.clearColor;
    log.editable = NO; log.selectable = YES;
    log.textColor = [UIColor colorWithWhite:0.92 alpha:1.0];
    log.font = [UIFont fontWithName:@"CourierNewPSMT" size:11.0] ?: [UIFont systemFontOfSize:11.0];
    [panel addSubview:log];

    gHFACyberPanel = panel; gHFACyberLogTextView = log;
    [window addSubview:panel];
    HFACyberUIAppendLog([NSString stringWithFormat:@"[System] %@ ready", HFAMapDisplayVersion()]);
    HFACyberUIAppendLog([NSString stringWithFormat:@"[System] main executable=%@", HFARealMainExecutable()]);
    HFACyberUIAppendLog(@"[System] 两步流程：扫描菜单模块 → 解析并导出");
    return panel;
}

void HFACyberUIToggle(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gHFACyberPanel) return;
        gHFACyberPanel.hidden = !gHFACyberPanel.hidden;
        if (!gHFACyberPanel.hidden) [gHFACyberPanel.superview bringSubviewToFront:gHFACyberPanel];
    });
}

void HFACyberUIBringToFront(id hostWindow) {
    UIWindow *window = [hostWindow isKindOfClass:UIWindow.class] ? hostWindow : nil;
    if (!window || !gHFACyberPanel) return;
    if (gHFACyberPanel.superview != window) { [gHFACyberPanel removeFromSuperview]; [window addSubview:gHFACyberPanel]; }
    if (!gHFACyberPanel.hidden) [window bringSubviewToFront:gHFACyberPanel];
}

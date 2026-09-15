#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>

extern unsigned HFAAppLocalScanCandidates(void);
extern unsigned HFAAppLocalExecuteParser(void);

static UIView *gHFACyberPanel = nil;
static UITextView *gHFACyberLogTextView = nil;
static id gHFACyberController = nil;

static UIColor *HFACyberColor(CGFloat r, CGFloat g, CGFloat b, CGFloat a) {
    return [UIColor colorWithRed:r green:g blue:b alpha:a];
}

void HFACyberUIAppendLog(NSString *text) {
    if (![text isKindOfClass:[NSString class]] || !text.length) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gHFACyberLogTextView) return;
        NSString *line = [text hasSuffix:@"\n"] ? text : [text stringByAppendingString:@"\n"];
        NSAttributedString *chunk = [[NSAttributedString alloc] initWithString:line attributes:@{
            NSForegroundColorAttributeName: HFACyberColor(0.90, 0.93, 0.96, 1.0),
            NSFontAttributeName: [UIFont fontWithName:@"CourierNewPSMT" size:11.0] ?: [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightRegular]
        }];
        [gHFACyberLogTextView.textStorage appendAttributedString:chunk];
        if (gHFACyberLogTextView.textStorage.length > 120000) {
            NSUInteger trim = MIN((NSUInteger)30000, gHFACyberLogTextView.textStorage.length);
            [gHFACyberLogTextView.textStorage deleteCharactersInRange:NSMakeRange(0, trim)];
        }
        NSRange end = NSMakeRange(gHFACyberLogTextView.textStorage.length, 0);
        [gHFACyberLogTextView scrollRangeToVisible:end];
    });
}

@interface HFACyberUIController : NSObject
@end

@implementation HFACyberUIController

- (void)handleCyberPan:(UIPanGestureRecognizer *)gesture {
    UIView *target = gesture.view;
    UIView *superview = target.superview;
    if (!target || !superview) return;
    if (gesture.state == UIGestureRecognizerStateBegan ||
        gesture.state == UIGestureRecognizerStateChanged) {
        CGPoint trans = [gesture translationInView:superview];
        CGPoint center = target.center;
        center.x += trans.x;
        center.y += trans.y;
        CGRect bounds = superview.bounds;
        CGFloat halfW = target.bounds.size.width * 0.5;
        CGFloat halfH = target.bounds.size.height * 0.5;
        center.x = MAX(MIN(center.x, CGRectGetMaxX(bounds) - 18.0), CGRectGetMinX(bounds) + 18.0);
        center.y = MAX(MIN(center.y, CGRectGetMaxY(bounds) - 18.0), CGRectGetMinY(bounds) + 18.0);
        if (halfW < bounds.size.width * 0.5) center.x = MAX(MIN(center.x, CGRectGetMaxX(bounds) - halfW), CGRectGetMinX(bounds) + halfW);
        if (halfH < bounds.size.height * 0.5) center.y = MAX(MIN(center.y, CGRectGetMaxY(bounds) - halfH), CGRectGetMinY(bounds) + halfH);
        target.center = center;
        [gesture setTranslation:CGPointZero inView:superview];
    }
}

- (void)actionCyberScan:(UIButton *)sender {
    sender.enabled = NO;
    HFACyberUIAppendLog(@"\n[COMMAND] 扫描菜单模块");
    HFACyberUIAppendLog(@"[DISCOVERY] scanning app root + Frameworks ...");
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        unsigned count = HFAAppLocalScanCandidates();
        HFACyberUIAppendLog([NSString stringWithFormat:@"[DISCOVERY-END] candidates=%u", count]);
        dispatch_async(dispatch_get_main_queue(), ^{ sender.enabled = YES; });
    });
}

- (void)actionCyberExport:(UIButton *)sender {
    sender.enabled = NO;
    HFACyberUIAppendLog(@"\n[COMMAND] 解析并导出");
    HFACyberUIAppendLog(@"[RESOLVE] image-local parser starting ...");
    dispatch_async(dispatch_get_main_queue(), ^{
        unsigned valid = HFAAppLocalExecuteParser();
        HFACyberUIAppendLog([NSString stringWithFormat:@"[EXPORT-END] validMappings=%u", valid]);
        sender.enabled = YES;
    });
}

@end

static UIButton *HFACyberButton(NSString *title, UIColor *accent, CGRect frame, SEL action) {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
    button.frame = frame;
    [button setTitle:title forState:UIControlStateNormal];
    [button setTitleColor:accent forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:12.5];
    button.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.50];
    button.layer.cornerRadius = 6.0;
    button.layer.borderWidth = 1.2;
    button.layer.borderColor = accent.CGColor;
    button.layer.shadowColor = accent.CGColor;
    button.layer.shadowRadius = 6.0;
    button.layer.shadowOpacity = 0.80;
    button.layer.shadowOffset = CGSizeZero;
    [button addTarget:gHFACyberController action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}

id HFACyberUICreatePanel(id hostWindow) {
    if (gHFACyberPanel) return gHFACyberPanel;
    UIWindow *window = [hostWindow isKindOfClass:[UIWindow class]] ? (UIWindow *)hostWindow : nil;
    if (!window) return nil;
    if (!gHFACyberController) gHFACyberController = [HFACyberUIController new];

    CGRect wb = window.bounds;
    CGFloat winWidth = MIN(460.0, MAX(300.0, wb.size.width - 20.0));
    CGFloat winHeight = MIN(320.0, MAX(240.0, wb.size.height - 90.0));
    CGFloat originX = MAX(10.0, (wb.size.width - winWidth) * 0.5);
    CGFloat originY = MAX(50.0, MIN(90.0, wb.size.height - winHeight - 20.0));
    UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(originX, originY, winWidth, winHeight)];
    panel.backgroundColor = HFACyberColor(0.02, 0.02, 0.05, 0.91);
    panel.layer.cornerRadius = 8.0;
    panel.layer.borderWidth = 1.5;
    panel.layer.borderColor = HFACyberColor(0.0, 1.0, 1.0, 0.80).CGColor;
    panel.layer.shadowColor = [UIColor cyanColor].CGColor;
    panel.layer.shadowRadius = 10.0;
    panel.layer.shadowOpacity = 0.90;
    panel.layer.shadowOffset = CGSizeZero;
    panel.clipsToBounds = NO;

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:gHFACyberController action:@selector(handleCyberPan:)];
    pan.cancelsTouchesInView = NO;
    [panel addGestureRecognizer:pan];

    UILabel *header = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, winWidth, 35.0)];
    header.text = @"  HFAMap AppLocalMenuResolver";
    header.textColor = HFACyberColor(0.2, 1.0, 0.2, 1.0);
    header.font = [UIFont fontWithName:@"CourierNewPS-BoldMT" size:13.0] ?: [UIFont monospacedSystemFontOfSize:13.0 weight:UIFontWeightBold];
    header.backgroundColor = [UIColor clearColor];
    CALayer *bottomBorder = [CALayer layer];
    bottomBorder.frame = CGRectMake(0, 34.0, winWidth, 1.5);
    bottomBorder.backgroundColor = HFACyberColor(0.0, 1.0, 1.0, 0.60).CGColor;
    bottomBorder.shadowColor = [UIColor cyanColor].CGColor;
    bottomBorder.shadowRadius = 4.0;
    bottomBorder.shadowOpacity = 0.8;
    [header.layer addSublayer:bottomBorder];
    [panel addSubview:header];

    CGFloat leftWidth = MIN(140.0, MAX(110.0, winWidth * 0.32));
    UIView *leftPanel = [[UIView alloc] initWithFrame:CGRectMake(0, 35.0, leftWidth, winHeight - 35.0)];
    leftPanel.backgroundColor = [UIColor clearColor];
    CALayer *rightBorder = [CALayer layer];
    rightBorder.frame = CGRectMake(leftWidth - 1.0, 0, 1.5, winHeight - 35.0);
    rightBorder.backgroundColor = HFACyberColor(0.0, 1.0, 1.0, 0.40).CGColor;
    [leftPanel.layer addSublayer:rightBorder];
    [panel addSubview:leftPanel];

    UIButton *scan = HFACyberButton(@"扫描菜单模块", [UIColor magentaColor], CGRectMake(10.0, 20.0, leftWidth - 20.0, 36.0), @selector(actionCyberScan:));
    [leftPanel addSubview:scan];
    UIButton *exportButton = HFACyberButton(@"解析并导出", [UIColor cyanColor], CGRectMake(10.0, 75.0, leftWidth - 20.0, 36.0), @selector(actionCyberExport:));
    [leftPanel addSubview:exportButton];

    UITextView *logView = [[UITextView alloc] initWithFrame:CGRectMake(leftWidth + 2.0, 37.0, winWidth - leftWidth - 4.0, winHeight - 39.0)];
    logView.backgroundColor = [UIColor clearColor];
    logView.textColor = HFACyberColor(0.90, 0.93, 0.96, 1.0);
    logView.font = [UIFont fontWithName:@"CourierNewPSMT" size:11.0] ?: [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightRegular];
    logView.editable = NO;
    logView.selectable = YES;
    logView.layoutManager.allowsNonContiguousLayout = NO;
    logView.textContainerInset = UIEdgeInsetsMake(6.0, 6.0, 6.0, 6.0);
    [panel addSubview:logView];

    gHFACyberPanel = panel;
    gHFACyberLogTextView = logView;
    [window addSubview:panel];
    panel.hidden = YES;
    HFACyberUIAppendLog(@"[System] HFAMap AppLocalMenuResolver ready.");
    HFACyberUIAppendLog(@"[System] 先扫描菜单模块，再解析并导出。");
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
    UIWindow *window = [hostWindow isKindOfClass:[UIWindow class]] ? (UIWindow *)hostWindow : nil;
    if (!window || !gHFACyberPanel) return;
    if (gHFACyberPanel.superview != window) {
        [gHFACyberPanel removeFromSuperview];
        [window addSubview:gHFACyberPanel];
    }
    if (!gHFACyberPanel.hidden) [window bringSubviewToFront:gHFACyberPanel];
}

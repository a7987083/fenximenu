#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <mach-o/dyld.h>
#include <string.h>

extern unsigned HFAAppLocalScanCandidates(void);
extern unsigned HFAAppLocalExecuteParser(void);
extern void HFAAppLocalSetPrimaryImage(const char *image);

static UIWindow *gHFAWindow;
static UIView *gHFAPanel;
static UIButton *gHFAFloatButton;
static UILabel *gHFATargetLabel;
static UILabel *gHFAStatusLabel;
static UITextView *gHFALogView;
static NSString *gHFASelectedImage;

static NSString *HFALogPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];
}

static UIViewController *HFATopController(void) {
    UIViewController *vc = gHFAWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

static NSString *HFABaseName(const char *path) {
    if (!path) return @"?";
    const char *slash = strrchr(path, '/');
    return [NSString stringWithUTF8String:slash ? slash + 1 : path] ?: @"?";
}

static BOOL HFAImageIsSelectable(const char *path) {
    if (!path || !*path) return NO;
    if (strstr(path, "/System/Library/") || strstr(path, "/usr/lib/")) return NO;
    NSString *p = [NSString stringWithUTF8String:path];
    NSString *bundle = NSBundle.mainBundle.bundlePath;
    if ([p hasPrefix:bundle]) return YES;
    NSString *base = p.lastPathComponent.lowercaseString;
    return [base hasSuffix:@".dylib"] || [p containsString:@".framework/"];
}

static NSArray<NSDictionary *> *HFASelectableImages(void) {
    NSMutableArray *out = [NSMutableArray array];
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!HFAImageIsSelectable(path)) continue;
        NSString *name = HFABaseName(path);
        if ([name containsString:@"HFAMapGenericSecretUI"] || [name containsString:@"HFAMapUniversal"]) continue;
        [out addObject:@{@"name":name, @"path":[NSString stringWithUTF8String:path] ?: @"?"}];
    }
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
    }];
    return out;
}

static void HFARefreshLog(void) {
    NSError *error = nil;
    NSString *s = [NSString stringWithContentsOfFile:HFALogPath() encoding:NSUTF8StringEncoding error:&error];
    if (!s) s = [NSString stringWithFormat:@"[LOG] %@", error.localizedDescription ?: @"not created yet"];
    if (s.length > 18000) s = [s substringFromIndex:s.length - 18000];
    NSString *tail = s;
    dispatch_async(dispatch_get_main_queue(), ^{
        gHFALogView.text = tail;
        if (tail.length) [gHFALogView scrollRangeToVisible:NSMakeRange(tail.length, 0)];
    });
}

@interface HFAPassThroughWindow : UIWindow @end
@implementation HFAPassThroughWindow
- (BOOL)pointInside:(CGPoint)point withEvent:(UIEvent *)event {
    for (UIView *view in [self.subviews reverseObjectEnumerator]) {
        if (view.hidden || view.alpha <= 0.01 || !view.userInteractionEnabled) continue;
        CGPoint p = [self convertPoint:point toView:view];
        if ([view hitTest:p withEvent:event]) return YES;
    }
    return NO;
}
@end

@interface HFAGenericRuntimeController : UIViewController @end
@implementation HFAGenericRuntimeController
- (BOOL)shouldAutorotate { return YES; }
- (UIInterfaceOrientationMask)supportedInterfaceOrientations { return UIInterfaceOrientationMaskAll; }
@end

@interface HFAGenericRuntimeActions : NSObject @end
@implementation HFAGenericRuntimeActions
- (void)dragFloat:(UIPanGestureRecognizer *)g {
    UIView *v=g.view; CGPoint d=[g translationInView:v.superview]; CGPoint c=v.center;
    c.x+=d.x; c.y+=d.y; CGFloat hw=v.bounds.size.width/2.0, hh=v.bounds.size.height/2.0;
    c.x=MAX(hw,MIN(v.superview.bounds.size.width-hw,c.x));
    c.y=MAX(hh,MIN(v.superview.bounds.size.height-hh,c.y));
    v.center=c; [g setTranslation:CGPointZero inView:v.superview];
}
- (void)dragPanel:(UIPanGestureRecognizer *)g {
    UIView *v=g.view; CGPoint d=[g translationInView:v.superview]; CGPoint c=v.superview.center;
    c=gHFAPanel.center; c.x+=d.x; c.y+=d.y; gHFAPanel.center=c;
    [g setTranslation:CGPointZero inView:v.superview];
}
- (void)togglePanel {
    gHFAPanel.hidden=!gHFAPanel.hidden;
    if (!gHFAPanel.hidden) { [gHFAWindow bringSubviewToFront:gHFAPanel]; [gHFAWindow bringSubviewToFront:gHFAFloatButton]; HFARefreshLog(); }
}
- (void)selectImage:(UIButton *)sender {
    NSArray<NSDictionary *> *images=HFASelectableImages();
    UIAlertController *sheet=[UIAlertController alertControllerWithTitle:@"选择目标 dylib" message:@"当前进程已加载的非系统 Mach-O" preferredStyle:UIAlertControllerStyleActionSheet];
    NSUInteger cap=MIN(images.count,(NSUInteger)30);
    for (NSUInteger i=0;i<cap;i++) {
        NSDictionary *row=images[i]; NSString *name=row[@"name"];
        [sheet addAction:[UIAlertAction actionWithTitle:name style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a){
            gHFASelectedImage=name; HFAAppLocalSetPrimaryImage(name.UTF8String);
            gHFATargetLabel.text=[NSString stringWithFormat:@"目标：%@",name];
            gHFAStatusLabel.text=@"状态：已选择，准备分析";
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    UIPopoverPresentationController *popover=sheet.popoverPresentationController;
    if (popover) { popover.sourceView=sender; popover.sourceRect=sender.bounds; }
    [HFATopController() presentViewController:sheet animated:YES completion:nil];
}
- (void)scanCandidates:(UIButton *)sender {
    sender.enabled=NO; gHFAStatusLabel.text=@"状态：扫描候选 dylib…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
        unsigned count=HFAAppLocalScanCandidates();
        dispatch_async(dispatch_get_main_queue(), ^{ gHFAStatusLabel.text=[NSString stringWithFormat:@"状态：发现 %u 个候选",count]; sender.enabled=YES; HFARefreshLog(); });
    });
}
- (void)analyzeAll:(UIButton *)sender {
    sender.enabled=NO;
    if (gHFASelectedImage.length) HFAAppLocalSetPrimaryImage(gHFASelectedImage.UTF8String);
    gHFAStatusLabel.text=@"状态：全量分析中…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
        if (!gHFASelectedImage.length) HFAAppLocalScanCandidates();
        unsigned valid=HFAAppLocalExecuteParser();
        dispatch_async(dispatch_get_main_queue(), ^{ gHFAStatusLabel.text=[NSString stringWithFormat:@"状态：分析完成，valid=%u",valid]; sender.enabled=YES; HFARefreshLog(); });
    });
}
- (void)refreshLog:(__unused UIButton *)sender { HFARefreshLog(); }
- (void)showLogPath:(UIButton *)sender {
    UIAlertController *a=[UIAlertController alertControllerWithTitle:@"日志位置" message:HFALogPath() preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"复制路径" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){ UIPasteboard.generalPasteboard.string=HFALogPath(); }]];
    [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleCancel handler:nil]];
    [HFATopController() presentViewController:a animated:YES completion:nil];
}
- (void)closePanel:(__unused UIButton *)sender { gHFAPanel.hidden=YES; }
@end

static HFAGenericRuntimeActions *gHFAActions;
static UIButton *HFAButton(NSString *title, CGRect frame, SEL action) {
    UIButton *b=[UIButton buttonWithType:UIButtonTypeSystem]; b.frame=frame;
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:[UIColor colorWithRed:0.15 green:1 blue:0.92 alpha:1] forState:UIControlStateNormal];
    b.titleLabel.font=[UIFont boldSystemFontOfSize:13]; b.backgroundColor=[UIColor colorWithWhite:0.08 alpha:0.94];
    b.layer.cornerRadius=8; b.layer.borderWidth=1; b.layer.borderColor=[UIColor colorWithRed:0.12 green:0.85 blue:1 alpha:0.85].CGColor;
    [b addTarget:gHFAActions action:action forControlEvents:UIControlEventTouchUpInside]; return b;
}

static void HFAInstallRuntimeUI(void) {
    if (gHFAWindow || !UIApplication.sharedApplication) return;
    gHFAActions=[HFAGenericRuntimeActions new];
    HFAPassThroughWindow *window=[[HFAPassThroughWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    window.backgroundColor=UIColor.clearColor; window.windowLevel=UIWindowLevelAlert-1;
    HFAGenericRuntimeController *vc=[HFAGenericRuntimeController new]; vc.view.backgroundColor=UIColor.clearColor;
    window.rootViewController=vc; window.hidden=NO; gHFAWindow=window;

    UIButton *floatButton=[UIButton buttonWithType:UIButtonTypeCustom]; floatButton.frame=CGRectMake(18,120,54,54);
    floatButton.backgroundColor=[UIColor colorWithRed:0.02 green:0.08 blue:0.12 alpha:0.90]; floatButton.layer.cornerRadius=27;
    floatButton.layer.borderWidth=1.5; floatButton.layer.borderColor=[UIColor colorWithRed:0 green:1 blue:0.92 alpha:0.90].CGColor;
    floatButton.layer.shadowColor=UIColor.cyanColor.CGColor; floatButton.layer.shadowRadius=7; floatButton.layer.shadowOpacity=0.8;
    [floatButton setTitle:@"HFA" forState:UIControlStateNormal]; [floatButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    floatButton.titleLabel.font=[UIFont boldSystemFontOfSize:12]; [floatButton addTarget:gHFAActions action:@selector(togglePanel) forControlEvents:UIControlEventTouchUpInside];
    [floatButton addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:gHFAActions action:@selector(dragFloat:)]];
    [window addSubview:floatButton]; gHFAFloatButton=floatButton;

    CGFloat width=MIN(360.0,UIScreen.mainScreen.bounds.size.width-18.0); CGFloat height=MIN(470.0,UIScreen.mainScreen.bounds.size.height-80.0);
    UIView *panel=[[UIView alloc] initWithFrame:CGRectMake((UIScreen.mainScreen.bounds.size.width-width)/2.0,MAX(48.0,(UIScreen.mainScreen.bounds.size.height-height)/2.0),width,height)];
    panel.backgroundColor=[UIColor colorWithRed:0.015 green:0.02 blue:0.045 alpha:0.96]; panel.layer.cornerRadius=13; panel.layer.borderWidth=1.3;
    panel.layer.borderColor=[UIColor colorWithRed:0 green:0.92 blue:1 alpha:0.75].CGColor; panel.layer.shadowColor=UIColor.cyanColor.CGColor;
    panel.layer.shadowRadius=11; panel.layer.shadowOpacity=0.55; panel.hidden=YES;

    UILabel *title=[[UILabel alloc] initWithFrame:CGRectMake(15,8,width-30,32)]; title.text=@"HFAMap Generic Secret/Key Analyzer v0.1";
    title.textColor=[UIColor colorWithRed:0.25 green:1 blue:0.55 alpha:1]; title.font=[UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightBold];
    title.userInteractionEnabled=YES; [title addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:gHFAActions action:@selector(dragPanel:)]]; [panel addSubview:title];

    gHFATargetLabel=[[UILabel alloc] initWithFrame:CGRectMake(15,43,width-30,20)]; gHFATargetLabel.text=@"目标：未选择"; gHFATargetLabel.textColor=UIColor.lightGrayColor; gHFATargetLabel.font=[UIFont systemFontOfSize:11.5]; [panel addSubview:gHFATargetLabel];
    gHFAStatusLabel=[[UILabel alloc] initWithFrame:CGRectMake(15,63,width-30,20)]; gHFAStatusLabel.text=@"状态：Ready"; gHFAStatusLabel.textColor=[UIColor colorWithRed:0.35 green:0.85 blue:1 alpha:1]; gHFAStatusLabel.font=[UIFont systemFontOfSize:11.5]; [panel addSubview:gHFAStatusLabel];

    CGFloat gap=8,x=15,y=91,bw=(width-30-gap)/2.0,bh=35;
    [panel addSubview:HFAButton(@"选择 dylib",CGRectMake(x,y,bw,bh),@selector(selectImage:))];
    [panel addSubview:HFAButton(@"扫描候选",CGRectMake(x+bw+gap,y,bw,bh),@selector(scanCandidates:))]; y+=bh+8;
    [panel addSubview:HFAButton(@"全量分析",CGRectMake(x,y,bw,bh),@selector(analyzeAll:))];
    [panel addSubview:HFAButton(@"刷新日志",CGRectMake(x+bw+gap,y,bw,bh),@selector(refreshLog:))]; y+=bh+8;
    [panel addSubview:HFAButton(@"日志路径",CGRectMake(x,y,bw,bh),@selector(showLogPath:))];
    [panel addSubview:HFAButton(@"关闭面板",CGRectMake(x+bw+gap,y,bw,bh),@selector(closePanel:))]; y+=bh+10;

    UITextView *log=[[UITextView alloc] initWithFrame:CGRectMake(12,y,width-24,height-y-12)]; log.backgroundColor=[UIColor colorWithWhite:0 alpha:0.35];
    log.textColor=[UIColor colorWithWhite:0.90 alpha:1]; log.font=[UIFont monospacedSystemFontOfSize:9.5 weight:UIFontWeightRegular]; log.editable=NO; log.selectable=YES; log.layer.cornerRadius=7;
    [panel addSubview:log]; gHFALogView=log; [window addSubview:panel]; gHFAPanel=panel;
}

__attribute__((constructor)) static void HFAGenericRuntimeUIInit(void) {
    dispatch_async(dispatch_get_main_queue(), ^{ dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(2.0*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ HFAInstallRuntimeUI(); }); });
}

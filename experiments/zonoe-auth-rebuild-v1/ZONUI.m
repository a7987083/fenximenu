#import "ZONUI.h"

@interface ZONInfoViewController : UIViewController
@property(nonatomic,copy) NSString *zonTitle;
@property(nonatomic,copy) NSString *zonText;
@end

@implementation ZONInfoViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectZero];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = self.zonTitle.length ? self.zonTitle : @"授权信息";
    title.font = [UIFont boldSystemFontOfSize:20.0];

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.translatesAutoresizingMaskIntoConstraints = NO;
    [close setTitle:@"关闭" forState:UIControlStateNormal];
    [close addTarget:self action:@selector(zonClose) forControlEvents:UIControlEventTouchUpInside];

    UITextView *text = [[UITextView alloc] initWithFrame:CGRectZero];
    text.translatesAutoresizingMaskIntoConstraints = NO;
    text.editable = NO;
    text.selectable = YES;
    text.alwaysBounceVertical = YES;
    text.font = [UIFont monospacedSystemFontOfSize:12.5 weight:UIFontWeightRegular];
    text.text = self.zonText ?: @"";
    text.backgroundColor = UIColor.secondarySystemBackgroundColor;
    text.layer.cornerRadius = 10.0;
    text.textContainerInset = UIEdgeInsetsMake(12, 10, 12, 10);

    [self.view addSubview:title];
    [self.view addSubview:close];
    [self.view addSubview:text];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [title.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [title.topAnchor constraintEqualToAnchor:g.topAnchor constant:12],
        [close.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [close.centerYAnchor constraintEqualToAnchor:title.centerYAnchor],
        [text.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:12],
        [text.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-12],
        [text.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:12],
        [text.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-12],
    ]];
}
- (void)zonClose { [self dismissViewControllerAnimated:YES completion:nil]; }
@end

@interface ZONUI ()
@property(nonatomic,strong) UIButton *button;
@property(nonatomic,weak) UIWindow *hostWindow;
@property(nonatomic,assign) CGPoint panStartCenter;
@property(nonatomic,assign) BOOL presentingInput;
@end

@implementation ZONUI

+ (instancetype)shared {
    static ZONUI *x;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ x = [ZONUI new]; });
    return x;
}

- (UIWindow *)foregroundWindow {
    UIWindow *fallback = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:UIWindowScene.class]) continue;
            if (scene.activationState != UISceneActivationStateForegroundActive) continue;
            for (UIWindow *candidate in ((UIWindowScene *)scene).windows) {
                if (candidate.hidden || candidate.alpha <= 0.01 || !candidate.rootViewController) continue;
                if (candidate.isKeyWindow) return candidate;
                if (!fallback && candidate.windowLevel == UIWindowLevelNormal) fallback = candidate;
            }
        }
    }
    if (fallback) return fallback;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (UIApplication.sharedApplication.keyWindow) return UIApplication.sharedApplication.keyWindow;
#pragma clang diagnostic pop
    for (UIWindow *candidate in UIApplication.sharedApplication.windows) {
        if (!candidate.hidden && candidate.alpha > 0.01 && candidate.rootViewController) return candidate;
    }
    return nil;
}

- (UIViewController *)topVC {
    UIViewController *vc = [self foregroundWindow].rootViewController;
    BOOL changed = YES;
    while (vc && changed) {
        changed = NO;
        if (vc.presentedViewController && !vc.presentedViewController.isBeingDismissed) {
            vc = vc.presentedViewController;
            changed = YES;
            continue;
        }
        if ([vc isKindOfClass:UINavigationController.class]) {
            UIViewController *next = ((UINavigationController *)vc).visibleViewController;
            if (next && next != vc) { vc = next; changed = YES; continue; }
        }
        if ([vc isKindOfClass:UITabBarController.class]) {
            UIViewController *next = ((UITabBarController *)vc).selectedViewController;
            if (next && next != vc) { vc = next; changed = YES; continue; }
        }
    }
    return vc;
}

- (void)installFloatingButton {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.button.superview) return;
        UIWindow *window = [self foregroundWindow];
        if (!window) return;
        self.hostWindow = window;

        UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
        button.frame = CGRectMake(18, 150, 54, 54);
        button.layer.cornerRadius = 27.0;
        button.layer.masksToBounds = YES;
        button.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.92];
        [button setTitle:@"ZN" forState:UIControlStateNormal];
        [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
        button.titleLabel.font = [UIFont boldSystemFontOfSize:17.0];
        button.accessibilityLabel = @"Zonoe";
        [button addTarget:self action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];

        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
        pan.maximumNumberOfTouches = 1;
        [button addGestureRecognizer:pan];

        [window addSubview:button];
        [window bringSubviewToFront:button];
        self.button = button;
    });
}

- (void)handlePan:(UIPanGestureRecognizer *)pan {
    UIView *view = pan.view;
    UIView *host = view.superview;
    if (!view || !host) return;

    if (pan.state == UIGestureRecognizerStateBegan) {
        self.panStartCenter = view.center;
    }

    CGPoint t = [pan translationInView:host];
    CGPoint c = CGPointMake(self.panStartCenter.x + t.x, self.panStartCenter.y + t.y);
    CGFloat halfW = CGRectGetWidth(view.bounds) * 0.5;
    CGFloat halfH = CGRectGetHeight(view.bounds) * 0.5;
    UIEdgeInsets safe = host.safeAreaInsets;
    CGFloat minX = safe.left + halfW + 4.0;
    CGFloat maxX = CGRectGetWidth(host.bounds) - safe.right - halfW - 4.0;
    CGFloat minY = safe.top + halfH + 4.0;
    CGFloat maxY = CGRectGetHeight(host.bounds) - safe.bottom - halfH - 4.0;
    c.x = MIN(MAX(c.x, minX), maxX);
    c.y = MIN(MAX(c.y, minY), maxY);
    view.center = c;

    if (pan.state == UIGestureRecognizerStateEnded || pan.state == UIGestureRecognizerStateCancelled) {
        CGFloat mid = CGRectGetMidX(host.bounds);
        CGPoint target = view.center;
        target.x = (target.x < mid) ? minX : maxX;
        [UIView animateWithDuration:0.22 animations:^{ view.center = target; }];
    }
}

- (void)tap {
    if (self.presentingInput) return;
    if (self.tapHandler) self.tapHandler();
}

- (void)presentInputAlert:(UIAlertController *)alert completionGuard:(dispatch_block_t)onPresented {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *vc = [self topVC];
        if (!vc || vc.isBeingDismissed) return;
        self.presentingInput = YES;
        [vc presentViewController:alert animated:YES completion:onPresented];
    });
}

- (void)requestUDID:(NSString *)prefill completion:(void (^)(NSString * _Nullable))completion {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"设备 UDID" message:@"请输入设备 UDID" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.text = prefill ?: @"";
        t.placeholder = @"00008120-...";
        t.autocapitalizationType = UITextAutocapitalizationTypeNone;
        t.autocorrectionType = UITextAutocorrectionTypeNo;
        t.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];
    __weak typeof(self) weakSelf = self;
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(__unused UIAlertAction *x) {
        weakSelf.presentingInput = NO;
        if (completion) completion(nil);
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"下一步" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x) {
        weakSelf.presentingInput = NO;
        NSString *s = [a.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (completion) completion(s.length ? s : nil);
    }]];
    [self presentInputAlert:a completionGuard:nil];
}

- (void)requestCardWithCompletion:(void (^)(NSString * _Nullable))completion {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"卡密" message:@"请输入软件源卡密" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.placeholder = @"请输入卡密";
        t.autocapitalizationType = UITextAutocapitalizationTypeNone;
        t.autocorrectionType = UITextAutocorrectionTypeNo;
        t.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];
    __weak typeof(self) weakSelf = self;
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(__unused UIAlertAction *x) {
        weakSelf.presentingInput = NO;
        if (completion) completion(nil);
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"确认激活" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x) {
        weakSelf.presentingInput = NO;
        NSString *s = [a.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (completion) completion(s.length ? s : nil);
    }]];
    [self presentInputAlert:a completionGuard:nil];
}

- (void)showInfo:(NSDictionary *)info title:(NSString *)title {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSData *data = [NSJSONSerialization dataWithJSONObject:info ?: @{} options:(NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys) error:nil];
        NSString *text = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : (info.description ?: @"");
        ZONInfoViewController *vc = [ZONInfoViewController new];
        vc.zonTitle = title ?: @"授权信息";
        vc.zonText = text;
        vc.modalPresentationStyle = UIModalPresentationPageSheet;
        UIViewController *presenter = [self topVC];
        if (!presenter) return;
        [presenter presentViewController:vc animated:YES completion:nil];
    });
}

@end

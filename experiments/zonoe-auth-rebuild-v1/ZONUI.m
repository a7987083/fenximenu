#import "ZONUI.h"

@interface ZONOverlayWindow : UIWindow
@end

@implementation ZONOverlayWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    UIViewController *root = self.rootViewController;
    if (!root.presentedViewController && hit == root.view) return nil;
    return hit;
}
@end

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
@property(nonatomic,strong) ZONOverlayWindow *overlayWindow;
@property(nonatomic,strong) UIViewController *overlayRoot;
@property(nonatomic,strong) UIButton *button;
@property(nonatomic,weak) UIWindow *previousKeyWindow;
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

- (UIWindowScene *)foregroundScene API_AVAILABLE(ios(13.0)) {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        if (scene.activationState == UISceneActivationStateForegroundActive) return (UIWindowScene *)scene;
    }
    return nil;
}

- (UIWindow *)currentHostKeyWindow {
    if (@available(iOS 13.0, *)) {
        UIWindowScene *scene = [self foregroundScene];
        for (UIWindow *w in scene.windows) {
            if (w == self.overlayWindow) continue;
            if (w.isKeyWindow && !w.hidden && w.rootViewController) return w;
        }
        for (UIWindow *w in scene.windows) {
            if (w == self.overlayWindow) continue;
            if (!w.hidden && w.alpha > 0.01 && w.windowLevel == UIWindowLevelNormal && w.rootViewController) return w;
        }
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    UIWindow *key = UIApplication.sharedApplication.keyWindow;
#pragma clang diagnostic pop
    if (key != self.overlayWindow) return key;
    return nil;
}

- (void)ensureOverlayWindow {
    if (self.overlayWindow) return;

    ZONOverlayWindow *window = nil;
    if (@available(iOS 13.0, *)) {
        UIWindowScene *scene = [self foregroundScene];
        if (scene) {
            window = [[ZONOverlayWindow alloc] initWithWindowScene:scene];
            window.frame = scene.coordinateSpace.bounds;
        }
    }
    if (!window) window = [[ZONOverlayWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];

    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = UIColor.clearColor;
    root.view.userInteractionEnabled = YES;

    window.rootViewController = root;
    window.backgroundColor = UIColor.clearColor;
    window.windowLevel = UIWindowLevelStatusBar + 1.0;
    window.hidden = NO;

    self.overlayWindow = window;
    self.overlayRoot = root;
}

- (void)installFloatingButton {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self ensureOverlayWindow];
        if (self.button.superview) return;

        UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
        button.frame = CGRectMake(16, 150, 56, 56);
        button.layer.cornerRadius = 28.0;
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

        [self.overlayRoot.view addSubview:button];
        self.button = button;
    });
}

- (void)handlePan:(UIPanGestureRecognizer *)pan {
    UIView *view = pan.view;
    UIView *host = self.overlayRoot.view;
    if (!view || !host) return;

    if (pan.state == UIGestureRecognizerStateBegan) self.panStartCenter = view.center;

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
        CGPoint target = view.center;
        target.x = (target.x < CGRectGetMidX(host.bounds)) ? minX : maxX;
        [UIView animateWithDuration:0.22 animations:^{ view.center = target; }];
    }
}

- (void)tap {
    if (self.presentingInput) return;
    if (self.tapHandler) self.tapHandler();
}

- (void)restoreHostKeyWindowSoon {
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIWindow *host = weakSelf.previousKeyWindow;
        if (host && !host.hidden) [host makeKeyWindow];
        weakSelf.previousKeyWindow = nil;
    });
}

- (void)presentInputAlert:(UIAlertController *)alert {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self ensureOverlayWindow];
        if (self.overlayRoot.presentedViewController || self.presentingInput) return;
        self.previousKeyWindow = [self currentHostKeyWindow];
        self.presentingInput = YES;
        [self.overlayWindow makeKeyAndVisible];
        [self.overlayRoot presentViewController:alert animated:YES completion:nil];
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
        [weakSelf restoreHostKeyWindowSoon];
        if (completion) completion(nil);
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"下一步" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x) {
        NSString *s = [a.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        weakSelf.presentingInput = NO;
        [weakSelf restoreHostKeyWindowSoon];
        if (completion) completion(s.length ? s : nil);
    }]];
    [self presentInputAlert:a];
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
        [weakSelf restoreHostKeyWindowSoon];
        if (completion) completion(nil);
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"确认激活" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x) {
        NSString *s = [a.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        weakSelf.presentingInput = NO;
        [weakSelf restoreHostKeyWindowSoon];
        if (completion) completion(s.length ? s : nil);
    }]];
    [self presentInputAlert:a];
}

- (void)showInfo:(NSDictionary *)info title:(NSString *)title {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self ensureOverlayWindow];
        if (self.overlayRoot.presentedViewController) return;

        NSData *data = [NSJSONSerialization dataWithJSONObject:info ?: @{} options:(NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys) error:nil];
        NSString *text = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : (info.description ?: @"");
        ZONInfoViewController *vc = [ZONInfoViewController new];
        vc.zonTitle = title ?: @"授权信息";
        vc.zonText = text;
        vc.modalPresentationStyle = UIModalPresentationPageSheet;

        self.previousKeyWindow = [self currentHostKeyWindow];
        [self.overlayWindow makeKeyAndVisible];
        [self.overlayRoot presentViewController:vc animated:YES completion:nil];
    });
}

@end

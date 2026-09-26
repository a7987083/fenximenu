#import "ZONUI.h"

@interface ZONUI ()
@property(nonatomic,strong) UIWindow *window;
@property(nonatomic,strong) UIButton *button;
@end

@implementation ZONUI

+ (instancetype)shared {
    static ZONUI *x;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ x = [ZONUI new]; });
    return x;
}

- (UIViewController *)topVC {
    UIWindow *w = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if (![s isKindOfClass:UIWindowScene.class] || s.activationState != UISceneActivationStateForegroundActive) continue;
            for (UIWindow *candidate in ((UIWindowScene *)s).windows) {
                if (candidate.isKeyWindow) { w = candidate; break; }
            }
            if (w) break;
        }
    }
    if (!w) w = UIApplication.sharedApplication.keyWindow;
    UIViewController *v = w.rootViewController;
    while (v.presentedViewController) v = v.presentedViewController;
    return v;
}

- (void)installFloatingButton {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.button) return;
        CGRect frame = CGRectMake(24, 160, 56, 56);
        self.window = [[UIWindow alloc] initWithFrame:frame];
        self.window.windowLevel = UIWindowLevelAlert + 10;
        self.window.backgroundColor = UIColor.clearColor;
        self.window.rootViewController = [UIViewController new];

        self.button = [UIButton buttonWithType:UIButtonTypeSystem];
        self.button.frame = self.window.bounds;
        self.button.layer.cornerRadius = 28;
        self.button.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.92];
        [self.button setTitle:@"ZN" forState:UIControlStateNormal];
        self.button.titleLabel.font = [UIFont boldSystemFontOfSize:18];
        [self.button addTarget:self action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
        [self.window.rootViewController.view addSubview:self.button];
        self.window.hidden = NO;
    });
}

- (void)tap {
    if (self.tapHandler) self.tapHandler();
}

- (void)requestUDID:(NSString *)prefill completion:(void (^)(NSString * _Nullable))completion {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"UDID" message:@"请输入设备 UDID" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.text = prefill ?: @"";
        t.placeholder = @"00008120-...";
        t.autocapitalizationType = UITextAutocapitalizationTypeNone;
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(__unused UIAlertAction *x) {
        completion(nil);
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"下一步" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x) {
        NSString *s = [a.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        completion(s.length ? s : nil);
    }]];
    [[self topVC] presentViewController:a animated:YES completion:nil];
}

- (void)requestCardWithCompletion:(void (^)(NSString * _Nullable))completion {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"卡密" message:@"请输入软件源卡密" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.placeholder = @"请输入卡密";
        t.autocapitalizationType = UITextAutocapitalizationTypeNone;
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(__unused UIAlertAction *x) {
        completion(nil);
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"确认激活" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x) {
        NSString *s = [a.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        completion(s.length ? s : nil);
    }]];
    [[self topVC] presentViewController:a animated:YES completion:nil];
}

- (void)showInfo:(NSDictionary *)info title:(NSString *)title {
    NSData *d = [NSJSONSerialization dataWithJSONObject:info ?: @{} options:NSJSONWritingPrettyPrinted error:nil];
    NSString *s = d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : info.description;
    UIAlertController *a = [UIAlertController alertControllerWithTitle:title ?: @"授权信息" message:s preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    [[self topVC] presentViewController:a animated:YES completion:nil];
}

@end

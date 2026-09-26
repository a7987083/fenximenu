#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import "ZONDylibConfig.h"
#import "ZONDylibVerify.h"

static NSString * const kZONLegacyBaseURL = @"https://app3.zonoeios.xyz";

@interface H5GGPassThroughWindow : UIWindow @end
@implementation H5GGPassThroughWindow
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *h = [super hitTest:p withEvent:e];
    UIView *r = self.rootViewController.view;
    return (h == self || h == r) ? nil : h;
}
@end

@interface H5GGCardAuthController : NSObject
@property(nonatomic,strong) H5GGPassThroughWindow *window;
@property(nonatomic,strong) UIButton *floatButton;
@property(nonatomic,strong) ZONDylibVerify *verifyClient;
@property(nonatomic,assign) BOOL busy;
@end

@implementation H5GGCardAuthController

- (NSString *)autoUDID {
    NSArray<NSString *> *keys = @[@"ZONUDID", @"udid", @"UDID", @"device_udid", @"deviceUDID"];
    NSDictionary *env = NSProcessInfo.processInfo.environment;
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    for (NSString *key in keys) {
        id v = env[key];
        if ([v isKindOfClass:NSString.class] && [v length] > 8) return v;
        v = [defaults objectForKey:key];
        if ([v isKindOfClass:NSString.class] && [v length] > 8) return v;
    }
    return @"";
}

- (UIViewController *)presenter {
    UIViewController *vc = self.window.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

- (void)setBusy:(BOOL)busy title:(NSString *)title {
    self.busy = busy;
    self.floatButton.enabled = !busy;
    [self.floatButton setTitle:(busy ? @"..." : (title.length ? title : @"ZN")) forState:UIControlStateNormal];
}

- (void)presentTitle:(NSString *)title message:(NSString *)message {
    UIViewController *vc = [self presenter];
    if (!vc) return;
    UIAlertController *a = [UIAlertController alertControllerWithTitle:title ?: @"授权" message:message ?: @"" preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
    [vc presentViewController:a animated:YES completion:nil];
}

- (NSString *)prettyJSON:(id)obj {
    if (!obj || obj == NSNull.null) return @"";
    if ([obj isKindOfClass:NSString.class]) return obj;
    if (![NSJSONSerialization isValidJSONObject:obj]) return [obj description] ?: @"";
    NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:NSJSONWritingPrettyPrinted error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : [obj description];
}

- (NSURL *)URLWithPath:(NSString *)path query:(NSDictionary<NSString *, NSString *> *)query {
    NSURLComponents *c = [NSURLComponents componentsWithString:[kZONLegacyBaseURL stringByAppendingString:path]];
    NSMutableArray<NSURLQueryItem *> *items = [NSMutableArray array];
    [query enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        (void)stop;
        [items addObject:[NSURLQueryItem queryItemWithName:key value:value ?: @""]];
    }];
    c.queryItems = items;
    return c.URL;
}

- (void)getJSON:(NSURL *)url completion:(void (^)(NSDictionary *json, NSError *error))completion {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:12.0];
    req.HTTPMethod = @"GET";
    [req setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    NSURLSessionDataTask *task = [NSURLSession.sharedSession dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        (void)response;
        if (error) { completion(nil, error); return; }
        if (!data.length) {
            completion(nil, [NSError errorWithDomain:@"ZONLegacy" code:-1 userInfo:@{NSLocalizedDescriptionKey:@"服务器返回空数据"}]);
            return;
        }
        NSError *jsonError = nil;
        id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (![obj isKindOfClass:NSDictionary.class]) {
            NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
            NSString *msg = raw.length ? [NSString stringWithFormat:@"服务器返回无法解析：%@", raw] : @"服务器返回不是 JSON 对象";
            completion(nil, jsonError ?: [NSError errorWithDomain:@"ZONLegacy" code:-2 userInfo:@{NSLocalizedDescriptionKey:msg}]);
            return;
        }
        completion((NSDictionary *)obj, nil);
    }];
    [task resume];
}

- (NSString *)formattedAuthorizedInfo:(ZONDylibVerifyResult *)r legacy:(NSDictionary *)legacy {
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    [lines addObject:@"授权状态：已激活"];

    NSString *legacyMsg = [legacy[@"msg"] isKindOfClass:NSString.class] ? legacy[@"msg"] : @"";
    if (legacyMsg.length) [lines addObject:[NSString stringWithFormat:@"旧授权：%@", legacyMsg]];

    if (r.accessLevel.length) [lines addObject:[NSString stringWithFormat:@"访问等级：%@", r.accessLevel]];
    if (r.code.length) [lines addObject:[NSString stringWithFormat:@"验证代码：%@", r.code]];
    if (r.action.length) [lines addObject:[NSString stringWithFormat:@"服务端动作：%@", r.action]];
    if (r.message.length) [lines addObject:[NSString stringWithFormat:@"服务端消息：%@", r.message]];
    if (r.token.length) [lines addObject:@"授权 Token：已下发"];
    if (r.isOfflineCache) [lines addObject:@"当前来源：离线授权缓存"];

    NSDictionary *legacyData = [legacy[@"data"] isKindOfClass:NSDictionary.class] ? legacy[@"data"] : @{};
    NSString *siteName = [legacyData[@"name"] isKindOfClass:NSString.class] ? legacyData[@"name"] : @"";
    if (siteName.length) [lines addObject:[NSString stringWithFormat:@"名称：%@", siteName]];
    NSString *legacyNotice = [legacyData[@"notice"] isKindOfClass:NSString.class] ? legacyData[@"notice"] : @"";
    if (legacyNotice.length) [lines addObject:[NSString stringWithFormat:@"\n公告：\n%@", legacyNotice]];

    NSString *notice = [self prettyJSON:r.notice];
    if (notice.length) [lines addObject:[NSString stringWithFormat:@"\n新版公告：\n%@", notice]];

    NSString *perms = [self prettyJSON:r.permissions];
    if (perms.length) [lines addObject:[NSString stringWithFormat:@"\n权限：\n%@", perms]];

    NSString *identity = [self prettyJSON:r.appIdentity];
    if (identity.length) [lines addObject:[NSString stringWithFormat:@"\nApp 身份：\n%@", identity]];

    NSString *update = [self prettyJSON:r.appUpdate];
    if (update.length) [lines addObject:[NSString stringWithFormat:@"\nApp 更新：\n%@", update]];

    return [lines componentsJoinedByString:@"\n"];
}

- (void)runNewVerifyWithUDID:(NSString *)udid legacy:(NSDictionary *)legacy {
    ZONDylibVerifyConfiguration *cfg = [ZONDylibConfig configurationWithUDIDProvider:^NSString *{ return udid; }];
    self.verifyClient = [[ZONDylibVerify alloc] initWithConfiguration:cfg];
    __weak typeof(self) weakSelf = self;
    [self.verifyClient verifyWithCompletion:^(ZONDylibVerifyResult *result) {
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            [self setBusy:NO title:@"ZN"];
            if (result.isAllowed) {
                [self presentTitle:@"授权信息" message:[self formattedAuthorizedInfo:result legacy:legacy ?: @{}]];
            } else {
                NSMutableString *m = [NSMutableString string];
                if (result.message.length) [m appendFormat:@"%@\n", result.message];
                if (result.code.length) [m appendFormat:@"code: %@\n", result.code];
                if (result.action.length) [m appendFormat:@"action: %@\n", result.action];
                NSString *notice = [self prettyJSON:result.notice];
                if (notice.length) [m appendFormat:@"\nnotice:\n%@", notice];
                [self presentTitle:@"Dylib 验证未通过" message:m.length ? m : @"服务器未允许当前 Dylib。"];
            }
        });
    }];
}

- (void)presentCardInputForUDID:(NSString *)udid reason:(NSString *)reason {
    [self setBusy:NO title:@"ZN"];
    UIViewController *vc = [self presenter];
    if (!vc) return;
    NSString *msg = reason.length ? reason : @"请输入卡密激活当前设备";
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"卡密激活" message:msg preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *f) {
        f.placeholder = @"请输入卡密";
        f.autocapitalizationType = UITextAutocapitalizationTypeNone;
        f.autocorrectionType = UITextAutocorrectionTypeNo;
        f.clearButtonMode = UITextFieldViewModeWhileEditing;
        f.secureTextEntry = NO;
    }];
    __weak typeof(self) weakSelf = self;
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"确认激活" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        NSString *card = [a.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (!card.length) {
            [self presentTitle:@"卡密激活" message:@"请输入卡密。"];
            return;
        }
        [self activateCard:card udid:udid];
    }]];
    [vc presentViewController:a animated:YES completion:nil];
}

- (void)activateCard:(NSString *)card udid:(NSString *)udid {
    if (self.busy) return;
    [self setBusy:YES title:nil];
    NSURL *url = [self URLWithPath:@"/index/app/list" query:@{@"udid":udid ?: @"", @"code":card ?: @""}];
    __weak typeof(self) weakSelf = self;
    [self getJSON:url completion:^(NSDictionary *json, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            if (error) {
                [self setBusy:NO title:@"ZN"];
                [self presentTitle:@"激活失败" message:error.localizedDescription ?: @"网络错误"];
                return;
            }
            NSString *msg = [json[@"msg"] isKindOfClass:NSString.class] ? json[@"msg"] : @"";
            BOOL success = ([msg rangeOfString:@"解锁成功"].location != NSNotFound || [msg.lowercaseString hasPrefix:@"ok"]);
            if (!success) {
                [self setBusy:NO title:@"ZN"];
                [self presentTitle:@"激活失败" message:msg.length ? msg : [self prettyJSON:json]];
                return;
            }
            [self checkLegacyAuthorizationForUDID:udid activationSuccessMessage:msg];
        });
    }];
}

- (void)checkLegacyAuthorizationForUDID:(NSString *)udid activationSuccessMessage:(NSString *)activationSuccessMessage {
    [self setBusy:YES title:nil];
    NSURL *url = [self URLWithPath:@"/index/index/dylib" query:@{@"udid":udid ?: @""}];
    __weak typeof(self) weakSelf = self;
    [self getJSON:url completion:^(NSDictionary *json, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            if (error) {
                [self setBusy:NO title:@"ZN"];
                [self presentTitle:@"授权检查失败" message:error.localizedDescription ?: @"网络错误"];
                return;
            }

            NSInteger code = [json[@"code"] respondsToSelector:@selector(integerValue)] ? [json[@"code"] integerValue] : 0;
            NSString *msg = [json[@"msg"] isKindOfClass:NSString.class] ? json[@"msg"] : @"";
            if (code == 1) {
                NSMutableDictionary *legacy = [json mutableCopy];
                if (activationSuccessMessage.length) legacy[@"activation_message"] = activationSuccessMessage;
                [self runNewVerifyWithUDID:udid legacy:legacy];
                return;
            }
            if (code == 2 || code == 3 || code == 0) {
                [self presentCardInputForUDID:udid reason:msg.length ? msg : @"当前设备尚未激活，请输入卡密。"];
                return;
            }
            [self setBusy:NO title:@"ZN"];
            [self presentTitle:(code == 666 ? @"设备已被限制" : @"授权检查") message:msg.length ? msg : [self prettyJSON:json]];
        });
    }];
}

- (void)floatTapped:(id)sender {
    (void)sender;
    if (self.busy) return;
    NSString *udid = [self autoUDID];
    if (udid.length <= 8) {
        [self presentTitle:@"无法验证" message:@"没有取得 UDID。请确认当前注入环境已经提供 UDID。"];
        return;
    }
    [self checkLegacyAuthorizationForUDID:udid activationSuccessMessage:nil];
}

- (void)drag:(UIPanGestureRecognizer *)p {
    if (p.state != UIGestureRecognizerStateBegan && p.state != UIGestureRecognizerStateChanged) return;
    CGPoint t = [p translationInView:self.window];
    CGPoint c = self.floatButton.center;
    c.x += t.x; c.y += t.y;
    CGRect b = self.window.bounds;
    c.x = MAX(30.0, MIN(CGRectGetWidth(b)-30.0, c.x));
    c.y = MAX(50.0, MIN(CGRectGetHeight(b)-50.0, c.y));
    self.floatButton.center = c;
    [p setTranslation:CGPointZero inView:self.window];
}

- (void)install {
    if (self.window || !UIApplication.sharedApplication) return;
    CGRect s = UIScreen.mainScreen.bounds;
    if (CGRectIsEmpty(s)) return;

    H5GGPassThroughWindow *w = [[H5GGPassThroughWindow alloc] initWithFrame:s];
    UIViewController *vc = [UIViewController new];
    vc.view = [[UIView alloc] initWithFrame:s];
    vc.view.backgroundColor = UIColor.clearColor;
    w.rootViewController = vc;
    w.windowLevel = UIWindowLevelAlert - 1.0;
    w.backgroundColor = UIColor.clearColor;
    w.hidden = NO;
    self.window = w;

    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    b.frame = CGRectMake(CGRectGetWidth(s)-72.0, CGRectGetHeight(s)*0.35, 54.0, 54.0);
    b.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.96];
    b.layer.cornerRadius = 27.0;
    b.layer.borderWidth = 1.5;
    b.layer.borderColor = [UIColor colorWithRed:0.2 green:0.45 blue:1 alpha:1].CGColor;
    [b setTitle:@"ZN" forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [b addTarget:self action:@selector(floatTapped:) forControlEvents:UIControlEventTouchUpInside];
    [b addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)]];
    [w addSubview:b];
    self.floatButton = b;
}
@end

static H5GGCardAuthController *gZONCardAuth;
__attribute__((constructor)) static void H5GGCardAuthInit(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        gZONCardAuth = [H5GGCardAuthController new];
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(__unused NSNotification *n) {
            [gZONCardAuth install];
        }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [gZONCardAuth install];
        });
    });
}

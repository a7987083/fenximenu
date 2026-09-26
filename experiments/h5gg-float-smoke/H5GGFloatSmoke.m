#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

static void H5GGPreflightAnchor(void) {}

static NSString *H5GGAppMachOUUID(void) {
    const struct mach_header *header = _dyld_get_image_header(0);
    if (!header) return @"";
    BOOL is64 = (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64);
    uintptr_t cursor = (uintptr_t)header + (is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *command = (const struct load_command *)cursor;
        if (!command || command->cmdsize < sizeof(struct load_command)) break;
        if ((command->cmd & 0x7fffffff) == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
            const uint8_t *u = ((const struct uuid_command *)command)->uuid;
            return [NSString stringWithFormat:@"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]];
        }
        cursor += command->cmdsize;
    }
    return @"";
}

static NSString *H5GGCurrentDylibSHA256(void) {
    Dl_info info;
    if (dladdr((const void *)&H5GGPreflightAnchor, &info) == 0 || !info.dli_fname) return @"";
    NSString *path = [NSString stringWithUTF8String:info.dli_fname];
    NSInputStream *stream = [NSInputStream inputStreamWithFileAtPath:path];
    [stream open];
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    uint8_t buffer[64 * 1024];
    NSInteger read = 0;
    while ((read = [stream read:buffer maxLength:sizeof(buffer)]) > 0) CC_SHA256_Update(&ctx, buffer, (CC_LONG)read);
    [stream close];
    if (read < 0) return @"";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &ctx);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

@interface H5GGPassThroughWindow : UIWindow
@end
@implementation H5GGPassThroughWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    UIView *root = self.rootViewController.view;
    if (hit == self || hit == root) return nil;
    return hit;
}
@end

@interface H5GGFloatSmokeController : NSObject <UITextFieldDelegate>
@property(nonatomic,strong) H5GGPassThroughWindow *window;
@property(nonatomic,strong) UIButton *floatButton;
@property(nonatomic,strong) UIView *menu;
@property(nonatomic,strong) UITextField *udidField;
@property(nonatomic,strong) UITextView *resultView;
@property(nonatomic,assign) BOOL shown;
@end

@implementation H5GGFloatSmokeController

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

- (void)install {
    if (self.window || !UIApplication.sharedApplication) return;
    CGRect screen = UIScreen.mainScreen.bounds;
    if (CGRectIsEmpty(screen)) return;

    H5GGPassThroughWindow *window = [[H5GGPassThroughWindow alloc] initWithFrame:screen];
    UIViewController *vc = [UIViewController new];
    vc.view = [[UIView alloc] initWithFrame:screen];
    vc.view.backgroundColor = UIColor.clearColor;
    window.rootViewController = vc;
    window.windowLevel = UIWindowLevelAlert - 1.0;
    window.backgroundColor = UIColor.clearColor;
    window.hidden = NO;
    self.window = window;

    UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
    button.frame = CGRectMake(CGRectGetWidth(screen) - 72.0, CGRectGetHeight(screen) * 0.35, 54.0, 54.0);
    button.backgroundColor = [UIColor colorWithRed:0.08 green:0.55 blue:1.0 alpha:0.95];
    button.layer.cornerRadius = 27.0;
    [button setTitle:@"H5" forState:UIControlStateNormal];
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [button addTarget:self action:@selector(toggle:) forControlEvents:UIControlEventTouchUpInside];
    [button addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)]];
    [window addSubview:button];
    self.floatButton = button;

    CGFloat width = MIN(380.0, CGRectGetWidth(screen) - 24.0);
    CGFloat height = MIN(500.0, CGRectGetHeight(screen) - 80.0);
    UIView *menu = [[UIView alloc] initWithFrame:CGRectMake((CGRectGetWidth(screen)-width)/2.0, (CGRectGetHeight(screen)-height)/2.0, width, height)];
    menu.backgroundColor = [UIColor colorWithWhite:0.07 alpha:0.96];
    menu.layer.cornerRadius = 18.0;
    menu.layer.masksToBounds = YES;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(16, 14, width-32, 30)];
    title.text = @"H5GG Verify Preflight V2";
    title.textColor = UIColor.whiteColor;
    title.textAlignment = NSTextAlignmentCenter;
    title.font = [UIFont boldSystemFontOfSize:18];
    [menu addSubview:title];

    UITextField *udid = [[UITextField alloc] initWithFrame:CGRectMake(16, 58, width-32, 42)];
    udid.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1.0];
    udid.textColor = UIColor.whiteColor;
    udid.placeholder = @"UDID（自动获取不到时手动输入）";
    udid.attributedPlaceholder = [[NSAttributedString alloc] initWithString:udid.placeholder attributes:@{NSForegroundColorAttributeName:[UIColor colorWithWhite:0.55 alpha:1.0]}];
    udid.autocapitalizationType = UITextAutocapitalizationTypeNone;
    udid.autocorrectionType = UITextAutocorrectionTypeNo;
    udid.clearButtonMode = UITextFieldViewModeWhileEditing;
    udid.layer.cornerRadius = 8.0;
    udid.leftView = [[UIView alloc] initWithFrame:CGRectMake(0,0,10,1)];
    udid.leftViewMode = UITextFieldViewModeAlways;
    udid.delegate = self;
    udid.text = [self autoUDID];
    [menu addSubview:udid];
    self.udidField = udid;

    UIButton *inspect = [UIButton buttonWithType:UIButtonTypeSystem];
    inspect.frame = CGRectMake(16, 112, width-32, 42);
    inspect.backgroundColor = [UIColor colorWithRed:0.10 green:0.48 blue:0.96 alpha:1.0];
    inspect.layer.cornerRadius = 9.0;
    [inspect setTitle:@"Inspect Verify Inputs" forState:UIControlStateNormal];
    [inspect setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [inspect addTarget:self action:@selector(inspect:) forControlEvents:UIControlEventTouchUpInside];
    [menu addSubview:inspect];

    UITextView *result = [[UITextView alloc] initWithFrame:CGRectMake(16, 166, width-32, height-226)];
    result.backgroundColor = [UIColor colorWithWhite:0.12 alpha:1.0];
    result.textColor = UIColor.whiteColor;
    result.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    result.editable = NO;
    result.layer.cornerRadius = 8.0;
    result.text = @"Ready.\n输入/确认 UDID 后点击 Inspect。";
    [menu addSubview:result];
    self.resultView = result;

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.frame = CGRectMake((width-130.0)/2.0, height-48.0, 130.0, 36.0);
    [close setTitle:@"Close" forState:UIControlStateNormal];
    [close setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [close addTarget:self action:@selector(close:) forControlEvents:UIControlEventTouchUpInside];
    [menu addSubview:close];

    menu.hidden = YES;
    [window addSubview:menu];
    self.menu = menu;
}

- (void)inspect:(id)sender {
    (void)sender;
    NSString *udid = [self.udidField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (udid.length > 8) [NSUserDefaults.standardUserDefaults setObject:udid forKey:@"ZONUDID"];
    [self.udidField resignFirstResponder];

    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier ?: @"";
    NSString *exe = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleExecutable"] ?: @"";
    NSString *version = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSString *build = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";
    NSString *uuid = H5GGAppMachOUUID();
    NSString *sha = H5GGCurrentDylibSHA256();
    BOOL ready = udid.length > 8 && bundleID.length > 0 && exe.length > 0 && uuid.length > 0 && sha.length == 64;

    self.resultView.text = [NSString stringWithFormat:@"verify_inputs_ready=%@\n\nudid=%@\nbundle_id=%@\nexecutable=%@\napp_version=%@\napp_build=%@\napp_macho_uuid=%@\ndylib_sha256=%@\n\ndylib_key=zonoe.main\ndylib_version=1\nprotocol_version=2",
                            ready ? @"true" : @"false",
                            udid.length ? udid : @"<missing>", bundleID, exe, version, build,
                            uuid.length ? uuid : @"<missing>", sha.length ? sha : @"<missing>"];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField { [textField resignFirstResponder]; return YES; }
- (void)toggle:(id)sender { (void)sender; self.shown = !self.shown; self.menu.hidden = !self.shown; }
- (void)close:(id)sender { (void)sender; self.shown = NO; self.menu.hidden = YES; [self.udidField resignFirstResponder]; }
- (void)drag:(UIPanGestureRecognizer *)pan {
    if (pan.state != UIGestureRecognizerStateBegan && pan.state != UIGestureRecognizerStateChanged) return;
    CGPoint t = [pan translationInView:self.window];
    CGPoint c = self.floatButton.center;
    c.x += t.x; c.y += t.y;
    CGRect b = self.window.bounds;
    c.x = MAX(30.0, MIN(CGRectGetWidth(b)-30.0, c.x));
    c.y = MAX(50.0, MIN(CGRectGetHeight(b)-50.0, c.y));
    self.floatButton.center = c;
    [pan setTranslation:CGPointZero inView:self.window];
}
@end

static H5GGFloatSmokeController *gH5GGFloatSmokeController;
__attribute__((constructor))
static void H5GGFloatSmokeInit(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        gH5GGFloatSmokeController = [H5GGFloatSmokeController new];
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(__unused NSNotification *note) {
            [gH5GGFloatSmokeController install];
        }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ [gH5GGFloatSmokeController install]; });
    });
}

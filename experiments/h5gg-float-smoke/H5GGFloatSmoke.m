#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

static NSString * const kZONCardService = @"com.zonoe.h5gg.card";
static NSString * const kZONCardAccount = @"zonoe.main";
static void H5GGV3Anchor(void) {}

static NSString *ZONKeychainCard(void) {
    NSDictionary *q = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecAttrService:kZONCardService,
                        (__bridge id)kSecAttrAccount:kZONCardAccount,
                        (__bridge id)kSecReturnData:@YES,
                        (__bridge id)kSecMatchLimit:(__bridge id)kSecMatchLimitOne};
    CFTypeRef out = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (s != errSecSuccess || !out) return @"";
    NSData *d = CFBridgingRelease(out);
    return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: @"";
}

static BOOL ZONSaveCard(NSString *card) {
    NSData *d = [card dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *base = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                           (__bridge id)kSecAttrService:kZONCardService,
                           (__bridge id)kSecAttrAccount:kZONCardAccount};
    SecItemDelete((__bridge CFDictionaryRef)base);
    if (card.length == 0) return YES;
    NSMutableDictionary *add = [base mutableCopy];
    add[(__bridge id)kSecValueData] = d;
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    return SecItemAdd((__bridge CFDictionaryRef)add, NULL) == errSecSuccess;
}

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
    if (dladdr((const void *)&H5GGV3Anchor, &info) == 0 || !info.dli_fname) return @"";
    NSInputStream *stream = [NSInputStream inputStreamWithFileAtPath:[NSString stringWithUTF8String:info.dli_fname]];
    [stream open]; CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx);
    uint8_t buf[65536]; NSInteger n=0;
    while ((n=[stream read:buf maxLength:sizeof(buf)])>0) CC_SHA256_Update(&ctx,buf,(CC_LONG)n);
    [stream close]; if (n<0) return @"";
    unsigned char dig[CC_SHA256_DIGEST_LENGTH]; CC_SHA256_Final(dig,&ctx);
    NSMutableString *hex=[NSMutableString stringWithCapacity:64];
    for(NSUInteger i=0;i<CC_SHA256_DIGEST_LENGTH;i++) [hex appendFormat:@"%02x",dig[i]];
    return hex;
}

@interface H5GGPassThroughWindow : UIWindow @end
@implementation H5GGPassThroughWindow
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e { UIView *h=[super hitTest:p withEvent:e]; UIView *r=self.rootViewController.view; return (h==self||h==r)?nil:h; }
@end

@interface H5GGCardV3Controller : NSObject <UITextFieldDelegate>
@property(nonatomic,strong) H5GGPassThroughWindow *window;
@property(nonatomic,strong) UIButton *floatButton;
@property(nonatomic,strong) UIView *menu;
@property(nonatomic,strong) UITextField *cardField;
@property(nonatomic,strong) UITextField *udidField;
@property(nonatomic,strong) UITextView *resultView;
@property(nonatomic,assign) BOOL shown;
@property(nonatomic,assign) BOOL prompted;
@end

@implementation H5GGCardV3Controller
- (NSString *)autoUDID {
    NSArray *keys=@[@"ZONUDID",@"udid",@"UDID",@"device_udid",@"deviceUDID"];
    NSDictionary *env=NSProcessInfo.processInfo.environment; NSUserDefaults *d=NSUserDefaults.standardUserDefaults;
    for(NSString *k in keys){ id v=env[k]; if([v isKindOfClass:NSString.class]&&[v length]>8)return v; v=[d objectForKey:k]; if([v isKindOfClass:NSString.class]&&[v length]>8)return v; }
    return @"";
}
- (void)showCardPromptIfNeeded {
    if(self.prompted) return; self.prompted=YES;
    NSString *saved=ZONKeychainCard(); if(saved.length>0){ self.cardField.text=saved; return; }
    UIViewController *presenter=self.window.rootViewController;
    UIAlertController *a=[UIAlertController alertControllerWithTitle:@"请输入卡密" message:@"首次使用需要填写卡密。当前版本先保存到本机 Keychain；服务端卡密字段尚未接入。" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *f){ f.placeholder=@"卡密"; f.secureTextEntry=YES; f.autocapitalizationType=UITextAutocapitalizationTypeNone; f.autocorrectionType=UITextAutocorrectionTypeNo; }];
    __weak typeof(self) w=self;
    [a addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){
        NSString *card=[a.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        BOOL ok=ZONSaveCard(card); w.cardField.text=card; w.resultView.text=ok?@"card_saved=true\nbackend_card_field_supported=false":@"card_saved=false\nkeychain_error=true";
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"稍后" style:UIAlertActionStyleCancel handler:nil]];
    [presenter presentViewController:a animated:YES completion:nil];
}
- (void)install {
    if(self.window||!UIApplication.sharedApplication)return; CGRect s=UIScreen.mainScreen.bounds; if(CGRectIsEmpty(s))return;
    self.window=[[H5GGPassThroughWindow alloc] initWithFrame:s]; UIViewController *vc=[UIViewController new]; vc.view=[[UIView alloc] initWithFrame:s]; vc.view.backgroundColor=UIColor.clearColor; self.window.rootViewController=vc; self.window.windowLevel=UIWindowLevelAlert-1; self.window.backgroundColor=UIColor.clearColor; self.window.hidden=NO;
    UIButton *b=[UIButton buttonWithType:UIButtonTypeCustom]; b.frame=CGRectMake(CGRectGetWidth(s)-72,CGRectGetHeight(s)*0.35,54,54); b.backgroundColor=[UIColor colorWithWhite:0.08 alpha:0.96]; b.layer.cornerRadius=27; b.layer.borderWidth=1.5; b.layer.borderColor=[UIColor colorWithRed:.2 green:.45 blue:1 alpha:1].CGColor; [b setTitle:@"ZN" forState:UIControlStateNormal]; [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal]; [b addTarget:self action:@selector(toggle:) forControlEvents:UIControlEventTouchUpInside]; [b addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)]]; [self.window addSubview:b]; self.floatButton=b;
    CGFloat w=MIN(390.0,CGRectGetWidth(s)-24), h=MIN(570.0,CGRectGetHeight(s)-70); UIView *m=[[UIView alloc] initWithFrame:CGRectMake((CGRectGetWidth(s)-w)/2,(CGRectGetHeight(s)-h)/2,w,h)]; m.backgroundColor=[UIColor colorWithWhite:.06 alpha:.97]; m.layer.cornerRadius=18; m.layer.masksToBounds=YES;
    UILabel *t=[[UILabel alloc] initWithFrame:CGRectMake(16,12,w-32,32)]; t.text=@"H5GG Card Entry V3"; t.textColor=UIColor.whiteColor; t.textAlignment=NSTextAlignmentCenter; t.font=[UIFont boldSystemFontOfSize:18]; [m addSubview:t];
    UITextField *card=[[UITextField alloc] initWithFrame:CGRectMake(16,56,w-32,42)]; card.backgroundColor=[UIColor colorWithWhite:.14 alpha:1]; card.textColor=UIColor.whiteColor; card.placeholder=@"卡密"; card.secureTextEntry=YES; card.layer.cornerRadius=8; card.leftView=[[UIView alloc] initWithFrame:CGRectMake(0,0,10,1)]; card.leftViewMode=UITextFieldViewModeAlways; card.clearButtonMode=UITextFieldViewModeWhileEditing; card.autocapitalizationType=UITextAutocapitalizationTypeNone; card.autocorrectionType=UITextAutocorrectionTypeNo; card.delegate=self; card.text=ZONKeychainCard(); [m addSubview:card]; self.cardField=card;
    UIButton *save=[UIButton buttonWithType:UIButtonTypeSystem]; save.frame=CGRectMake(16,108,w-32,40); save.backgroundColor=[UIColor colorWithRed:.1 green:.48 blue:.96 alpha:1]; save.layer.cornerRadius=8; [save setTitle:@"保存卡密到 Keychain" forState:UIControlStateNormal]; [save setTitleColor:UIColor.whiteColor forState:UIControlStateNormal]; [save addTarget:self action:@selector(saveCard:) forControlEvents:UIControlEventTouchUpInside]; [m addSubview:save];
    UITextField *udid=[[UITextField alloc] initWithFrame:CGRectMake(16,160,w-32,42)]; udid.backgroundColor=[UIColor colorWithWhite:.14 alpha:1]; udid.textColor=UIColor.whiteColor; udid.placeholder=@"UDID"; udid.layer.cornerRadius=8; udid.leftView=[[UIView alloc] initWithFrame:CGRectMake(0,0,10,1)]; udid.leftViewMode=UITextFieldViewModeAlways; udid.autocapitalizationType=UITextAutocapitalizationTypeNone; udid.autocorrectionType=UITextAutocorrectionTypeNo; udid.delegate=self; udid.text=[self autoUDID]; [m addSubview:udid]; self.udidField=udid;
    UIButton *inspect=[UIButton buttonWithType:UIButtonTypeSystem]; inspect.frame=CGRectMake(16,212,w-32,40); inspect.backgroundColor=[UIColor colorWithRed:.16 green:.38 blue:.86 alpha:1]; inspect.layer.cornerRadius=8; [inspect setTitle:@"Inspect Verify Inputs" forState:UIControlStateNormal]; [inspect setTitleColor:UIColor.whiteColor forState:UIControlStateNormal]; [inspect addTarget:self action:@selector(inspect:) forControlEvents:UIControlEventTouchUpInside]; [m addSubview:inspect];
    UITextView *r=[[UITextView alloc] initWithFrame:CGRectMake(16,264,w-32,h-324)]; r.backgroundColor=[UIColor colorWithWhite:.11 alpha:1]; r.textColor=UIColor.whiteColor; r.font=[UIFont monospacedSystemFontOfSize:10.5 weight:UIFontWeightRegular]; r.editable=NO; r.layer.cornerRadius=8; r.text=@"Ready.\ncard_backend_supported=false"; [m addSubview:r]; self.resultView=r;
    UIButton *close=[UIButton buttonWithType:UIButtonTypeSystem]; close.frame=CGRectMake((w-130)/2,h-48,130,36); [close setTitle:@"Close" forState:UIControlStateNormal]; [close setTitleColor:UIColor.whiteColor forState:UIControlStateNormal]; [close addTarget:self action:@selector(close:) forControlEvents:UIControlEventTouchUpInside]; [m addSubview:close];
    m.hidden=YES; [self.window addSubview:m]; self.menu=m;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.45*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ [self showCardPromptIfNeeded]; });
}
- (void)saveCard:(id)x { (void)x; NSString *c=[self.cardField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]; BOOL ok=ZONSaveCard(c); [self.cardField resignFirstResponder]; self.resultView.text=[NSString stringWithFormat:@"card_saved=%@\ncard_present=%@\ncard_length=%lu\nbackend_card_field_supported=false",ok?@"true":@"false",c.length?@"true":@"false",(unsigned long)c.length]; }
- (void)inspect:(id)x { (void)x; NSString *c=[self.cardField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]; NSString *u=[self.udidField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]; if(u.length>8)[NSUserDefaults.standardUserDefaults setObject:u forKey:@"ZONUDID"];
    NSString *bid=NSBundle.mainBundle.bundleIdentifier?:@"", *exe=[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleExecutable"]?:@"", *ver=[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"]?:@"", *build=[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"]?:@"", *uuid=H5GGAppMachOUUID(), *sha=H5GGCurrentDylibSHA256(); BOOL ready=c.length>0&&u.length>8&&bid.length&&exe.length&&uuid.length&&sha.length==64;
    self.resultView.text=[NSString stringWithFormat:@"verify_inputs_ready=%@\ncard_present=%@\ncard_length=%lu\nbackend_card_field_supported=false\n\nudid=%@\nbundle_id=%@\nexecutable=%@\napp_version=%@\napp_build=%@\napp_macho_uuid=%@\ndylib_sha256=%@\n\ndylib_key=zonoe.main\nprotocol_version=2",ready?@"true":@"false",c.length?@"true":@"false",(unsigned long)c.length,u.length?u:@"<missing>",bid,exe,ver,build,uuid.length?uuid:@"<missing>",sha.length?sha:@"<missing>"];
}
- (BOOL)textFieldShouldReturn:(UITextField *)f{[f resignFirstResponder];return YES;}
- (void)toggle:(id)x{(void)x;self.shown=!self.shown;self.menu.hidden=!self.shown;}
- (void)close:(id)x{(void)x;self.shown=NO;self.menu.hidden=YES;[self.cardField resignFirstResponder];[self.udidField resignFirstResponder];}
- (void)drag:(UIPanGestureRecognizer *)p{if(p.state!=UIGestureRecognizerStateBegan&&p.state!=UIGestureRecognizerStateChanged)return;CGPoint t=[p translationInView:self.window],c=self.floatButton.center;c.x+=t.x;c.y+=t.y;CGRect b=self.window.bounds;c.x=MAX(30,MIN(CGRectGetWidth(b)-30,c.x));c.y=MAX(50,MIN(CGRectGetHeight(b)-50,c.y));self.floatButton.center=c;[p setTranslation:CGPointZero inView:self.window];}
@end

static H5GGCardV3Controller *gV3;
__attribute__((constructor)) static void H5GGCardV3Init(void){dispatch_async(dispatch_get_main_queue(),^{gV3=[H5GGCardV3Controller new];[[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(__unused NSNotification *n){[gV3 install];}];dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.0*NSEC_PER_SEC)),dispatch_get_main_queue(),^{[gV3 install];});});}

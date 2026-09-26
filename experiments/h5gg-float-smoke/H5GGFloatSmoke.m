#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import "ZONDylibConfig.h"
#import "ZONDylibVerify.h"

@interface H5GGPassThroughWindow : UIWindow @end
@implementation H5GGPassThroughWindow
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *h=[super hitTest:p withEvent:e];
    UIView *r=self.rootViewController.view;
    return (h==self||h==r)?nil:h;
}
@end

@interface H5GGServerVerifyController : NSObject
@property(nonatomic,strong) H5GGPassThroughWindow *window;
@property(nonatomic,strong) UIButton *floatButton;
@property(nonatomic,strong) ZONDylibVerify *verifyClient;
@property(nonatomic,assign) BOOL verifying;
@end

@implementation H5GGServerVerifyController

- (NSString *)autoUDID {
    NSArray<NSString *> *keys=@[@"ZONUDID",@"udid",@"UDID",@"device_udid",@"deviceUDID"];
    NSDictionary *env=NSProcessInfo.processInfo.environment;
    NSUserDefaults *defaults=NSUserDefaults.standardUserDefaults;
    for(NSString *key in keys){
        id v=env[key];
        if([v isKindOfClass:NSString.class]&&[v length]>8)return v;
        v=[defaults objectForKey:key];
        if([v isKindOfClass:NSString.class]&&[v length]>8)return v;
    }
    return @"";
}

- (UIViewController *)presenter {
    UIViewController *vc=self.window.rootViewController;
    while(vc.presentedViewController) vc=vc.presentedViewController;
    return vc;
}

- (void)presentTitle:(NSString *)title message:(NSString *)message {
    UIViewController *vc=[self presenter];
    if(!vc)return;
    UIAlertController *a=[UIAlertController alertControllerWithTitle:title?:@"服务器验证" message:message?:@"" preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
    [vc presentViewController:a animated:YES completion:nil];
}

- (NSString *)prettyJSON:(NSDictionary *)obj {
    if(!obj.count)return @"";
    NSData *d=[NSJSONSerialization dataWithJSONObject:obj options:NSJSONWritingPrettyPrinted error:nil];
    return d?[[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding]:obj.description;
}

- (NSString *)formattedResult:(ZONDylibVerifyResult *)r {
    NSMutableArray<NSString *> *lines=[NSMutableArray array];
    if(r.message.length)[lines addObject:r.message];
    [lines addObject:[NSString stringWithFormat:@"\nallowed: %@",r.isAllowed?@"true":@"false"]];
    if(r.code.length)[lines addObject:[NSString stringWithFormat:@"code: %@",r.code]];
    if(r.action.length)[lines addObject:[NSString stringWithFormat:@"action: %@",r.action]];
    if(r.accessLevel.length)[lines addObject:[NSString stringWithFormat:@"access_level: %@",r.accessLevel]];
    if(r.isOfflineCache)[lines addObject:@"offline_cache: true"];
    NSString *notice=[self prettyJSON:r.notice];
    if(notice.length)[lines addObject:[NSString stringWithFormat:@"\nnotice:\n%@",notice]];
    NSString *perms=[self prettyJSON:r.permissions];
    if(perms.length)[lines addObject:[NSString stringWithFormat:@"\npermissions:\n%@",perms]];
    return [lines componentsJoinedByString:@"\n"];
}

- (void)runServerVerify:(id)sender {
    (void)sender;
    if(self.verifying)return;
    NSString *udid=[self autoUDID];
    if(udid.length<=8){
        [self presentTitle:@"服务器验证" message:@"UDID unavailable\n请先确保当前注入环境能够提供 UDID。"];
        return;
    }
    self.verifying=YES;
    self.floatButton.enabled=NO;
    [self.floatButton setTitle:@"..." forState:UIControlStateNormal];

    ZONDylibVerifyConfiguration *cfg=[ZONDylibConfig configurationWithUDIDProvider:^NSString *{ return udid; }];
    self.verifyClient=[[ZONDylibVerify alloc] initWithConfiguration:cfg];
    __weak typeof(self) weakSelf=self;
    [self.verifyClient verifyWithCompletion:^(ZONDylibVerifyResult *result){
        dispatch_async(dispatch_get_main_queue(),^{
            __strong typeof(weakSelf) self=weakSelf;
            if(!self)return;
            self.verifying=NO;
            self.floatButton.enabled=YES;
            [self.floatButton setTitle:@"ZN" forState:UIControlStateNormal];
            [self presentTitle:(result.isAllowed?@"服务器验证通过":@"服务器验证") message:[self formattedResult:result]];
        });
    }];
}

- (void)drag:(UIPanGestureRecognizer *)p {
    if(p.state!=UIGestureRecognizerStateBegan&&p.state!=UIGestureRecognizerStateChanged)return;
    CGPoint t=[p translationInView:self.window];
    CGPoint c=self.floatButton.center; c.x+=t.x; c.y+=t.y;
    CGRect b=self.window.bounds;
    c.x=MAX(30.0,MIN(CGRectGetWidth(b)-30.0,c.x));
    c.y=MAX(50.0,MIN(CGRectGetHeight(b)-50.0,c.y));
    self.floatButton.center=c;
    [p setTranslation:CGPointZero inView:self.window];
}

- (void)install {
    if(self.window||!UIApplication.sharedApplication)return;
    CGRect s=UIScreen.mainScreen.bounds; if(CGRectIsEmpty(s))return;
    H5GGPassThroughWindow *w=[[H5GGPassThroughWindow alloc] initWithFrame:s];
    UIViewController *vc=[UIViewController new]; vc.view=[[UIView alloc] initWithFrame:s]; vc.view.backgroundColor=UIColor.clearColor;
    w.rootViewController=vc; w.windowLevel=UIWindowLevelAlert-1.0; w.backgroundColor=UIColor.clearColor; w.hidden=NO; self.window=w;

    UIButton *b=[UIButton buttonWithType:UIButtonTypeCustom];
    b.frame=CGRectMake(CGRectGetWidth(s)-72.0,CGRectGetHeight(s)*0.35,54.0,54.0);
    b.backgroundColor=[UIColor colorWithWhite:0.08 alpha:0.96];
    b.layer.cornerRadius=27.0; b.layer.borderWidth=1.5; b.layer.borderColor=[UIColor colorWithRed:0.2 green:0.45 blue:1 alpha:1].CGColor;
    [b setTitle:@"ZN" forState:UIControlStateNormal]; [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [b addTarget:self action:@selector(runServerVerify:) forControlEvents:UIControlEventTouchUpInside];
    [b addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)]];
    [w addSubview:b]; self.floatButton=b;
}
@end

static H5GGServerVerifyController *gZONServerVerify;
__attribute__((constructor)) static void H5GGServerVerifyInit(void){
    dispatch_async(dispatch_get_main_queue(),^{
        gZONServerVerify=[H5GGServerVerifyController new];
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(__unused NSNotification *n){ [gZONServerVerify install]; }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.0*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ [gZONServerVerify install]; });
    });
}

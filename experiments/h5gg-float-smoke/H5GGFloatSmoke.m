#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>

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

@interface H5GGFloatSmokeController : NSObject
@property(nonatomic,strong) H5GGPassThroughWindow *window;
@property(nonatomic,strong) UIButton *floatButton;
@property(nonatomic,strong) UIView *menu;
@property(nonatomic,assign) BOOL shown;
@end

@implementation H5GGFloatSmokeController

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
    button.layer.masksToBounds = YES;
    [button setTitle:@"H5" forState:UIControlStateNormal];
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [button addTarget:self action:@selector(toggle:) forControlEvents:UIControlEventTouchUpInside];
    [button addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)]];
    [window addSubview:button];
    self.floatButton = button;

    CGFloat width = MIN(340.0, CGRectGetWidth(screen) - 30.0);
    UIView *menu = [[UIView alloc] initWithFrame:CGRectMake((CGRectGetWidth(screen)-width)/2.0,
                                                            (CGRectGetHeight(screen)-230.0)/2.0,
                                                            width,
                                                            230.0)];
    menu.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.95];
    menu.layer.cornerRadius = 18.0;
    menu.layer.masksToBounds = YES;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(18, 18, width-36, 30)];
    title.text = @"H5GG Float Smoke Test";
    title.textColor = UIColor.whiteColor;
    title.textAlignment = NSTextAlignmentCenter;
    [menu addSubview:title];

    UILabel *info = [[UILabel alloc] initWithFrame:CGRectMake(20, 58, width-40, 100)];
    info.text = @"UIWindow: OK\nTouch passthrough: enabled\nDrag the H5 button\nTap Close to hide panel";
    info.textColor = UIColor.whiteColor;
    info.textAlignment = NSTextAlignmentCenter;
    info.numberOfLines = 0;
    [menu addSubview:info];

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.frame = CGRectMake((width-150.0)/2.0, 170.0, 150.0, 42.0);
    close.backgroundColor = [UIColor colorWithRed:0.15 green:0.45 blue:0.95 alpha:1.0];
    close.layer.cornerRadius = 10.0;
    [close setTitle:@"Close" forState:UIControlStateNormal];
    [close setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [close addTarget:self action:@selector(close:) forControlEvents:UIControlEventTouchUpInside];
    [menu addSubview:close];

    menu.hidden = YES;
    [window addSubview:menu];
    self.menu = menu;
}

- (void)toggle:(id)sender {
    (void)sender;
    self.shown = !self.shown;
    self.menu.hidden = !self.shown;
}

- (void)close:(id)sender {
    (void)sender;
    self.shown = NO;
    self.menu.hidden = YES;
}

- (void)drag:(UIPanGestureRecognizer *)pan {
    if (pan.state != UIGestureRecognizerStateBegan && pan.state != UIGestureRecognizerStateChanged) return;
    CGPoint t = [pan translationInView:self.window];
    CGPoint c = self.floatButton.center;
    c.x += t.x;
    c.y += t.y;
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
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                          object:nil
                                                           queue:NSOperationQueue.mainQueue
                                                      usingBlock:^(__unused NSNotification *note) {
            [gH5GGFloatSmokeController install];
        }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [gH5GGFloatSmokeController install];
        });
    });
}

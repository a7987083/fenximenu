#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "HFAMapBuildInfo.h"

extern "C" {
id HFACyberUICreatePanel(id hostWindow);
void HFACyberUIToggle(void);
void HFACyberUIBringToFront(id hostWindow);
}

static UIButton *gHFAMapButton = nil;

static UIWindow *HFAMapFindWindow(void) {
    UIApplication *app = UIApplication.sharedApplication;
    for (UIWindow *window in app.windows)
        if (window.isKeyWindow && !window.hidden && window.alpha > 0.0) return window;
    for (UIWindow *window in [app.windows reverseObjectEnumerator])
        if (!window.hidden && window.alpha > 0.0 && window.windowLevel == UIWindowLevelNormal) return window;
    return app.keyWindow;
}

@interface HFAMapFloatingTarget : NSObject
+ (instancetype)shared;
- (void)toggle;
@end

@implementation HFAMapFloatingTarget
+ (instancetype)shared {
    static HFAMapFloatingTarget *obj; static dispatch_once_t once;
    dispatch_once(&once, ^{ obj = [HFAMapFloatingTarget new]; });
    return obj;
}
- (void)toggle {
    UIWindow *window = HFAMapFindWindow();
    if (window) {
        HFACyberUICreatePanel(window);
        HFACyberUIBringToFront(window);
        HFACyberUIToggle();
    }
}
@end

static BOOL HFAMapInstallFloatingUI(void) {
    if (gHFAMapButton.superview) return YES;
    UIWindow *window = HFAMapFindWindow();
    if (!window) return NO;

    CGFloat y = MAX(80.0, window.safeAreaInsets.top + 36.0);
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.frame = CGRectMake(18.0, y, 56.0, 56.0);
    button.layer.cornerRadius = 28.0;
    button.layer.masksToBounds = YES;
    button.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.94];
    [button setTitle:@"HFA" forState:UIControlStateNormal];
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:15.0];
    button.layer.borderWidth = 1.0;
    button.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.35].CGColor;
    [button addTarget:[HFAMapFloatingTarget shared] action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];

    HFACyberUICreatePanel(window);
    [window addSubview:button];
    [window bringSubviewToFront:button];
    gHFAMapButton = button;
    NSLog(@"[HFAMap] %@ two-button UI installed", HFAMapDisplayVersion());
    return YES;
}

static void HFAMapScheduleInstall(NSUInteger attempt) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (HFAMapInstallFloatingUI()) return;
        if (attempt >= 20) return;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ HFAMapScheduleInstall(attempt + 1); });
    });
}

__attribute__((constructor)) static void HFAMapConstructor(void) {
    @autoreleasepool {
        NSLog(@"[HFAMap] %@ entry loaded", HFAMapDisplayVersion());
        HFAMapScheduleInstall(0);
    }
}

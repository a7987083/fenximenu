#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "HFAMapCore.h"

static UIView *gPanel; static UIButton *gButton; static UILabel *gStatus;
static UIWindow *ZPWindow(void) {
    UIApplication *app=UIApplication.sharedApplication;
    for(UIWindow *w in app.windows) if(w.isKeyWindow&&!w.hidden&&w.alpha>0) return w;
    for(UIWindow *w in [app.windows reverseObjectEnumerator]) if(!w.hidden&&w.alpha>0&&w.windowLevel==UIWindowLevelNormal) return w;
    return app.keyWindow;
}
@interface ZPTarget:NSObject
+ (instancetype)shared; - (void)toggle; - (void)scan;
@end
@implementation ZPTarget
+ (instancetype)shared { static id o; static dispatch_once_t once; dispatch_once(&once,^{o=[self new];}); return o; }
- (void)toggle { if(gPanel) gPanel.hidden=!gPanel.hidden; }
- (void)scan {
    gStatus.text=@"Analyzing loaded menu images…";
    HFAMapRunBoundedScan(^(NSDictionary *s){
        NSString *family=s[@"family"]?:@"unknown"; NSUInteger obs=[s[@"observations"] count];
        NSUInteger valid=[s[@"validatedFeatures"] count]; NSString *reason=s[@"reason"];
        gStatus.text = reason.length ? [NSString stringWithFormat:@"Stopped: %@\nSee ZPatchIG_Analysis.json",reason]
                                     : [NSString stringWithFormat:@"%@ — %@\n%lu observations / %lu validated",s[@"status"]?:@"?",family,(unsigned long)obs,(unsigned long)valid];
    });
}
@end
static BOOL ZPInstall(void) {
    if(gButton.superview) return YES; UIWindow *w=ZPWindow(); if(!w) return NO;
    CGFloat y=MAX(80.0,w.safeAreaInsets.top+36.0);
    UIButton *b=[UIButton buttonWithType:UIButtonTypeSystem]; b.frame=CGRectMake(18,y,60,60); b.layer.cornerRadius=30; b.backgroundColor=[UIColor colorWithWhite:.08 alpha:.93];
    [b setTitle:@"ZP" forState:UIControlStateNormal]; [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal]; b.titleLabel.font=[UIFont boldSystemFontOfSize:16];
    [b addTarget:[ZPTarget shared] action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    UIView *p=[[UIView alloc] initWithFrame:CGRectMake(86,y,270,190)]; p.backgroundColor=[UIColor colorWithWhite:.06 alpha:.95]; p.layer.cornerRadius=12; p.hidden=YES;
    UILabel *t=[[UILabel alloc] initWithFrame:CGRectMake(14,10,242,28)]; t.text=@"ZPatchIG v0.1.1 Analyzer"; t.textColor=UIColor.whiteColor; t.font=[UIFont boldSystemFontOfSize:17]; [p addSubview:t];
    UIButton *scan=[UIButton buttonWithType:UIButtonTypeSystem]; scan.frame=CGRectMake(14,48,242,42); scan.backgroundColor=[UIColor colorWithRed:.15 green:.34 blue:.70 alpha:1]; scan.layer.cornerRadius=8;
    [scan setTitle:@"Analyze Menu (5s)" forState:UIControlStateNormal]; [scan setTitleColor:UIColor.whiteColor forState:UIControlStateNormal]; [scan addTarget:[ZPTarget shared] action:@selector(scan) forControlEvents:UIControlEventTouchUpInside]; [p addSubview:scan];
    UILabel *st=[[UILabel alloc] initWithFrame:CGRectMake(14,100,242,72)]; st.text=@"Read-only v0.1.1.\nABI-first Legacy AP / C4M0 classification + 0xA0 descriptor evidence."; st.numberOfLines=3; st.textColor=[UIColor colorWithWhite:.88 alpha:1]; st.font=[UIFont systemFontOfSize:13]; [p addSubview:st]; gStatus=st;
    [w addSubview:p];[w addSubview:b];[w bringSubviewToFront:p];[w bringSubviewToFront:b]; gPanel=p;gButton=b; return YES;
}
static void ZPSchedule(NSUInteger attempt){ dispatch_async(dispatch_get_main_queue(),^{ if(ZPInstall())return; if(attempt>=20)return; dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ZPSchedule(attempt+1);});}); }
__attribute__((constructor)) static void ZPConstructor(void){ @autoreleasepool { NSLog(@"[ZPatchIG] v0.1.1 loaded"); ZPSchedule(0); } }

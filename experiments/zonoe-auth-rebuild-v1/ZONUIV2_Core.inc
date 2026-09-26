@interface ZONUI ()
@property(strong) ZONOverlayWindow *window;
@property(strong) UIViewController *root;
@property(strong) UIButton *button;
@property(weak) UIWindow *oldKey;
@property(assign) CGPoint dragStart;
@property(assign) BOOL presenting;
@property(copy) void (^lastCardCompletion)(NSString *);
@end

@implementation ZONUI
+ (instancetype)shared { static ZONUI *x; static dispatch_once_t once; dispatch_once(&once,^{x=[ZONUI new];}); return x; }
- (UIWindowScene *)scene API_AVAILABLE(ios(13.0)) { for(UIScene *s in UIApplication.sharedApplication.connectedScenes) if([s isKindOfClass:UIWindowScene.class]&&s.activationState==UISceneActivationStateForegroundActive) return (UIWindowScene*)s; return nil; }
- (UIWindow *)host { if(@available(iOS 13.0,*)) for(UIWindow *w in self.scene.windows) if(w!=self.window&&w.isKeyWindow&&!w.hidden) return w; return nil; }
- (void)ensureWindow { if(self.window)return; ZONOverlayWindow *w=nil; if(@available(iOS 13.0,*)){UIWindowScene *s=self.scene;if(s){w=[[ZONOverlayWindow alloc]initWithWindowScene:s];w.frame=s.coordinateSpace.bounds;}} if(!w)w=[[ZONOverlayWindow alloc]initWithFrame:UIScreen.mainScreen.bounds]; self.root=[UIViewController new];self.root.view.backgroundColor=UIColor.clearColor;w.rootViewController=self.root;w.backgroundColor=UIColor.clearColor;w.windowLevel=UIWindowLevelStatusBar+1;w.hidden=NO;self.window=w; }
- (void)installFloatingButton { dispatch_async(dispatch_get_main_queue(),^{[self ensureWindow];if(self.button)return;UIButton *b=[UIButton buttonWithType:UIButtonTypeSystem];b.frame=CGRectMake(16,150,56,56);b.layer.cornerRadius=28;b.backgroundColor=[UIColor colorWithWhite:.08 alpha:.92];[b setTitle:@"ZN" forState:UIControlStateNormal];[b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];b.titleLabel.font=[UIFont boldSystemFontOfSize:17];[b addTarget:self action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];[b addGestureRecognizer:[[UIPanGestureRecognizer alloc]initWithTarget:self action:@selector(pan:)]];[self.root.view addSubview:b];self.button=b;}); }
- (void)pan:(UIPanGestureRecognizer *)p { UIView *v=p.view,*h=self.root.view;if(p.state==UIGestureRecognizerStateBegan)self.dragStart=v.center;CGPoint q=[p translationInView:h];CGFloat r=28;UIEdgeInsets i=h.safeAreaInsets;CGFloat l=i.left+r+4,R=CGRectGetWidth(h.bounds)-i.right-r-4,T=i.top+r+4,B=CGRectGetHeight(h.bounds)-i.bottom-r-4;CGPoint c=CGPointMake(self.dragStart.x+q.x,self.dragStart.y+q.y);c.x=MIN(MAX(c.x,l),R);c.y=MIN(MAX(c.y,T),B);v.center=c;if(p.state==UIGestureRecognizerStateEnded){c.x=c.x<CGRectGetMidX(h.bounds)?l:R;[UIView animateWithDuration:.2 animations:^{v.center=c;}];} }
- (void)tap { if(!self.presenting&&self.tapHandler)self.tapHandler(); }
- (void)begin { [self ensureWindow];self.oldKey=[self host];self.presenting=YES;[self.window makeKeyAndVisible]; }
- (void)end { self.presenting=NO;UIWindow *w=self.oldKey;self.oldKey=nil;dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(.2*NSEC_PER_SEC)),dispatch_get_main_queue(),^{if(w&&!w.hidden)[w makeKeyWindow];}); }
- (void)alert:(UIAlertController *)a { dispatch_async(dispatch_get_main_queue(),^{if(self.root.presentedViewController)return;[self begin];[self.root presentViewController:a animated:YES completion:nil];}); }

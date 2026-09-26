@interface ZONOverlayWindow : UIWindow @end
@implementation ZONOverlayWindow
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e { UIView *v=[super hitTest:p withEvent:e]; if(!self.rootViewController.presentedViewController&&v==self.rootViewController.view)return nil; return v; }
@end

@interface ZONCenterVC : UIViewController
@property(copy) NSString *body;
@property(copy) dispatch_block_t clearCard,clearUDID,done;
@end
@implementation ZONCenterVC
- (void)viewDidLoad {
    [super viewDidLoad]; self.view.backgroundColor=UIColor.systemBackgroundColor;
    UILabel *h=[UILabel new]; h.translatesAutoresizingMaskIntoConstraints=NO; h.text=@"授权中心"; h.font=[UIFont boldSystemFontOfSize:21];
    UITextView *t=[UITextView new]; t.translatesAutoresizingMaskIntoConstraints=NO; t.editable=NO; t.selectable=YES; t.alwaysBounceVertical=YES; t.text=self.body?:@""; t.font=[UIFont systemFontOfSize:15]; t.backgroundColor=UIColor.secondarySystemBackgroundColor; t.layer.cornerRadius=12; t.textContainerInset=UIEdgeInsetsMake(12,12,12,12);
    UIButton *c1=[UIButton buttonWithType:UIButtonTypeSystem],*c2=[UIButton buttonWithType:UIButtonTypeSystem],*ok=[UIButton buttonWithType:UIButtonTypeSystem];
    for(UIButton *b in @[c1,c2,ok]) b.translatesAutoresizingMaskIntoConstraints=NO;
    [c1 setTitle:@"清除卡密" forState:UIControlStateNormal]; [c2 setTitle:@"清除 UDID" forState:UIControlStateNormal]; [ok setTitle:@"确定" forState:UIControlStateNormal];
    [c1 addTarget:self action:@selector(c1) forControlEvents:UIControlEventTouchUpInside]; [c2 addTarget:self action:@selector(c2) forControlEvents:UIControlEventTouchUpInside]; [ok addTarget:self action:@selector(ok) forControlEvents:UIControlEventTouchUpInside];
    UIStackView *bar=[[UIStackView alloc]initWithArrangedSubviews:@[c1,c2,ok]]; bar.translatesAutoresizingMaskIntoConstraints=NO; bar.axis=UILayoutConstraintAxisHorizontal; bar.spacing=8; bar.distribution=UIStackViewDistributionFillEqually;
    [self.view addSubview:h]; [self.view addSubview:t]; [self.view addSubview:bar]; UILayoutGuide *g=self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[[h.topAnchor constraintEqualToAnchor:g.topAnchor constant:16],[h.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],[t.topAnchor constraintEqualToAnchor:h.bottomAnchor constant:12],[t.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:12],[t.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-12],[bar.topAnchor constraintEqualToAnchor:t.bottomAnchor constant:12],[bar.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:12],[bar.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-12],[bar.heightAnchor constraintEqualToConstant:44],[bar.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-12]]];
}
- (void)c1 { if(self.clearCard)self.clearCard(); [self dismissViewControllerAnimated:YES completion:self.done]; }
- (void)c2 { if(self.clearUDID)self.clearUDID(); [self dismissViewControllerAnimated:YES completion:self.done]; }
- (void)ok { [self dismissViewControllerAnimated:YES completion:self.done]; }
@end

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

static UIView *gHFAFeaturePanel = nil;
static UILabel *gHFAFeatureStatus = nil;
static UIScrollView *gHFAFeatureScroll = nil;
static NSString *gHFAFeaturePackageName = nil;
static NSString *gHFAFeatureIdentityName = nil;
static NSString *gHFAFeatureSchema = nil;
static NSDictionary *gHFAFeaturePackage = nil;
static NSMutableDictionary<NSString *, NSDictionary *> *gHFAFeatureByID = nil;
static NSMutableDictionary<NSString *, UITextField *> *gHFAFeatureTextFields = nil;

static NSString *HFAV2Documents(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static void HFAV2SetStatus(NSString *text) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gHFAFeatureStatus) gHFAFeatureStatus.text = text ?: @"";
    });
}

static NSDictionary *HFAV2ReadJSON(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;
    id root = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [root isKindOfClass:[NSDictionary class]] ? root : nil;
}

static BOOL HFAV2PackageMatchesCurrentApp(NSDictionary *root) {
    NSDictionary *package = [root[@"package"] isKindOfClass:[NSDictionary class]] ? root[@"package"] : nil;
    if (!package) return NO;
    NSBundle *bundle = NSBundle.mainBundle;
    NSString *bundleID = bundle.bundleIdentifier ?: @"";
    NSString *shortVersion = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSString *buildVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";
    NSString *declaredBundle = [package[@"bundleIdentifier"] isKindOfClass:[NSString class]] ? package[@"bundleIdentifier"] : @"";
    NSString *declaredShort = [package[@"shortVersion"] isKindOfClass:[NSString class]] ? package[@"shortVersion"] : @"";
    NSString *declaredBuild = [package[@"buildVersion"] isKindOfClass:[NSString class]] ? package[@"buildVersion"] : @"";
    if (declaredBundle.length && ![declaredBundle isEqualToString:bundleID]) return NO;
    if (declaredShort.length && ![declaredShort isEqualToString:shortVersion]) return NO;
    if (declaredBuild.length && ![declaredBuild isEqualToString:buildVersion]) return NO;
    return YES;
}

static NSString *HFAV2IdentityForPackagePath(NSString *packagePath) {
    NSString *stem = [packagePath stringByDeletingPathExtension];
    NSString *candidate = [stem stringByAppendingString:@".identity.json"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:candidate]) return candidate.lastPathComponent;
    return nil;
}

static NSDictionary *HFAV2NewestSupportedPackage(NSString **pathOut) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *docs = HFAV2Documents();
    NSArray<NSString *> *names = [fm contentsOfDirectoryAtPath:docs error:nil] ?: @[];
    NSMutableArray<NSDictionary *> *candidates = [NSMutableArray array];
    for (NSString *name in names) {
        if (![name hasSuffix:@".json"] || [name hasSuffix:@".identity.json"] ||
            [name hasPrefix:@"HFAPatchPlayback."]) continue;
        NSString *path = [docs stringByAppendingPathComponent:name];
        NSDictionary *root = HFAV2ReadJSON(path);
        NSString *schema = [root[@"schema"] isKindOfClass:[NSString class]] ? root[@"schema"] : nil;
        if (![schema isEqualToString:@"com.hfa.patch/v1"] &&
            ![schema isEqualToString:@"com.hfa.feature/v2"]) continue;
        if (!HFAV2PackageMatchesCurrentApp(root)) continue;
        NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
        NSDate *date = [attrs fileModificationDate] ?: [NSDate distantPast];
        [candidates addObject:@{ @"path": path, @"root": root, @"date": date }];
    }
    [candidates sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [b[@"date"] compare:a[@"date"]];
    }];
    NSDictionary *best = candidates.firstObject;
    if (!best) return nil;
    if (pathOut) *pathOut = best[@"path"];
    return best[@"root"];
}

static BOOL HFAV2WriteCommand(NSDictionary *command, NSString **reasonOut) {
    if (![command isKindOfClass:[NSDictionary class]] || ![NSJSONSerialization isValidJSONObject:command]) {
        if (reasonOut) *reasonOut = @"invalid-command";
        return NO;
    }
    NSString *path = [HFAV2Documents() stringByAppendingPathComponent:@"HFAPatchPlayback.command.json"];
    NSFileManager *fm = NSFileManager.defaultManager;
    if ([fm fileExistsAtPath:path]) {
        if (reasonOut) *reasonOut = @"executor-busy";
        return NO;
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:command options:NSJSONWritingPrettyPrinted error:nil];
    if (!data || ![data writeToFile:path options:NSDataWritingAtomic error:nil]) {
        if (reasonOut) *reasonOut = @"command-write-failed";
        return NO;
    }
    return YES;
}

static NSMutableDictionary *HFAV2BaseCommand(NSString *action) {
    NSMutableDictionary *cmd = [@{ @"action": action ?: @"",
                                    @"package": gHFAFeaturePackageName ?: @"" } mutableCopy];
    if (gHFAFeatureIdentityName.length) cmd[@"identity"] = gHFAFeatureIdentityName;
    return cmd;
}

static NSDictionary *HFAV2Execution(NSDictionary *feature) {
    NSDictionary *value = [feature[@"execution"] isKindOfClass:[NSDictionary class]] ? feature[@"execution"] : nil;
    return value;
}

static NSDictionary *HFAV2Control(NSDictionary *feature) {
    NSDictionary *value = [feature[@"control"] isKindOfClass:[NSDictionary class]] ? feature[@"control"] : nil;
    return value;
}

@interface HFAMapFeatureV2Target : NSObject
+ (instancetype)shared;
- (void)toggleChanged:(UISwitch *)sender;
- (void)setNumber:(UIButton *)sender;
- (void)invokeButton:(UIButton *)sender;
- (void)reloadButton:(UIButton *)sender;
@end

@implementation HFAMapFeatureV2Target
+ (instancetype)shared {
    static HFAMapFeatureV2Target *target;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ target = [HFAMapFeatureV2Target new]; });
    return target;
}

- (void)toggleChanged:(UISwitch *)sender {
    NSString *fid = sender.accessibilityIdentifier ?: @"";
    NSDictionary *feature = gHFAFeatureByID[fid];
    if (!feature) return;
    NSString *executionKind = HFAV2Execution(feature)[@"kind"];
    NSMutableDictionary *cmd = nil;
    if ([gHFAFeatureSchema isEqualToString:@"com.hfa.patch/v1"] ||
        [executionKind isEqualToString:@"bytePatch"]) {
        cmd = HFAV2BaseCommand(sender.isOn ? @"apply" : @"restore");
        cmd[@"featureIds"] = @[fid];
    } else if ([executionKind isEqualToString:@"runtimeState"]) {
        cmd = HFAV2BaseCommand(@"set");
        cmd[@"featureId"] = fid;
        cmd[@"value"] = @(sender.isOn);
    }
    if (!cmd) {
        HFAV2SetStatus([NSString stringWithFormat:@"%@：暂不支持", feature[@"title"] ?: fid]);
        sender.on = !sender.isOn;
        return;
    }
    NSString *reason = nil;
    if (HFAV2WriteCommand(cmd, &reason))
        HFAV2SetStatus([NSString stringWithFormat:@"%@ → %@", feature[@"title"] ?: fid, sender.isOn ? @"ON" : @"OFF"]);
    else {
        sender.on = !sender.isOn;
        HFAV2SetStatus([NSString stringWithFormat:@"执行失败：%@", reason ?: @"unknown"]);
    }
}

- (void)setNumber:(UIButton *)sender {
    NSString *fid = sender.accessibilityIdentifier ?: @"";
    NSDictionary *feature = gHFAFeatureByID[fid];
    UITextField *field = gHFAFeatureTextFields[fid];
    if (!feature || !field) return;
    NSDictionary *execution = HFAV2Execution(feature);
    if (![execution[@"kind"] isEqualToString:@"runtimeState"]) {
        HFAV2SetStatus(@"该数值项没有可执行 runtimeState");
        return;
    }
    double value = field.text.doubleValue;
    NSMutableDictionary *cmd = HFAV2BaseCommand(@"set");
    cmd[@"featureId"] = fid;
    cmd[@"value"] = @(value);
    NSString *reason = nil;
    if (HFAV2WriteCommand(cmd, &reason)) {
        [field resignFirstResponder];
        HFAV2SetStatus([NSString stringWithFormat:@"%@ = %@", feature[@"title"] ?: fid, field.text ?: @""]);
    } else {
        HFAV2SetStatus([NSString stringWithFormat:@"执行失败：%@", reason ?: @"unknown"]);
    }
}

- (void)invokeButton:(UIButton *)sender {
    NSString *fid = sender.accessibilityIdentifier ?: @"";
    NSDictionary *feature = gHFAFeatureByID[fid];
    NSDictionary *execution = HFAV2Execution(feature);
    if (!feature || ![execution[@"kind"] isEqualToString:@"nativeCall"]) {
        HFAV2SetStatus(@"该按钮没有可执行 nativeCall");
        return;
    }
    NSMutableDictionary *cmd = HFAV2BaseCommand(@"invoke");
    cmd[@"featureId"] = fid;
    NSString *reason = nil;
    if (HFAV2WriteCommand(cmd, &reason))
        HFAV2SetStatus([NSString stringWithFormat:@"%@：已执行", feature[@"title"] ?: fid]);
    else
        HFAV2SetStatus([NSString stringWithFormat:@"执行失败：%@", reason ?: @"unknown"]);
}

- (void)reloadButton:(UIButton *)sender {
    (void)sender;
    extern void HFAMapFeatureUIReloadLatest(void);
    HFAMapFeatureUIReloadLatest();
}
@end

static UILabel *HFAV2Label(NSString *text, CGRect frame, CGFloat size) {
    UILabel *label = [[UILabel alloc] initWithFrame:frame];
    label.text = text;
    label.textColor = [UIColor colorWithWhite:0.96 alpha:1.0];
    label.font = [UIFont systemFontOfSize:size];
    label.numberOfLines = 1;
    return label;
}

static void HFAV2ClearRows(void) {
    for (UIView *view in [gHFAFeatureScroll.subviews copy]) [view removeFromSuperview];
    [gHFAFeatureByID removeAllObjects];
    [gHFAFeatureTextFields removeAllObjects];
}

static void HFAV2AddToggleRow(NSDictionary *feature, CGFloat y, BOOL initial) {
    NSString *fid = feature[@"id"] ?: @"";
    UILabel *label = HFAV2Label(feature[@"title"] ?: fid, CGRectMake(8, y + 7, 190, 34), 14);
    [gHFAFeatureScroll addSubview:label];
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(225, y + 8, 52, 32)];
    sw.on = initial;
    sw.accessibilityIdentifier = fid;
    [sw addTarget:[HFAMapFeatureV2Target shared] action:@selector(toggleChanged:) forControlEvents:UIControlEventValueChanged];
    [gHFAFeatureScroll addSubview:sw];
}

static void HFAV2AddNumberRow(NSDictionary *feature, CGFloat y) {
    NSString *fid = feature[@"id"] ?: @"";
    NSDictionary *control = HFAV2Control(feature);
    NSNumber *def = [control[@"default"] isKindOfClass:[NSNumber class]] ? control[@"default"] : @1;
    UILabel *label = HFAV2Label(feature[@"title"] ?: fid, CGRectMake(8, y + 7, 145, 34), 14);
    [gHFAFeatureScroll addSubview:label];
    UITextField *field = [[UITextField alloc] initWithFrame:CGRectMake(154, y + 7, 78, 34)];
    field.text = def.stringValue;
    field.textColor = UIColor.whiteColor;
    field.backgroundColor = [UIColor colorWithWhite:0.14 alpha:1.0];
    field.layer.cornerRadius = 6.0;
    field.textAlignment = NSTextAlignmentCenter;
    field.keyboardType = UIKeyboardTypeDecimalPad;
    [gHFAFeatureScroll addSubview:field];
    gHFAFeatureTextFields[fid] = field;
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.frame = CGRectMake(238, y + 7, 65, 34);
    [button setTitle:@"设置" forState:UIControlStateNormal];
    button.accessibilityIdentifier = fid;
    [button addTarget:[HFAMapFeatureV2Target shared] action:@selector(setNumber:) forControlEvents:UIControlEventTouchUpInside];
    [gHFAFeatureScroll addSubview:button];
}

static void HFAV2AddButtonRow(NSDictionary *feature, CGFloat y) {
    NSString *fid = feature[@"id"] ?: @"";
    UILabel *label = HFAV2Label(feature[@"title"] ?: fid, CGRectMake(8, y + 7, 190, 34), 14);
    [gHFAFeatureScroll addSubview:label];
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.frame = CGRectMake(218, y + 7, 85, 34);
    [button setTitle:@"执行" forState:UIControlStateNormal];
    button.accessibilityIdentifier = fid;
    [button addTarget:[HFAMapFeatureV2Target shared] action:@selector(invokeButton:) forControlEvents:UIControlEventTouchUpInside];
    [gHFAFeatureScroll addSubview:button];
}

static void HFAV2AddUnsupportedRow(NSDictionary *feature, CGFloat y, NSString *kind) {
    NSString *fid = feature[@"id"] ?: @"";
    UILabel *label = HFAV2Label(feature[@"title"] ?: fid, CGRectMake(8, y + 5, 190, 36), 14);
    [gHFAFeatureScroll addSubview:label];
    UILabel *state = HFAV2Label([NSString stringWithFormat:@"%@ 未支持", kind ?: @"?"], CGRectMake(198, y + 5, 105, 36), 11);
    state.textColor = [UIColor colorWithWhite:0.65 alpha:1.0];
    state.textAlignment = NSTextAlignmentRight;
    [gHFAFeatureScroll addSubview:state];
}

static void HFAV2RenderPackage(NSDictionary *root, NSString *path) {
    if (!gHFAFeaturePanel || !gHFAFeatureScroll || !root || !path.length) return;
    HFAV2ClearRows();
    gHFAFeaturePackage = root;
    gHFAFeaturePackageName = path.lastPathComponent;
    gHFAFeatureIdentityName = HFAV2IdentityForPackagePath(path);
    gHFAFeatureSchema = root[@"schema"];
    NSArray *features = [root[@"features"] isKindOfClass:[NSArray class]] ? root[@"features"] : @[];
    CGFloat y = 0;
    for (NSDictionary *feature in features) {
        if (![feature isKindOfClass:[NSDictionary class]]) continue;
        NSString *fid = [feature[@"id"] isKindOfClass:[NSString class]] ? feature[@"id"] : nil;
        if (!fid.length) continue;
        gHFAFeatureByID[fid] = feature;
        NSString *kind = nil;
        BOOL initial = NO;
        if ([gHFAFeatureSchema isEqualToString:@"com.hfa.patch/v1"]) {
            kind = @"toggle";
            initial = [feature[@"defaultEnabled"] boolValue];
        } else {
            NSDictionary *control = HFAV2Control(feature);
            kind = [control[@"kind"] isKindOfClass:[NSString class]] ? control[@"kind"] : @"?";
            initial = [control[@"default"] boolValue];
        }
        if ([kind isEqualToString:@"toggle"]) HFAV2AddToggleRow(feature, y, initial);
        else if ([kind isEqualToString:@"number"]) HFAV2AddNumberRow(feature, y);
        else if ([kind isEqualToString:@"button"] || [kind isEqualToString:@"action"]) HFAV2AddButtonRow(feature, y);
        else HFAV2AddUnsupportedRow(feature, y, kind);
        y += 49.0;
    }
    gHFAFeatureScroll.contentSize = CGSizeMake(gHFAFeatureScroll.bounds.size.width, MAX(y, gHFAFeatureScroll.bounds.size.height));
    CGRect frame = gHFAFeaturePanel.frame;
    frame.size.height = MIN(MAX(300.0, 190.0 + MIN(y, 240.0)), 430.0);
    gHFAFeaturePanel.frame = frame;
    CGRect scrollFrame = gHFAFeatureScroll.frame;
    scrollFrame.size.height = MAX(95.0, frame.size.height - 178.0);
    gHFAFeatureScroll.frame = scrollFrame;
    NSString *identityState = gHFAFeatureIdentityName.length ? @"identity ✓" : @"identity ?";
    HFAV2SetStatus([NSString stringWithFormat:@"已自动加载 %@\n%lu 个功能 · %@", gHFAFeaturePackageName,
                    (unsigned long)gHFAFeatureByID.count, identityState]);
}

void HFAMapFeatureUIAttach(id panelObject, id statusObject) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIView *panel = [panelObject isKindOfClass:[UIView class]] ? (UIView *)panelObject : nil;
        UILabel *status = [statusObject isKindOfClass:[UILabel class]] ? (UILabel *)statusObject : nil;
        if (!panel) return;
        gHFAFeaturePanel = panel;
        gHFAFeatureStatus = status;
        if (!gHFAFeatureByID) gHFAFeatureByID = [NSMutableDictionary dictionary];
        if (!gHFAFeatureTextFields) gHFAFeatureTextFields = [NSMutableDictionary dictionary];
        UIScrollView *scroll = [[UIScrollView alloc] initWithFrame:CGRectMake(10, 170, 310, 120)];
        scroll.backgroundColor = [UIColor colorWithWhite:0.025 alpha:0.35];
        scroll.layer.cornerRadius = 8.0;
        scroll.alwaysBounceVertical = YES;
        [panel addSubview:scroll];
        gHFAFeatureScroll = scroll;
        UIButton *reload = [UIButton buttonWithType:UIButtonTypeSystem];
        reload.frame = CGRectMake(244, 128, 76, 34);
        [reload setTitle:@"重载JSON" forState:UIControlStateNormal];
        [reload addTarget:[HFAMapFeatureV2Target shared] action:@selector(reloadButton:) forControlEvents:UIControlEventTouchUpInside];
        [panel addSubview:reload];
        extern void HFAMapFeatureUIReloadLatest(void);
        HFAMapFeatureUIReloadLatest();
    });
}

void HFAMapFeatureUIReloadLatest(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *path = nil;
        NSDictionary *root = HFAV2NewestSupportedPackage(&path);
        if (!root || !path.length) {
            HFAV2ClearRows();
            HFAV2SetStatus(@"尚无可加载 JSON。\n点击扫描后会自动加载刚生成的包。");
            return;
        }
        HFAV2RenderPackage(root, path);
    });
}

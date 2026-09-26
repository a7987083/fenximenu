#import "ZONAPISmokeCenter.h"
#import <UIKit/UIKit.h>
#import "ZONUI.h"
#import "ZONNetwork.h"
#import "ZONAPIEndpoints.h"
#import "ZONActivation.h"
#import "ZONAuthorization.h"
#import "ZONVerify.h"
#import "ZONStorage.h"
#import "ZONResponseFormatter.h"

@implementation ZONAPISmokeCenter
+ (instancetype)shared { static ZONAPISmokeCenter *x; static dispatch_once_t once; dispatch_once(&once, ^{ x=[ZONAPISmokeCenter new]; }); return x; }

- (UIViewController *)presenter {
    UIWindow *w=nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) if(scene.activationState==UISceneActivationStateForegroundActive && [scene isKindOfClass:UIWindowScene.class]) { for(UIWindow *x in ((UIWindowScene *)scene).windows) if(x.isKeyWindow){w=x;break;} if(w)break; }
    if(!w) w=UIApplication.sharedApplication.windows.firstObject;
    UIViewController *v=w.rootViewController; while(v.presentedViewController) v=v.presentedViewController; if([v isKindOfClass:UINavigationController.class]) v=((UINavigationController *)v).topViewController; return v;
}
- (void)show:(id)obj title:(NSString *)title { NSString *text=[ZONResponseFormatter displayTextForObject:obj]; [[ZONUI shared] showText:text title:title completion:nil]; }
- (NSString *)udid { return [ZONStorage udid] ?: @""; }
- (NSString *)card { return [ZONStorage card] ?: @""; }
- (void)needUDID:(void(^)(NSString *udid))completion {
    NSString *u=[self udid]; if(u.length){ completion(u); return; }
    [[ZONUI shared] requestUDID:nil completion:^(NSString *x){ if(!x.length)return; [ZONStorage setUDID:x]; completion(x); }];
}
- (void)needCard:(void(^)(NSString *card))completion {
    NSString *c=[self card]; if(c.length){ completion(c); return; }
    [[ZONUI shared] requestCardWithCompletion:^(NSString *x){ if(!x.length)return; [ZONStorage setCard:x]; completion(x); }];
}

- (NSDictionary *)httpEnvelope:(NSDictionary *)json data:(NSData *)data response:(NSHTTPURLResponse *)response error:(NSError *)error {
    NSMutableDictionary *r=[NSMutableDictionary dictionary];
    r[@"http_status"]=@(response.statusCode);
    if(error) r[@"error"]=error.localizedDescription?:@"网络错误";
    if([json isKindOfClass:NSDictionary.class] && json.count) r[@"json"]=json;
    else if(data.length){ NSString *s=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]?:@""; if(s.length>1200)s=[[s substringToIndex:1200] stringByAppendingString:@"…"]; r[@"body_preview"]=s; }
    return r;
}

- (void)runReadOnlyScan:(NSString *)udid {
    NSMutableDictionary *report=[NSMutableDictionary dictionary];
    dispatch_group_t g=dispatch_group_create();
    NSArray *items=@[
        @[@"appstore_refresh",[ZONAPIEndpoints activationURLForUDID:udid card:nil]],
        @[@"apiface",[ZONAPIEndpoints apiFaceURLForUDID:udid]],
        @[@"legacy_dylib_config",[ZONAPIEndpoints legacyDylibConfigURLForUDID:udid]],
        @[@"unbind_query",[ZONAPIEndpoints unbindQueryURLForUDID:udid]],
        @[@"runtime_config",[ZONAPIEndpoints runtimeConfigURLForDylibKey:@"zonoe.main"]]
    ];
    for(NSArray *it in items){ dispatch_group_enter(g); NSString *key=it[0]; NSURL *url=it[1]; [ZONNetwork GET:url timeout:12 completion:^(NSDictionary *json,NSData *data,NSHTTPURLResponse *resp,NSError *err){ report[key]=[self httpEnvelope:json data:data response:resp error:err]; dispatch_group_leave(g); }]; }
    dispatch_group_enter(g);
    [ZONVerify runWithUDID:udid completion:^(NSDictionary *verify){ report[@"verify_v2"]=verify?:@{}; [ZONStorage setLastVerify:verify]; dispatch_group_leave(g); }];
    dispatch_group_notify(g,dispatch_get_main_queue(),^{
        report[@"udid"]=udid;
        [self show:report title:@"API 全链路只读测试"];
        NSDictionary *verify=report[@"verify_v2"]; [self maybeShowNoticeAndUpdate:verify];
    });
}

- (NSString *)renderTemplate:(NSString *)s update:(NSDictionary *)u {
    if(![s isKindOfClass:NSString.class]) return @"";
    NSBundle *b=NSBundle.mainBundle;
    NSString *name=[b objectForInfoDictionaryKey:@"CFBundleDisplayName"] ?: [b objectForInfoDictionaryKey:@"CFBundleName"] ?: [b objectForInfoDictionaryKey:@"CFBundleExecutable"] ?: @"App";
    NSDictionary *m=@{
        @"{app_name}":name,
        @"{current_version}":[b objectForInfoDictionaryKey:@"CFBundleShortVersionString"]?:@"",
        @"{current_build}":[b objectForInfoDictionaryKey:@"CFBundleVersion"]?:@"",
        @"{latest_version}":[u[@"latest_version"] description]?:@"",
        @"{latest_build}":[u[@"latest_build"] description]?:@""
    };
    NSMutableString *x=[s mutableCopy]; for(NSString *k in m) [x replaceOccurrencesOfString:k withString:m[k] options:0 range:NSMakeRange(0,x.length)]; return x;
}
- (void)maybeShowNoticeAndUpdate:(NSDictionary *)verify {
    id notice=verify[@"notice"]; if(notice && notice!=NSNull.null) [[ZONUI shared] showNoticeObject:notice completion:nil];
    NSDictionary *u=[verify[@"app_update"] isKindOfClass:NSDictionary.class]?verify[@"app_update"]:@{}; if(!u.count)return;
    if([u[@"enabled"] respondsToSelector:@selector(boolValue)] && ![u[@"enabled"] boolValue]) return;
    NSString *title=[self renderTemplate:([u[@"title"] isKindOfClass:NSString.class]?u[@"title"]:@"发现新版本") update:u];
    NSString *msg=[self renderTemplate:([u[@"message"] isKindOfClass:NSString.class]?u[@"message"]:[ZONResponseFormatter displayTextForDictionary:u]) update:u];
    [[ZONUI shared] showText:msg title:title completion:nil];
}

- (void)testAuthorizationHTML:(NSString *)udid {
    [self needCard:^(NSString *card){ [ZONAuthorization queryCard:card udid:udid completion:^(NSDictionary *r,NSError *e){ NSMutableDictionary *x=[NSMutableDictionary dictionaryWithDictionary:r?:@{}]; if(e)x[@"error"]=e.localizedDescription?:@""; [self show:x title:@"/authorization HTML 兼容测试"]; }]; }];
}
- (void)testActivation:(NSString *)udid {
    [self needCard:^(NSString *card){ [ZONActivation activateUDID:udid card:card completion:^(BOOL ok,NSString *message,NSDictionary *raw){ if(ok){[ZONStorage setCard:card]; [ZONStorage setLastActivationObject:raw];} [self show:raw?:@{@"ok":@(ok),@"message":message?:@""} title:@"/appstore 激活测试"]; }]; }];
}
- (void)testVerify:(NSString *)udid { [ZONVerify runWithUDID:udid completion:^(NSDictionary *r){ [ZONStorage setLastVerify:r]; [self show:r title:@"Verify v2"]; [self maybeShowNoticeAndUpdate:r]; }]; }
- (void)testGET:(NSURL *)url title:(NSString *)title { [ZONNetwork GET:url timeout:12 completion:^(NSDictionary *j,NSData *d,NSHTTPURLResponse *r,NSError *e){ [self show:[self httpEnvelope:j data:d response:r error:e] title:title]; }]; }

- (void)promptUnbind:(NSString *)udid {
    [self needCard:^(NSString *card){
        UIAlertController *a=[UIAlertController alertControllerWithTitle:@"换绑提交测试" message:@"此接口会真实提交换绑。请输入新 UDID；仅在你明确要测试时继续。" preferredStyle:UIAlertControllerStyleAlert];
        [a addTextFieldWithConfigurationHandler:^(UITextField *t){ t.placeholder=@"新 UDID"; }];
        [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
        [a addAction:[UIAlertAction actionWithTitle:@"确认提交" style:UIAlertActionStyleDestructive handler:^(__unused UIAlertAction *x){ NSString *n=a.textFields.firstObject.text?:@""; if(!n.length)return; NSDictionary *body=@{@"code":card,@"old_udid":udid,@"new_udid":n}; [ZONNetwork POST:[ZONAPIEndpoints unbindURL] formBody:body timeout:12 completion:^(NSDictionary *j,NSData *d,NSHTTPURLResponse *r,NSError *e){ [self show:[self httpEnvelope:j data:d response:r error:e] title:@"/unbind HTML 兼容结果"]; }]; }]];
        [[self presenter] presentViewController:a animated:YES completion:nil];
    }];
}

- (void)presentMenuForUDID:(NSString *)udid {
    UIAlertController *a=[UIAlertController alertControllerWithTitle:@"ZON API 全链路测试" message:@"8 个文档入口均已覆盖；HTML 入口仅做兼容测试，不参与 JSON 业务判断。" preferredStyle:UIAlertControllerStyleActionSheet];
    [a addAction:[UIAlertAction actionWithTitle:@"全链路只读扫描" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){[self runReadOnlyScan:udid];}]];
    [a addAction:[UIAlertAction actionWithTitle:@"首次激活 /appstore" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){[self testActivation:udid];}]];
    [a addAction:[UIAlertAction actionWithTitle:@"日常授权 /apiface" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){[self testGET:[ZONAPIEndpoints apiFaceURLForUDID:udid] title:@"/apiface"]; }]];
    [a addAction:[UIAlertAction actionWithTitle:@"旧 Dylib 配置" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){[self testGET:[ZONAPIEndpoints legacyDylibConfigURLForUDID:udid] title:@"/index/index/dylib"]; }]];
    [a addAction:[UIAlertAction actionWithTitle:@"换绑状态 /unbind/query" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){[self testGET:[ZONAPIEndpoints unbindQueryURLForUDID:udid] title:@"/unbind/query"]; }]];
    [a addAction:[UIAlertAction actionWithTitle:@"Runtime Config" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){[self testGET:[ZONAPIEndpoints runtimeConfigURLForDylibKey:@"zonoe.main"] title:@"Runtime Config"]; }]];
    [a addAction:[UIAlertAction actionWithTitle:@"Verify v2" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){[self testVerify:udid];}]];
    [a addAction:[UIAlertAction actionWithTitle:@"/authorization HTML 兼容" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){[self testAuthorizationHTML:udid];}]];
    [a addAction:[UIAlertAction actionWithTitle:@"换绑提交 /unbind（会改数据）" style:UIAlertActionStyleDestructive handler:^(__unused UIAlertAction *x){[self promptUnbind:udid];}]];
    [a addAction:[UIAlertAction actionWithTitle:@"清除本地卡密" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){[ZONStorage clearCardState];}]];
    [a addAction:[UIAlertAction actionWithTitle:@"清除本地 UDID" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *x){[ZONStorage clearUDIDState];}]];
    [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    UIPopoverPresentationController *p=a.popoverPresentationController; if(p){UIViewController *v=[self presenter];p.sourceView=v.view;p.sourceRect=CGRectMake(CGRectGetMidX(v.view.bounds),CGRectGetMidY(v.view.bounds),1,1);p.permittedArrowDirections=0;}
    [[self presenter] presentViewController:a animated:YES completion:nil];
}
- (void)present { [self needUDID:^(NSString *udid){ [self presentMenuForUDID:udid]; }]; }
@end

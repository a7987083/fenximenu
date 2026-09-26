#import <Foundation/Foundation.h>
#import "ZONUI.h"
#import "ZONActivation.h"
#import "ZONLicenseStatus.h"
#import "ZONVerify.h"
#import "ZONStorage.h"
#import "ZONResponseFormatter.h"

static id ZONFirstValueForKeys(id obj, NSArray<NSString *> *keys) {
    if([obj isKindOfClass:NSDictionary.class]) {
        NSDictionary *d=obj;
        for(NSString *key in keys) { id v=d[key]; if(v && v!=NSNull.null) return v; }
        for(id v in d.allValues) { id found=ZONFirstValueForKeys(v,keys); if(found) return found; }
    } else if([obj isKindOfClass:NSArray.class]) {
        for(id v in (NSArray *)obj) { id found=ZONFirstValueForKeys(v,keys); if(found) return found; }
    }
    return nil;
}

static NSString *ZONString(id v) {
    if(!v || v==NSNull.null) return @"";
    if([v isKindOfClass:NSString.class]) return v;
    if([v respondsToSelector:@selector(stringValue)]) return [v stringValue];
    return [v description]?:@"";
}

static NSString *ZONTemplate(NSString *text, NSDictionary *update) {
    if(!text.length) return @"";
    NSBundle *b=NSBundle.mainBundle;
    NSString *appName=[b objectForInfoDictionaryKey:@"CFBundleDisplayName"] ?: [b objectForInfoDictionaryKey:@"CFBundleName"] ?: [b objectForInfoDictionaryKey:@"CFBundleExecutable"] ?: @"";
    NSString *currentVersion=[b objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSString *currentBuild=[b objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";
    NSString *latestVersion=ZONString(update[@"latest_version"] ?: update[@"version"]);
    NSString *latestBuild=ZONString(update[@"latest_build"] ?: update[@"build"]);
    NSDictionary *vars=@{
        @"{app_name}":appName,
        @"{current_version}":currentVersion,
        @"{current_build}":currentBuild,
        @"{latest_version}":latestVersion,
        @"{latest_build}":latestBuild
    };
    NSMutableString *out=[text mutableCopy];
    [vars enumerateKeysAndObjectsUsingBlock:^(NSString *k,NSString *v,BOOL *stop){
        [out replaceOccurrencesOfString:k withString:v options:0 range:NSMakeRange(0,out.length)];
    }];
    return out.copy;
}

static BOOL ZONShouldPresentUpdate(NSDictionary *update) {
    if(![update isKindOfClass:NSDictionary.class] || update.count==0) return NO;
    id available=update[@"available"];
    if([available respondsToSelector:@selector(boolValue)]) return [available boolValue];
    id show=update[@"show"] ?: update[@"enabled"];
    if([show respondsToSelector:@selector(boolValue)]) return [show boolValue];
    return YES;
}

static NSDictionary *ZONCenterObject(NSString *udid, NSDictionary *license, NSDictionary *verify) {
    NSMutableDictionary *out=[NSMutableDictionary dictionary];
    if(udid.length) out[@"udid"]=udid;
    if(license.count) out[@"authorization_status"]=license;
    if(verify.count) {
        NSArray *keys=@[@"access_level",@"permissions",@"code",@"action",@"message",@"server_time",@"protocol_version",@"offline_grace_seconds"];
        for(NSString *key in keys) { id v=verify[key]; if(v && v!=NSNull.null) out[key]=v; }
    }
    id remaining=ZONFirstValueForKeys(license,@[@"remaining_seconds",@"remaining_time",@"remaining"]);
    if(remaining) out[@"remaining_seconds"]=remaining;
    else {
        id expireObj=ZONFirstValueForKeys(license,@[@"expire",@"expires_at",@"expire_time"]);
        double expire=[ZONString(expireObj) doubleValue];
        double now=[verify[@"server_time"] respondsToSelector:@selector(doubleValue)]?[verify[@"server_time"] doubleValue]:0;
        if(expire>0 && now>0) out[@"remaining_seconds"]=@(MAX(0,expire-now));
    }
    return out.copy;
}

static void ZONShowCenter(NSString *udid, NSDictionary *license, NSDictionary *verify) {
    NSDictionary *center=ZONCenterObject(udid,license,verify);
    NSString *text=[ZONResponseFormatter displayTextForDictionary:center];
    [[ZONUI shared] showAuthorizationText:text
                                clearCard:^{ [ZONStorage clearCardState]; }
                                clearUDID:^{ [ZONStorage clearUDIDState]; }
                               completion:nil];
}

static void ZONShowUpdateThenCenter(NSString *udid, NSDictionary *license, NSDictionary *verify) {
    NSDictionary *update=[verify[@"app_update"] isKindOfClass:NSDictionary.class]?verify[@"app_update"]:nil;
    if(!ZONShouldPresentUpdate(update)) { ZONShowCenter(udid,license,verify); return; }

    NSString *title=ZONTemplate(ZONString(update[@"title"]),update);
    NSString *body=ZONString(update[@"message"] ?: update[@"content"] ?: update[@"text"]);
    if(!body.length) body=[ZONResponseFormatter displayTextForDictionary:update];
    body=ZONTemplate(body,update);

    [[ZONUI shared] showText:body
                       title:title.length?title:@"更新"
                  completion:^{ ZONShowCenter(udid,license,verify); }];
}

static void ZONShowFirstActivationPostFlow(NSString *udid, NSDictionary *license, NSDictionary *verify) {
    id notice=verify[@"notice"];
    if(notice && notice!=NSNull.null) {
        [[ZONUI shared] showNoticeObject:notice completion:^{
            ZONShowUpdateThenCenter(udid,license,verify);
        }];
    } else {
        ZONShowUpdateThenCenter(udid,license,verify);
    }
}

typedef void (^ZONAuthorizedStateCompletion)(NSDictionary *license, NSDictionary *verify);

static void ZONLoadAuthorizedState(NSString *udid, ZONAuthorizedStateCompletion completion) {
    ZONUI *ui=[ZONUI shared];
    [ZONLicenseStatus fetchForUDID:udid completion:^(NSDictionary *license, BOOL ignoredSignatureState, NSError *licenseError) {
        if(licenseError) {
            [ui showText:licenseError.localizedDescription?:@"网络错误" title:@"授权状态" completion:nil];
            return;
        }
        [ZONVerify runWithUDID:udid completion:^(NSDictionary *verify) {
            [ZONStorage setLastVerify:verify];
            BOOL ok=[verify[@"ok"] respondsToSelector:@selector(boolValue)]?[verify[@"ok"] boolValue]:NO;
            if(!ok) {
                NSString *title=ZONString(verify[@"code"]);
                [ui showText:[ZONResponseFormatter displayTextForDictionary:verify]
                       title:title.length?title:@"验证结果"
                  completion:nil];
                return;
            }
            if(completion) completion(license?:@{},verify?:@{});
        }];
    }];
}

static void ZONOpenAuthorizationCenter(NSString *udid) {
    ZONLoadAuthorizedState(udid, ^(NSDictionary *license, NSDictionary *verify) {
        ZONShowCenter(udid,license,verify);
    });
}

static void ZONContinueAfterActivation(NSString *udid) {
    ZONLoadAuthorizedState(udid, ^(NSDictionary *license, NSDictionary *verify) {
        ZONShowFirstActivationPostFlow(udid,license,verify);
    });
}

static void ZONPromptCard(NSString *udid, NSString *serverMessage) {
    ZONUI *ui=[ZONUI shared];
    [ui requestCardWithServerMessage:serverMessage completion:^(NSString *card) {
        if(!card.length) return;
        [ZONActivation activateUDID:udid card:card completion:^(BOOL ok, NSString *message, NSDictionary *raw) {
            if(!ok) {
                NSString *serverText=ZONString(raw[@"message"] ?: raw[@"msg"]);
                if(!serverText.length) serverText=message;
                ZONPromptCard(udid,serverText);
                return;
            }

            // 成功后不再复用卡密输入框。先保存状态，再弹独立成功结果。
            [ZONStorage setUDID:udid];
            [ZONStorage setCard:card];
            [ZONStorage setLastActivationObject:raw?:@{}];

            NSString *activationText=[ZONResponseFormatter displayTextForDictionary:raw?:@{}];
            NSString *activationTitle=ZONString(raw[@"title"]);
            if(!activationTitle.length) activationTitle=ZONString(raw[@"message"] ?: raw[@"msg"]);
            if(!activationTitle.length) activationTitle=@"激活结果";

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.20*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
                [ui showText:activationText title:activationTitle completion:^{
                    // 用户确认成功结果后，继续公告 → 更新 → 授权中心。
                    ZONContinueAfterActivation(udid);
                }];
            });
        }];
    }];
}

static void ZONRoute(void) {
    NSString *udid=[ZONStorage udid];
    NSString *card=[ZONStorage card];

    // 已激活：不再进入卡密流程，直接授权中心。
    if(udid.length && card.length) {
        ZONOpenAuthorizationCenter(udid);
        return;
    }

    ZONUI *ui=[ZONUI shared];
    [ui requestUDID:udid completion:^(NSString *inputUDID) {
        if(!inputUDID.length) return;
        [ZONStorage setUDID:inputUDID];
        ZONPromptCard(inputUDID,nil);
    }];
}

__attribute__((constructor)) static void ZONStart(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.0*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
        ZONUI *ui=[ZONUI shared];
        [ui installFloatingButton];
        ui.tapHandler=^{ ZONRoute(); };
    });
}

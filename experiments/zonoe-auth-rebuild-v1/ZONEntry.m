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
    [vars enumerateKeysAndObjectsUsingBlock:^(NSString *k,NSString *v,BOOL *stop){[out replaceOccurrencesOfString:k withString:v options:0 range:NSMakeRange(0,out.length)];}];
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
        id level=verify[@"access_level"]; if(level && level!=NSNull.null) out[@"access_level"]=level;
        id permissions=verify[@"permissions"]; if(permissions && permissions!=NSNull.null) out[@"permissions"]=permissions;
        id code=verify[@"code"]; if(code && code!=NSNull.null) out[@"code"]=code;
        id action=verify[@"action"]; if(action && action!=NSNull.null) out[@"action"]=action;
        id message=verify[@"message"]; if(message && message!=NSNull.null) out[@"message"]=message;
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
    [[ZONUI shared] showAuthorizationText:text clearCard:^{[ZONStorage clearCardState];} clearUDID:^{[ZONStorage clearUDIDState];} completion:nil];
}

static void ZONShowUpdateThenCenter(NSString *udid, NSDictionary *license, NSDictionary *verify) {
    NSDictionary *update=[verify[@"app_update"] isKindOfClass:NSDictionary.class]?verify[@"app_update"]:nil;
    if(!ZONShouldPresentUpdate(update)) { ZONShowCenter(udid,license,verify); return; }
    NSString *title=ZONTemplate(ZONString(update[@"title"]),update);
    NSString *body=ZONString(update[@"message"] ?: update[@"content"] ?: update[@"text"]);
    if(!body.length) body=[ZONResponseFormatter displayTextForDictionary:update];
    body=ZONTemplate(body,update);
    [[ZONUI shared] showText:body title:title.length?title:@"更新" completion:^{ZONShowCenter(udid,license,verify);}];
}

static void ZONShowNoticeUpdateCenter(NSString *udid, NSDictionary *license, NSDictionary *verify) {
    id notice=verify[@"notice"];
    if(notice && notice!=NSNull.null) {
        [[ZONUI shared] showNoticeObject:notice completion:^{ZONShowUpdateThenCenter(udid,license,verify);}];
    } else {
        ZONShowUpdateThenCenter(udid,license,verify);
    }
}

static void ZONRefreshAuthorizedState(NSString *udid) {
    ZONUI *ui=[ZONUI shared];
    [ZONLicenseStatus fetchForUDID:udid completion:^(NSDictionary *license, BOOL ignoredSignatureState, NSError *licenseError) {
        if(licenseError){[ui showText:licenseError.localizedDescription?:@"网络错误" title:@"授权状态" completion:nil];return;}
        [ZONVerify runWithUDID:udid completion:^(NSDictionary *verify) {
            [ZONStorage setLastVerify:verify];
            BOOL ok=[verify[@"ok"] respondsToSelector:@selector(boolValue)]?[verify[@"ok"] boolValue]:NO;
            if(!ok){
                NSString *title=ZONString(verify[@"code"]); if(!title.length) title=@"验证结果";
                [ui showText:[ZONResponseFormatter displayTextForDictionary:verify] title:title completion:nil];
                return;
            }
            ZONShowNoticeUpdateCenter(udid,license?:@{},verify?:@{});
        }];
    }];
}

static void ZONPromptCard(NSString *udid, NSString *serverMessage);

static void ZONPromptCard(NSString *udid, NSString *serverMessage) {
    ZONUI *ui=[ZONUI shared];
    [ui requestCardWithServerMessage:serverMessage completion:^(NSString *card) {
        if(!card.length) return;
        [ZONActivation activateUDID:udid card:card completion:^(BOOL ok, NSString *message, NSDictionary *raw) {
            if(!ok){
                NSString *serverText=ZONString(raw[@"message"] ?: raw[@"msg"]);
                if(!serverText.length) serverText=message;
                ZONPromptCard(udid,serverText);
                return;
            }
            NSString *activationText=[ZONResponseFormatter displayTextForDictionary:raw?:@{}];
            NSString *activationTitle=ZONString(raw[@"title"]);
            if(!activationTitle.length) activationTitle=ZONString(raw[@"message"]);
            if(!activationTitle.length) activationTitle=@"激活结果";
            [ui showText:activationText title:activationTitle completion:^{ZONRefreshAuthorizedState(udid);}];
        }];
    }];
}

static void ZONRoute(void) {
    NSString *udid=[ZONStorage udid];
    NSString *card=[ZONStorage card];
    if(udid.length && card.length){ZONRefreshAuthorizedState(udid);return;}
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
        ui.tapHandler=^{ZONRoute();};
    });
}

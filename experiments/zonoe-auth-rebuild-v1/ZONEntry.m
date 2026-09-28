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
    NSDictionary *vars=@{@"{app_name}":appName,@"{current_version}":currentVersion,@"{current_build}":currentBuild,@"{latest_version}":latestVersion,@"{latest_build}":latestBuild};
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

static BOOL ZONLicenseIsAuthorized(NSDictionary *license) {
    if(![license isKindOfClass:NSDictionary.class] || !license.count) return NO;
    id auths=license[@"authorizations"];
    if([auths isKindOfClass:NSArray.class] && [(NSArray *)auths count]>0) return YES;
    id status=ZONFirstValueForKeys(license,@[@"status",@"active",@"authorized",@"valid"]);
    if([status respondsToSelector:@selector(boolValue)] && [status boolValue]) return YES;
    id expireObj=ZONFirstValueForKeys(license,@[@"expire",@"expires_at",@"expire_time"]);
    double expire=[ZONString(expireObj) doubleValue];
    if(expire>NSDate.date.timeIntervalSince1970) return YES;
    return NO;
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
        double now=[verify[@"server_time"] respondsToSelector:@selector(doubleValue)]?[verify[@"server_time"] doubleValue]:NSDate.date.timeIntervalSince1970;
        if(expire>0) out[@"remaining_seconds"]=@(MAX(0,expire-now));
    }
    return out.copy;
}

static NSDictionary *ZONActivationSuccessObject(NSDictionary *raw, NSDictionary *license, NSDictionary *verify) {
    NSMutableDictionary *out=[NSMutableDictionary dictionary];
    id msg=raw[@"message"] ?: raw[@"msg"]; if(msg && msg!=NSNull.null) out[@"message"]=msg;
    id expire=ZONFirstValueForKeys(license,@[@"expire",@"expires_at",@"expire_time"]); if(expire) out[@"expire"]=expire;
    id remaining=ZONFirstValueForKeys(license,@[@"remaining_seconds",@"remaining_time",@"remaining"]);
    if(remaining) out[@"remaining_seconds"]=remaining;
    else if(expire) {
        double end=[ZONString(expire) doubleValue];
        double now=[verify[@"server_time"] respondsToSelector:@selector(doubleValue)]?[verify[@"server_time"] doubleValue]:NSDate.date.timeIntervalSince1970;
        if(end>0) out[@"remaining_seconds"]=@(MAX(0,end-now));
    }
    id level=verify[@"access_level"]; if(level && level!=NSNull.null) out[@"access_level"]=level;
    return out.copy;
}

static void ZONShowCenter(NSString *udid, NSDictionary *license, NSDictionary *verify) {
    NSString *text=[ZONResponseFormatter displayTextForDictionary:ZONCenterObject(udid,license,verify)];
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

static void ZONShowFirstActivationPostFlow(NSString *udid, NSDictionary *license, NSDictionary *verify) {
    id notice=verify[@"notice"];
    if(notice && notice!=NSNull.null) [[ZONUI shared] showNoticeObject:notice completion:^{ZONShowUpdateThenCenter(udid,license,verify);}];
    else ZONShowUpdateThenCenter(udid,license,verify);
}

static void ZONLoadAuthorizedState(NSString *udid, void (^completion)(NSDictionary *,NSDictionary *), void (^failure)(NSString *)) {
    [ZONLicenseStatus fetchForUDID:udid completion:^(NSDictionary *license, BOOL ignored, NSError *licenseError) {
        if(licenseError){if(failure)failure(licenseError.localizedDescription?:@"网络错误");return;}
        [ZONVerify runWithUDID:udid completion:^(NSDictionary *verify) {
            BOOL verifyOK=[verify[@"ok"] respondsToSelector:@selector(boolValue)]?[verify[@"ok"] boolValue]:NO;
            if(!verifyOK || !ZONLicenseIsAuthorized(license)) {
                NSString *m=ZONString(verify[@"message"] ?: license[@"message"] ?: license[@"msg"]);
                if(failure) failure(m.length?m:@"授权状态无效");
                return;
            }
            [ZONStorage setLastVerify:verify];
            if(completion) completion(license?:@{},verify?:@{});
        }];
    }];
}

static void ZONOpenAuthorizationCenter(NSString *udid) {
    ZONLoadAuthorizedState(udid, ^(NSDictionary *license, NSDictionary *verify){ZONShowCenter(udid,license,verify);}, ^(NSString *message){
        [[ZONUI shared] showText:message title:@"授权状态" completion:nil];
    });
}

static void ZONPromptCard(NSString *udid, NSString *serverMessage) {
    ZONUI *ui=[ZONUI shared];
    [ui requestCardWithServerMessage:serverMessage completion:^(NSString *card) {
        if(!card.length) return;
        [ZONActivation activateUDID:udid card:card completion:^(BOOL requestOK, NSString *message, NSDictionary *raw) {
            if(!requestOK) {
                NSString *serverText=ZONString(raw[@"message"] ?: raw[@"msg"]); if(!serverText.length) serverText=message;
                ZONPromptCard(udid,serverText); return;
            }
            ZONLoadAuthorizedState(udid, ^(NSDictionary *license, NSDictionary *verify) {
                // 只有服务器确认 UDID 已拥有有效授权后，才持久化成功态。
                [ZONStorage setUDID:udid];
                [ZONStorage setCard:card];
                [ZONStorage setLastActivationObject:raw?:@{}];
                [ZONStorage setLastVerify:verify];

                NSDictionary *success=ZONActivationSuccessObject(raw?:@{},license,verify);
                NSString *title=ZONString(raw[@"title"] ?: raw[@"message"] ?: raw[@"msg"]);
                if(!title.length) title=@"激活成功";
                NSString *text=[ZONResponseFormatter displayTextForDictionary:success];
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.25*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
                    [ui showText:text title:title completion:^{ZONShowFirstActivationPostFlow(udid,license,verify);}];
                });
            }, ^(NSString *verifyFailure) {
                NSString *serverText=ZONString(raw[@"message"] ?: raw[@"msg"]);
                if(!serverText.length) serverText=verifyFailure;
                ZONPromptCard(udid,serverText);
            });
        }];
    }];
}

static void ZONRoute(void) {
    NSString *udid=[ZONStorage udid];
    NSString *card=[ZONStorage card];
    if(udid.length && card.length) { ZONOpenAuthorizationCenter(udid); return; }
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

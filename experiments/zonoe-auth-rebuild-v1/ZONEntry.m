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

static NSString *ZONDateText(double epoch) {
    if(epoch<=0) return @"";
    NSDateFormatter *f=[NSDateFormatter new];
    f.locale=[NSLocale localeWithLocaleIdentifier:@"zh_CN"];
    f.dateFormat=@"yyyy-MM-dd HH:mm:ss";
    return [f stringFromDate:[NSDate dateWithTimeIntervalSince1970:epoch]]?:@"";
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
    if([auths isKindOfClass:NSArray.class] && [(NSArray *)auths count]>0) {
        double now=NSDate.date.timeIntervalSince1970;
        for(id item in (NSArray *)auths) {
            if(![item isKindOfClass:NSDictionary.class]) continue;
            id expireObj=ZONFirstValueForKeys(item,@[@"expire",@"expires_at",@"expire_time"]);
            double expire=[ZONString(expireObj) doubleValue];
            if(expire<=0 || expire>now) return YES;
        }
    }
    id status=ZONFirstValueForKeys(license,@[@"status",@"active",@"authorized",@"valid"]);
    id expireObj=ZONFirstValueForKeys(license,@[@"expire",@"expires_at",@"expire_time"]);
    double expire=[ZONString(expireObj) doubleValue];
    if([status respondsToSelector:@selector(boolValue)] && [status boolValue] && (expire<=0 || expire>NSDate.date.timeIntervalSince1970)) return YES;
    return expire>NSDate.date.timeIntervalSince1970;
}

static id ZONLicenseProjection(id obj) {
    if([obj isKindOfClass:NSArray.class]) {
        NSMutableArray *a=[NSMutableArray array];
        for(id v in (NSArray *)obj) [a addObject:ZONLicenseProjection(v)?:NSNull.null];
        return a.copy;
    }
    if(![obj isKindOfClass:NSDictionary.class]) return obj?:NSNull.null;
    NSDictionary *d=obj;
    NSArray *wanted=@[@"authorizations",@"expire",@"expires_at",@"expire_time",@"status",@"active",@"authorized",@"valid",@"scope",@"type",@"access_level",@"permissions"];
    NSMutableDictionary *out=[NSMutableDictionary dictionary];
    for(NSString *k in wanted) { id v=d[k]; if(v && v!=NSNull.null) out[k]=ZONLicenseProjection(v); }
    return out.copy;
}

static NSString *ZONLicenseFingerprint(NSDictionary *license) {
    id p=ZONLicenseProjection(license?:@{});
    if(![NSJSONSerialization isValidJSONObject:p]) return [p description]?:@"";
    NSData *data=[NSJSONSerialization dataWithJSONObject:p options:NSJSONWritingSortedKeys error:nil];
    return data?[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]:@"";
}

static NSDictionary *ZONCenterObject(NSString *udid, NSDictionary *license, NSDictionary *verify) {
    NSMutableDictionary *out=[NSMutableDictionary dictionary];
    if(udid.length) out[@"udid"]=udid;
    id auths=license[@"authorizations"]; if(auths && auths!=NSNull.null) out[@"authorizations"]=auths;
    id expire=ZONFirstValueForKeys(license,@[@"expire",@"expires_at",@"expire_time"]);
    double end=[ZONString(expire) doubleValue];
    if(end>0) out[@"expires_at"]=ZONDateText(end);
    id type=ZONFirstValueForKeys(license,@[@"type"]); if(type) out[@"type"]=type;
    id status=ZONFirstValueForKeys(license,@[@"status"]); if(status) out[@"status"]=status;
    NSArray *keys=@[@"access_level",@"permissions",@"code",@"action",@"message",@"offline_grace_seconds"];
    for(NSString *key in keys) { id v=verify[key]; if(v && v!=NSNull.null) out[key]=v; }
    id remaining=ZONFirstValueForKeys(license,@[@"remaining_seconds",@"remaining_time",@"remaining"]);
    if(remaining) out[@"remaining_seconds"]=remaining;
    else if(end>0) {
        double now=[verify[@"server_time"] respondsToSelector:@selector(doubleValue)]?[verify[@"server_time"] doubleValue]:NSDate.date.timeIntervalSince1970;
        out[@"remaining_seconds"]=@(MAX(0,end-now));
    }
    return out.copy;
}

static NSDictionary *ZONActivationSuccessObject(NSDictionary *raw, NSDictionary *license, NSDictionary *verify) {
    NSMutableDictionary *out=[NSMutableDictionary dictionary];
    id msg=raw[@"message"] ?: raw[@"msg"]; if(msg && msg!=NSNull.null) out[@"message"]=msg;
    id expire=ZONFirstValueForKeys(license,@[@"expire",@"expires_at",@"expire_time"]);
    double end=[ZONString(expire) doubleValue];
    if(end>0) out[@"expires_at"]=ZONDateText(end);
    id remaining=ZONFirstValueForKeys(license,@[@"remaining_seconds",@"remaining_time",@"remaining"]);
    if(remaining) out[@"remaining_seconds"]=remaining;
    else if(end>0) {
        double now=[verify[@"server_time"] respondsToSelector:@selector(doubleValue)]?[verify[@"server_time"] doubleValue]:NSDate.date.timeIntervalSince1970;
        out[@"remaining_seconds"]=@(MAX(0,end-now));
    }
    id level=verify[@"access_level"]; if(level && level!=NSNull.null) out[@"access_level"]=level;
    id permissions=verify[@"permissions"]; if(permissions && permissions!=NSNull.null) out[@"permissions"]=permissions;
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

typedef void (^ZONStateOK)(NSDictionary *license, NSDictionary *verify);
typedef void (^ZONStateFail)(NSString *message, BOOL authorizationInvalid);

static void ZONLoadAuthorizedState(NSString *udid, ZONStateOK completion, ZONStateFail failure) {
    [ZONLicenseStatus fetchForUDID:udid completion:^(NSDictionary *license, BOOL ignored, NSError *licenseError) {
        if(licenseError) { if(failure) failure(licenseError.localizedDescription?:@"网络错误",NO); return; }
        if(!ZONLicenseIsAuthorized(license)) {
            NSString *m=ZONString(license[@"message"] ?: license[@"msg"]);
            if(failure) failure(m.length?m:@"授权状态无效",YES);
            return;
        }
        [ZONVerify runWithUDID:udid completion:^(NSDictionary *verify) {
            BOOL verifyOK=[verify[@"ok"] respondsToSelector:@selector(boolValue)]?[verify[@"ok"] boolValue]:NO;
            if(!verifyOK) {
                NSString *m=ZONString(verify[@"message"] ?: verify[@"code"]);
                if(failure) failure(m.length?m:@"授权状态无效",YES);
                return;
            }
            [ZONStorage setLastVerify:verify];
            if(completion) completion(license?:@{},verify?:@{});
        }];
    }];
}

static void ZONPromptCard(NSString *udid, NSString *serverMessage);

static void ZONOpenAuthorizationCenter(NSString *udid) {
    ZONLoadAuthorizedState(udid, ^(NSDictionary *license, NSDictionary *verify){
        ZONShowCenter(udid,license,verify);
    }, ^(NSString *message, BOOL authorizationInvalid){
        if(authorizationInvalid) {
            [ZONStorage clearCardState];
            ZONPromptCard(udid,message);
        } else {
            [[ZONUI shared] showText:message title:@"授权状态" completion:nil];
        }
    });
}

static void ZONPromptCard(NSString *udid, NSString *serverMessage) {
    ZONUI *ui=[ZONUI shared];
    [ui requestCardWithServerMessage:serverMessage completion:^(NSString *card) {
        if(!card.length) return;

        [ZONLicenseStatus fetchForUDID:udid completion:^(NSDictionary *beforeLicense, BOOL ignoredBefore, NSError *beforeError) {
            BOOL beforeAuthorized=!beforeError && ZONLicenseIsAuthorized(beforeLicense);
            NSString *beforeFingerprint=beforeError?@"":ZONLicenseFingerprint(beforeLicense?:@{});

            [ZONActivation activateUDID:udid card:card completion:^(BOOL requestOK, NSString *message, NSDictionary *raw) {
                if(!requestOK) {
                    NSString *serverText=ZONString(raw[@"message"] ?: raw[@"msg"]); if(!serverText.length) serverText=message;
                    ZONPromptCard(udid,serverText); return;
                }

                [ZONLicenseStatus fetchForUDID:udid completion:^(NSDictionary *afterLicense, BOOL ignoredAfter, NSError *afterError) {
                    if(afterError) {
                        NSString *serverText=ZONString(raw[@"message"] ?: raw[@"msg"]); if(!serverText.length) serverText=afterError.localizedDescription;
                        ZONPromptCard(udid,serverText); return;
                    }

                    BOOL afterAuthorized=ZONLicenseIsAuthorized(afterLicense);
                    NSString *afterFingerprint=ZONLicenseFingerprint(afterLicense?:@{});
                    BOOL stateChanged=!beforeAuthorized ? afterAuthorized : ![beforeFingerprint isEqualToString:afterFingerprint];

                    if(!afterAuthorized || !stateChanged) {
                        NSString *serverText=ZONString(raw[@"message"] ?: raw[@"msg"]);
                        if(!serverText.length) serverText=@"授权状态未发生变化";
                        ZONPromptCard(udid,serverText);
                        return;
                    }

                    [ZONVerify runWithUDID:udid completion:^(NSDictionary *verify) {
                        BOOL verifyOK=[verify[@"ok"] respondsToSelector:@selector(boolValue)]?[verify[@"ok"] boolValue]:NO;
                        if(!verifyOK) {
                            NSString *serverText=ZONString(verify[@"message"] ?: verify[@"code"]);
                            if(!serverText.length) serverText=@"授权验证失败";
                            ZONPromptCard(udid,serverText);
                            return;
                        }

                        [ZONStorage setUDID:udid];
                        [ZONStorage setCard:card];
                        [ZONStorage setLastActivationObject:raw?:@{}];
                        [ZONStorage setLastVerify:verify];

                        NSDictionary *success=ZONActivationSuccessObject(raw?:@{},afterLicense,verify);
                        NSString *title=ZONString(raw[@"title"]);
                        if(!title.length) title=@"激活成功";
                        NSString *text=[ZONResponseFormatter displayTextForDictionary:success];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.25*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
                            [ui showText:text title:title completion:^{ZONShowFirstActivationPostFlow(udid,afterLicense,verify);}];
                        });
                    }];
                }];
            }];
        }];
    }];
}

static void ZONRoute(void) {
    NSString *udid=[ZONStorage udid];
    NSString *card=[ZONStorage card];
    if(udid.length && card.length) { ZONOpenAuthorizationCenter(udid); return; }
    if(udid.length) { ZONPromptCard(udid,nil); return; }
    ZONUI *ui=[ZONUI shared];
    [ui requestUDID:nil completion:^(NSString *inputUDID) {
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

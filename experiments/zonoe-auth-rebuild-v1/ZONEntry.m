#import <Foundation/Foundation.h>
#import "ZONUI.h"
#import "ZONAuthorization.h"
#import "ZONActivation.h"
#import "ZONLicenseStatus.h"
#import "ZONVerify.h"
#import "ZONStorage.h"
#import "ZONResponseFormatter.h"

static BOOL ZONResultExplicitSuccess(NSDictionary *d) {
    id ok=d[@"ok"];
    if([ok respondsToSelector:@selector(boolValue)]) return [ok boolValue];
    NSString *code=[d[@"code"] isKindOfClass:NSString.class]?[d[@"code"] lowercaseString]:@"";
    return [code isEqualToString:@"ok"]||[code isEqualToString:@"success"]||[code isEqualToString:@"authorized"]||[code isEqualToString:@"active"]||[code isEqualToString:@"activated"]||[code isEqualToString:@"bound"];
}

static NSString *ZONServerMessage(NSDictionary *d, NSString *fallback) {
    id m=d[@"message"]?:d[@"msg"];
    return [m isKindOfClass:NSString.class]&&[m length]?m:(fallback?:@"服务器未返回消息");
}

static void ZONShowNoticeThenFinish(NSString *udid) {
    [ZONVerify runWithUDID:udid completion:^(NSDictionary *verify) {
        [ZONStorage setLastVerify:verify];
        id notice=verify[@"notice"];
        if(notice && notice!=NSNull.null) [[ZONUI shared] showNoticeObject:notice completion:nil];
    }];
}

static void ZONShowAuthorizationCenter(NSString *udid) {
    ZONUI *ui=[ZONUI shared];
    [ZONLicenseStatus fetchForUDID:udid completion:^(NSDictionary *license, BOOL signatureValid, NSError *error) {
        if(error){ [ui showText:error.localizedDescription?:@"授权状态查询失败" title:@"授权状态" completion:nil]; return; }
        [ZONVerify runWithUDID:udid completion:^(NSDictionary *verify) {
            [ZONStorage setLastVerify:verify];
            NSMutableDictionary *all=[NSMutableDictionary dictionary];
            all[@"udid"]=udid?:@"";
            all[@"authorization_status"]=license?:@{};
            all[@"verify"]=verify?:@{};
            all[@"hmac_signature_valid"]=@(signatureValid);
            NSString *text=[ZONResponseFormatter displayTextForDictionary:all];
            [ui showAuthorizationText:text clearCard:^{ [ZONStorage clearCardState]; } clearUDID:^{ [ZONStorage clearUDIDState]; } completion:nil];
        }];
    }];
}

static void ZONFinishSuccessfulCardFlow(NSString *udid, NSString *card, NSDictionary *serverResult) {
    [ZONStorage setUDID:udid];
    [ZONStorage setCard:card];
    [ZONStorage setLastActivationObject:serverResult];
    NSString *text=[ZONResponseFormatter displayTextForDictionary:serverResult];
    [[ZONUI shared] showText:text title:@"激活成功" completion:^{ ZONShowNoticeThenFinish(udid); }];
}

static void ZONPromptCard(NSString *udid, NSString *serverMessage);

static void ZONHandleAuthorizationResult(NSString *udid, NSString *card, NSDictionary *result) {
    ZONUI *ui=[ZONUI shared];
    BOOL needsActivation=[ZONAuthorization resultNeedsActivation:result];
    if(needsActivation){
        [ZONActivation activateUDID:udid card:card completion:^(BOOL ok, NSString *message, NSDictionary *raw) {
            if(!ok){ ZONPromptCard(udid, ZONServerMessage(raw,message)); return; }
            ZONFinishSuccessfulCardFlow(udid,card,raw?:@{});
        }];
        return;
    }
    if(!ZONResultExplicitSuccess(result)){
        ZONPromptCard(udid,ZONServerMessage(result,@"卡密或设备授权无效"));
        return;
    }
    ZONFinishSuccessfulCardFlow(udid,card,result);
}

static void ZONPromptCard(NSString *udid, NSString *serverMessage) {
    ZONUI *ui=[ZONUI shared];
    [ui requestCardWithServerMessage:serverMessage completion:^(NSString *card) {
        if(!card.length) return;
        [ZONAuthorization queryCard:card udid:udid completion:^(NSDictionary *result, NSError *error) {
            if(error){ ZONPromptCard(udid,error.localizedDescription?:@"网络错误"); return; }
            ZONHandleAuthorizationResult(udid,card,result?:@{});
        }];
    }];
}

static void ZONRouteFromFloatingWindow(void) {
    NSString *udid=[ZONStorage udid];
    NSString *card=[ZONStorage card];
    if(udid.length && card.length){ ZONShowAuthorizationCenter(udid); return; }
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
        ui.tapHandler=^{ ZONRouteFromFloatingWindow(); };
    });
}

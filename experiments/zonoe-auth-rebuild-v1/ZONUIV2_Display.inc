- (void)showInfo:(NSDictionary *)info title:(NSString *)title {
    NSDictionary *verify=[info[@"verify"] isKindOfClass:NSDictionary.class]?info[@"verify"]:nil;
    if(verify){
        [ZONStorage setLastVerify:verify];
        if([ZONStorage justActivated]){
            [ZONStorage setJustActivated:NO];
            NSString *activation=[ZONResponseFormatter displayTextForObject:[ZONStorage lastActivationObject]];
            id notice=verify[@"notice"];
            __weak typeof(self)w=self;
            [self showText:activation title:@"激活成功" completion:^{[w showNoticeObject:notice completion:nil];}];
            return;
        }
        BOOL allowed=[verify[@"ok"] boolValue]||[verify[@"allowed"] boolValue];
        if(!allowed){
            NSString *code=[verify[@"code"] isKindOfClass:NSString.class]?verify[@"code"]:@"";
            if([code isEqualToString:@"license_invalid"])[ZONStorage clearCardState];
            [self showText:[ZONResponseFormatter displayTextForDictionary:verify] title:@"验证结果" completion:nil];
            return;
        }
        NSMutableDictionary *d=[verify mutableCopy];
        NSString *udid=[info[@"udid"] isKindOfClass:NSString.class]?info[@"udid"]:[ZONStorage udid]; if(udid.length)d[@"udid"]=udid;
        [self showAuthorizationText:[ZONResponseFormatter displayTextForDictionary:d] clearCard:^{[ZONStorage clearCardState];} clearUDID:^{[ZONStorage clearUDIDState];} completion:nil];
        return;
    }
    if(![info[@"success"] boolValue]){
        id raw=info[@"raw"]; NSString *message=[info[@"message"] isKindOfClass:NSString.class]?info[@"message"]:@"";
        NSString *text=(raw&&raw!=NSNull.null)?[ZONResponseFormatter displayTextForObject:raw]:message;
        void(^retry)(NSString*)=self.lastCardCompletion; __weak typeof(self)w=self;
        [self showText:text.length?text:message title:title.length?title:@"激活结果" completion:^{if(retry)[w requestCardWithServerMessage:text completion:retry];}];
        return;
    }
    [self showText:[ZONResponseFormatter displayTextForDictionary:info] title:title completion:nil];
}
@end

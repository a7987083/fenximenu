- (void)requestUDID:(NSString *)prefill completion:(void (^)(NSString *))cb {
    UIAlertController *a=[UIAlertController alertControllerWithTitle:@"设备验证" message:@"请输入设备 UDID" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField*t){t.text=prefill?:@"";t.placeholder=@"请输入 UDID";t.autocorrectionType=UITextAutocorrectionTypeNo;t.autocapitalizationType=UITextAutocapitalizationTypeNone;}];
    __weak typeof(self)w=self;
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(UIAlertAction*x){[w end];if(cb)cb(nil);}]];
    [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction*x){NSString*s=[a.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];[w end];if(cb)cb(s.length?s:nil);}]];
    [self alert:a];
}
- (void)requestCardWithCompletion:(void (^)(NSString *))cb { self.lastCardCompletion=cb; [self requestCardWithServerMessage:nil completion:cb]; }
- (void)requestCardWithServerMessage:(NSString *)msg completion:(void (^)(NSString *))cb {
    UIAlertController *a=[UIAlertController alertControllerWithTitle:@"卡密激活" message:msg.length?msg:@"请输入卡密" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField*t){t.placeholder=@"请输入卡密";t.autocorrectionType=UITextAutocorrectionTypeNo;t.autocapitalizationType=UITextAutocapitalizationTypeNone;}];
    __weak typeof(self)w=self;
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(UIAlertAction*x){[w end];if(cb)cb(nil);}]];
    [a addAction:[UIAlertAction actionWithTitle:@"激活" style:UIAlertActionStyleDefault handler:^(UIAlertAction*x){NSString*s=[a.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];[w end];if(cb)cb(s.length?s:nil);}]];
    [self alert:a];
}
- (void)showText:(NSString *)text title:(NSString *)title completion:(dispatch_block_t)cb {
    UIAlertController *a=[UIAlertController alertControllerWithTitle:title?:@"提示" message:text?:@"" preferredStyle:UIAlertControllerStyleAlert];
    __weak typeof(self)w=self;
    [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction*x){[w end];if(cb)dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(.35*NSEC_PER_SEC)),dispatch_get_main_queue(),cb);}]];
    [self alert:a];
}
- (void)showNoticeObject:(id)n completion:(dispatch_block_t)cb {
    if(!n||n==NSNull.null){if(cb)cb();return;}
    [self showText:[ZONResponseFormatter displayTextForObject:n] title:[ZONResponseFormatter titleForNotice:n fallback:@"公告"] completion:cb];
}
- (void)showAuthorizationText:(NSString *)text clearCard:(dispatch_block_t)c1 clearUDID:(dispatch_block_t)c2 completion:(dispatch_block_t)cb {
    dispatch_async(dispatch_get_main_queue(),^{if(self.root.presentedViewController)return;[self begin];ZONCenterVC*v=[ZONCenterVC new];v.body=text;__weak typeof(self)w=self;v.clearCard=c1;v.clearUDID=c2;v.done=^{[w end];if(cb)cb();};v.modalPresentationStyle=UIModalPresentationPageSheet;[self.root presentViewController:v animated:YES completion:nil];});
}

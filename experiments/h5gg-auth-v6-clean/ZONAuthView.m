#import "ZONAuthView.h"

@implementation ZONAuthView

+ (void)presentUDIDFrom:(UIViewController *)viewController
              prefilled:(NSString *)prefilled
             completion:(ZONStringCompletion)completion
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"UDID"
                                                                   message:@"请输入设备 UDID"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"请输入 UDID";
        field.text = prefilled ?: @"";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
        field.autocorrectionType = UITextAutocorrectionTypeNo;
        field.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(__unused UIAlertAction *action) {
        if (completion) completion(nil);
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"确认" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
        NSString *value = [alert.textFields.firstObject.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (completion) completion(value.length ? value : nil);
    }]];
    [viewController presentViewController:alert animated:YES completion:nil];
}

+ (void)presentCardFrom:(UIViewController *)viewController
                message:(NSString *)message
             completion:(ZONStringCompletion)completion
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"卡密激活"
                                                                   message:message.length ? message : @"请输入卡密"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"请输入卡密";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
        field.autocorrectionType = UITextAutocorrectionTypeNo;
        field.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(__unused UIAlertAction *action) {
        if (completion) completion(nil);
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"确认激活" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
        NSString *value = [alert.textFields.firstObject.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (completion) completion(value.length ? value : nil);
    }]];
    [viewController presentViewController:alert animated:YES completion:nil];
}

+ (void)presentMessageFrom:(UIViewController *)viewController
                     title:(NSString *)title
                   message:(NSString *)message
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title ?: @"提示"
                                                                   message:message ?: @""
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
    [viewController presentViewController:alert animated:YES completion:nil];
}

@end

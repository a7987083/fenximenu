#import "ZONUDIDPrompt.h"

@implementation ZONUDIDPrompt

+ (void)presentFrom:(UIViewController *)viewController
          prefilled:(NSString *)prefilled
         completion:(void (^)(NSString * _Nullable))completion
{
    if (!viewController) {
        if (completion) completion(nil);
        return;
    }

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"UDID"
                                                                   message:@"请输入设备 UDID"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"例如：00008120-...";
        field.text = prefilled ?: @"";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
        field.autocorrectionType = UITextAutocorrectionTypeNo;
        field.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];

    [alert addAction:[UIAlertAction actionWithTitle:@"取消"
                                              style:UIAlertActionStyleCancel
                                            handler:^(__unused UIAlertAction *action) {
        if (completion) completion(nil);
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"确认"
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction *action) {
        NSString *value = [alert.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (completion) completion(value.length ? value : nil);
    }]];

    [viewController presentViewController:alert animated:YES completion:nil];
}

@end

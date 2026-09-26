#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^ZONTextInputCompletion)(NSString * _Nullable value);

@interface ZONAuthView : NSObject
+ (void)presentUDIDFrom:(UIViewController *)presenter
              prefilled:(nullable NSString *)prefilled
             completion:(ZONTextInputCompletion)completion;
+ (void)presentCardFrom:(UIViewController *)presenter
                 reason:(nullable NSString *)reason
             completion:(ZONTextInputCompletion)completion;
+ (void)presentMessageFrom:(UIViewController *)presenter
                     title:(NSString *)title
                   message:(NSString *)message;
@end

NS_ASSUME_NONNULL_END

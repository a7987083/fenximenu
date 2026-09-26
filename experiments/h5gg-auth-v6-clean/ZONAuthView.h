#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^ZONStringCompletion)(NSString * _Nullable value);

@interface ZONAuthView : NSObject
+ (void)presentUDIDFrom:(UIViewController *)viewController
              prefilled:(nullable NSString *)prefilled
             completion:(ZONStringCompletion)completion;
+ (void)presentCardFrom:(UIViewController *)viewController
                message:(nullable NSString *)message
             completion:(ZONStringCompletion)completion;
+ (void)presentMessageFrom:(UIViewController *)viewController
                     title:(NSString *)title
                   message:(NSString *)message;
@end

NS_ASSUME_NONNULL_END

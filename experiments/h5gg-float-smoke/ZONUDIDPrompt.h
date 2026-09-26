#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZONUDIDPrompt : NSObject
+ (void)presentFrom:(UIViewController *)viewController
          prefilled:(nullable NSString *)prefilled
         completion:(void (^)(NSString * _Nullable udid))completion;
@end

NS_ASSUME_NONNULL_END

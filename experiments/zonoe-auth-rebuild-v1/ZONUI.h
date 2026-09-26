#import <UIKit/UIKit.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONUI : NSObject
+ (instancetype)shared;
- (void)installFloatingButton;
- (void)requestUDID:(NSString * _Nullable)prefill completion:(void (^)(NSString * _Nullable udid))completion;
- (void)requestCardWithCompletion:(void (^)(NSString * _Nullable card))completion;
- (void)showInfo:(NSDictionary *)info title:(NSString *)title;
@property (nonatomic, copy) dispatch_block_t tapHandler;
@end
NS_ASSUME_NONNULL_END

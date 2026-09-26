#import <UIKit/UIKit.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONUI : NSObject
+ (instancetype)shared;
- (void)installFloatingButton;
- (void)requestUDID:(NSString * _Nullable)prefill completion:(void (^)(NSString * _Nullable udid))completion;
- (void)requestCardWithCompletion:(void (^)(NSString * _Nullable card))completion;
- (void)requestCardWithServerMessage:(NSString * _Nullable)serverMessage completion:(void (^)(NSString * _Nullable card))completion;
- (void)showInfo:(NSDictionary *)info title:(NSString *)title;
- (void)showText:(NSString *)text title:(NSString *)title completion:(dispatch_block_t _Nullable)completion;
- (void)showNoticeObject:(id _Nullable)notice completion:(dispatch_block_t _Nullable)completion;
- (void)showAuthorizationText:(NSString *)text clearCard:(dispatch_block_t)clearCard clearUDID:(dispatch_block_t)clearUDID completion:(dispatch_block_t _Nullable)completion;
@property(nonatomic,copy) dispatch_block_t tapHandler;
@end
NS_ASSUME_NONNULL_END

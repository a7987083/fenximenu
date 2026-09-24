#import <UIKit/UIKit.h>

static NSString * const kHFAMapVisibleVersion258 = @"HFAMap v2.5.8-dev";

static void HFAApplyVisibleVersion258(void) {
    for (UIWindow *window in UIApplication.sharedApplication.windows) {
        NSMutableArray *stack = [NSMutableArray arrayWithObject:window];
        while (stack.count) {
            UIView *view = stack.lastObject; [stack removeLastObject];
            if ([view isKindOfClass:UILabel.class]) {
                UILabel *label = (UILabel *)view;
                if ([label.text hasPrefix:@"HFAMap v2.5."]) label.text = kHFAMapVisibleVersion258;
            }
            for (UIView *sub in view.subviews) [stack addObject:sub];
        }
    }
}

__attribute__((constructor))
static void HFAMapVersion258Constructor(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        for (NSUInteger i = 0; i < 20; ++i) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * i * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                HFAApplyVisibleVersion258();
            });
        }
    });
}

#import <Foundation/Foundation.h>
#import "ZONUI.h"
#import "ZONAPISmokeCenter.h"

__attribute__((constructor)) static void ZONStart(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.0*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
        ZONUI *ui=[ZONUI shared];
        [ui installFloatingButton];
        ui.tapHandler=^{ [[ZONAPISmokeCenter shared] present]; };
    });
}

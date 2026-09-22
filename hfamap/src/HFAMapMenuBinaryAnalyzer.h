#import <Foundation/Foundation.h>
#import <mach-o/loader.h>

NSDictionary *HFAMapAnalyzeMenuBinary(const struct mach_header_64 *header,
                                      intptr_t slide,
                                      NSTimeInterval deadline);

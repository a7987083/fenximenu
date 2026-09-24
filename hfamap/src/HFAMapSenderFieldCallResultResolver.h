#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSDictionary *HFAMapResolveSenderFieldCallResults(NSString *loadedMenuPath,
                                                                     NSDictionary *featureInventory,
                                                                     NSError **error);
FOUNDATION_EXPORT BOOL HFAMapPersistSenderFieldCallResults(NSDictionary *result, NSError **error);

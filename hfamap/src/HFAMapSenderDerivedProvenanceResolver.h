#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSDictionary *HFAMapResolveSenderDerivedProvenance(const void *implementation,
                                                                      NSString *implementationPath,
                                                                      NSDictionary *entryContext);
FOUNDATION_EXPORT BOOL HFAMapPersistSenderDerivedProvenance(NSDictionary *result, NSError **error);

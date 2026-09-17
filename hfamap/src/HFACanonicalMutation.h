#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString * const HFACanonicalMutationSchema;

void HFAIngestCanonicalPackage(NSArray *features,
                               NSDictionary *targets,
                               NSString *provider);
NSArray *HFACanonicalMutationSnapshot(void);
BOOL HFAFlushCanonicalMutations(void);
void HFAResetCanonicalMutations(void);

NS_ASSUME_NONNULL_END

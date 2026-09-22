#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Runtime-only IL2CPP metadata resolver. The implementation is derived from
// the proven ZNIL2CPPResolver / ZNIL2CPPHybridFinder design at
// UnitXP_SP3-Moonstone@a3b8db8651eaea23ec0ae7e5fca497e8f67bcf6c.
// It never invokes a managed method and never writes game state.
NSDictionary *HFAIL2CPPResolveInstrumentCandidates(NSDictionary * _Nullable context,
                                                    NSTimeInterval absoluteDeadline,
                                                    NSUInteger candidateLimit);

NS_ASSUME_NONNULL_END

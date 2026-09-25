from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
source = (SRC / "HFAMapMenuImplementationInventory.mm").read_text()

source = source.replace(
    '#import "HFAMapOutputName.h"\n',
    '#import "HFAMapOutputName.h"\n#import "HFAMapDiagnostics.h"\n',
    1,
)

source = source.replace(
    'static const NSUInteger kHFAImplementationMaxActionsPerFeature = 16;\nstatic const NSUInteger kHFAImplementationMaxEvidenceDepth = 10;\n',
    'static const NSUInteger kHFAImplementationMaxActionsPerFeature = 16;\n'
    'static const NSUInteger kHFAImplementationMaxEvidenceDepth = 10;\n'
    'static const NSUInteger kHFAImplementationMaxUniqueActions = 12;\n'
    'static const NSTimeInterval kHFAImplementationAnalysisBudgetSeconds = 3.0;\n',
    1,
)

old = '''    NSArray *patchRecords = HFAImplementationCanonicalPatches(canonicalPatchFeatures);\n    NSMutableArray *featureRecords = [NSMutableArray array];\n    NSUInteger runtimeMethodCount = 0, patchCount = 0, mutationCandidateCount = 0;\n'''
new = '''    NSArray *patchRecords = HFAImplementationCanonicalPatches(canonicalPatchFeatures);\n    NSMutableArray *featureRecords = [NSMutableArray array];\n    NSMutableDictionary *analysisCache = [NSMutableDictionary dictionary];\n    NSUInteger runtimeMethodCount = 0, patchCount = 0, mutationCandidateCount = 0;\n    NSUInteger uniqueActionAnalysisCount = 0, actionCacheHitCount = 0, actionBudgetSkipCount = 0;\n    NSTimeInterval analysisDeadline = NSDate.date.timeIntervalSince1970 + kHFAImplementationAnalysisBudgetSeconds;\n    HFADiagnosticsLog(@"menu-implementation-inventory", @"start", @{\n        @"loadedFeatureInputCount": @([featureInventory[@"featureCandidates"] count]),\n        @"uniqueActionLimit": @(kHFAImplementationMaxUniqueActions),\n        @"analysisBudgetSeconds": @(kHFAImplementationAnalysisBudgetSeconds)\n    });\n'''
if old not in source:
    raise SystemExit("v25201 inventory init anchor missing")
source = source.replace(old, new, 1)

old = '''                NSDictionary *analysis = HFAMapAnalyzeStrippedActionIMP((const void *)(uintptr_t)implementation, menuPath) ?: @{};\n                NSUInteger before = runtimeMethods.count;\n'''
new = '''                NSString *analysisKey = [NSString stringWithFormat:@"0x%llX", (unsigned long long)implementation];\n                NSDictionary *analysis = analysisCache[analysisKey];\n                BOOL cacheHit = analysis != nil;\n                BOOL budgetSkipped = NO;\n                if (cacheHit) {\n                    ++actionCacheHitCount;\n                    HFADiagnosticsLog(@"menu-implementation-inventory", @"action-cache-hit", @{\n                        @"implementation": analysisKey, @"feature": feature[@"title"] ?: @""\n                    });\n                } else if (uniqueActionAnalysisCount >= kHFAImplementationMaxUniqueActions ||\n                           NSDate.date.timeIntervalSince1970 >= analysisDeadline) {\n                    ++actionBudgetSkipCount;\n                    budgetSkipped = YES;\n                    analysis = @{ @"status": @"inventory-budget-skipped", @"analysisOnly": @YES,\n                                  @"canonicalEligible": @NO };\n                    HFADiagnosticsLog(@"menu-implementation-inventory", @"action-skipped-budget", @{\n                        @"implementation": analysisKey, @"feature": feature[@"title"] ?: @"",\n                        @"uniqueActionAnalysisCount": @(uniqueActionAnalysisCount)\n                    });\n                } else {\n                    ++uniqueActionAnalysisCount;\n                    HFADiagnosticsLog(@"menu-implementation-inventory", @"action-analysis-start", @{\n                        @"implementation": analysisKey, @"feature": feature[@"title"] ?: @"",\n                        @"uniqueActionAnalysisCount": @(uniqueActionAnalysisCount)\n                    });\n                    analysis = HFAMapAnalyzeStrippedActionIMP((const void *)(uintptr_t)implementation, menuPath) ?: @{};\n                    analysisCache[analysisKey] = analysis;\n                    HFADiagnosticsLog(@"menu-implementation-inventory", @"action-analysis-complete", @{\n                        @"implementation": analysisKey, @"feature": feature[@"title"] ?: @"",\n                        @"status": analysis[@"status"] ?: @"unknown",\n                        @"decodedInstructionCount": analysis[@"decodedInstructionCount"] ?: @0,\n                        @"callCount": analysis[@"callCount"] ?: @0\n                    });\n                }\n                NSUInteger before = runtimeMethods.count;\n'''
if old not in source:
    raise SystemExit("v25201 action analysis anchor missing")
source = source.replace(old, new, 1)

old = '''                    @"status": analysis[@"status"] ?: @"unknown"\n                }];\n'''
new = '''                    @"status": analysis[@"status"] ?: @"unknown",\n                    @"analysisCacheHit": @(cacheHit),\n                    @"analysisBudgetSkipped": @(budgetSkipped)\n                }];\n'''
if old not in source:
    raise SystemExit("v25201 action evidence anchor missing")
source = source.replace(old, new, 1)

old = '''            @"canonicalPatchInputCount": @(canonicalPatchFeatures.count),\n            @"loadedFeatureInputCount": @([featureInventory[@"featureCandidates"] count])\n        },\n'''
new = '''            @"canonicalPatchInputCount": @(canonicalPatchFeatures.count),\n            @"loadedFeatureInputCount": @([featureInventory[@"featureCandidates"] count]),\n            @"uniqueActionAnalysisCount": @(uniqueActionAnalysisCount),\n            @"actionCacheHitCount": @(actionCacheHitCount),\n            @"actionBudgetSkipCount": @(actionBudgetSkipCount),\n            @"analysisBudgetSeconds": @(kHFAImplementationAnalysisBudgetSeconds),\n            @"analysisTruncated": @(actionBudgetSkipCount > 0)\n        },\n'''
if old not in source:
    raise SystemExit("v25201 summary anchor missing")
source = source.replace(old, new, 1)

source = source.replace(
    '@"buildVersion": @"2.5.20-dev",\n        @"componentVersion": @"2.5.20-dev-menu-implementation-inventory",',
    '@"buildVersion": @"2.5.20.1-dev",\n        @"componentVersion": @"2.5.20.1-dev-menu-implementation-inventory-cache",',
    1,
)
source = source.replace(
    '@"stateMutationCandidateIsNotProofOfWrite": @YES\n        }\n    };',
    '@"stateMutationCandidateIsNotProofOfWrite": @YES,\n            @"sharedImplementationAnalysisCached": @YES,\n            @"boundedInventoryAnalysis": @YES\n        }\n    };',
    1,
)

out = SRC / "HFAMapMenuImplementationInventory25201.mm"
out.write_text("// GENERATED BY tools/generate_v25201_inventory_cache.py — do not edit directly.\n" + source)
print(out)

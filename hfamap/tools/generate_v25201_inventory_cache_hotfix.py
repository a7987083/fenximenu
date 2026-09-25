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
    'static const NSUInteger kHFAImplementationMaxEvidenceDepth = 10;\n',
    'static const NSUInteger kHFAImplementationMaxEvidenceDepth = 10;\n'
    'static const NSUInteger kHFAImplementationMaxUniqueActionAnalyses = 8;\n'
    'static const NSTimeInterval kHFAImplementationTotalBudgetSeconds = 5.0;\n',
    1,
)

old = '''    NSArray *patchRecords = HFAImplementationCanonicalPatches(canonicalPatchFeatures);\n    NSMutableArray *featureRecords = [NSMutableArray array];\n    NSUInteger runtimeMethodCount = 0, patchCount = 0, mutationCandidateCount = 0;\n\n    for (NSDictionary *feature in featureInventory[@"featureCandidates"] ?: @[]) {'''
new = '''    NSArray *patchRecords = HFAImplementationCanonicalPatches(canonicalPatchFeatures);\n    NSMutableArray *featureRecords = [NSMutableArray array];\n    NSMutableDictionary *analysisCache = [NSMutableDictionary dictionary];\n    NSUInteger runtimeMethodCount = 0, patchCount = 0, mutationCandidateCount = 0;\n    NSUInteger uniqueActionAnalysisCount = 0, actionAnalysisCacheHitCount = 0;\n    BOOL actionAnalysisBudgetExhausted = NO;\n    NSTimeInterval actionAnalysisDeadline = NSDate.date.timeIntervalSince1970 + kHFAImplementationTotalBudgetSeconds;\n    HFADiagnosticsLog(@"menu-implementation-inventory", @"start", @{\n        @"featureInputCount": @([featureInventory[@"featureCandidates"] count]),\n        @"maxUniqueActionAnalyses": @(kHFAImplementationMaxUniqueActionAnalyses),\n        @"totalBudgetSeconds": @(kHFAImplementationTotalBudgetSeconds)\n    });\n\n    for (NSDictionary *feature in featureInventory[@"featureCandidates"] ?: @[]) {'''
if old not in source:
    raise SystemExit("inventory setup anchor missing")
source = source.replace(old, new, 1)

old = '''                NSDictionary *analysis = HFAMapAnalyzeStrippedActionIMP((const void *)(uintptr_t)implementation, menuPath) ?: @{};\n                NSUInteger before = runtimeMethods.count;'''
new = '''                NSString *analysisKey = [NSString stringWithFormat:@"0x%llX", (unsigned long long)implementation];\n                NSDictionary *analysis = analysisCache[analysisKey];\n                if (analysis) {\n                    ++actionAnalysisCacheHitCount;\n                    HFADiagnosticsLog(@"menu-implementation-inventory", @"action-cache-hit", @{\n                        @"implementation": analysisKey, @"feature": feature[@"title"] ?: @""\n                    });\n                } else if (uniqueActionAnalysisCount >= kHFAImplementationMaxUniqueActionAnalyses ||\n                           NSDate.date.timeIntervalSince1970 > actionAnalysisDeadline) {\n                    actionAnalysisBudgetExhausted = YES;\n                    analysis = @{ @"status": @"inventory-analysis-budget-exhausted",\n                                  @"analysisOnly": @YES, @"canonicalEligible": @NO };\n                    HFADiagnosticsLog(@"menu-implementation-inventory", @"action-skipped-budget", @{\n                        @"implementation": analysisKey, @"feature": feature[@"title"] ?: @"",\n                        @"uniqueActionAnalysisCount": @(uniqueActionAnalysisCount)\n                    });\n                } else {\n                    HFADiagnosticsLog(@"menu-implementation-inventory", @"action-analysis-start", @{\n                        @"implementation": analysisKey, @"feature": feature[@"title"] ?: @""\n                    });\n                    analysis = HFAMapAnalyzeStrippedActionIMP((const void *)(uintptr_t)implementation, menuPath) ?: @{};\n                    analysisCache[analysisKey] = analysis;\n                    ++uniqueActionAnalysisCount;\n                    HFADiagnosticsLog(@"menu-implementation-inventory", @"action-analysis-complete", @{\n                        @"implementation": analysisKey, @"feature": feature[@"title"] ?: @"",\n                        @"decodedInstructionCount": analysis[@"decodedInstructionCount"] ?: @0,\n                        @"blockCount": analysis[@"blockCount"] ?: @0, @"callCount": analysis[@"callCount"] ?: @0,\n                        @"il2cppCorrelationCount": analysis[@"il2cppCorrelationCount"] ?: @0\n                    });\n                }\n                NSUInteger before = runtimeMethods.count;'''
if old not in source:
    raise SystemExit("action analysis anchor missing")
source = source.replace(old, new, 1)

source = source.replace('@"buildVersion": @"2.5.20-dev",', '@"buildVersion": @"2.5.20.1-dev",', 1)
source = source.replace('@"componentVersion": @"2.5.20-dev-menu-implementation-inventory",', '@"componentVersion": @"2.5.20.1-dev-menu-implementation-inventory-cache-hotfix",', 1)

old = '''            @"canonicalPatchInputCount": @(canonicalPatchFeatures.count),\n            @"loadedFeatureInputCount": @([featureInventory[@"featureCandidates"] count])\n        },'''
new = '''            @"canonicalPatchInputCount": @(canonicalPatchFeatures.count),\n            @"loadedFeatureInputCount": @([featureInventory[@"featureCandidates"] count]),\n            @"uniqueActionAnalysisCount": @(uniqueActionAnalysisCount),\n            @"actionAnalysisCacheHitCount": @(actionAnalysisCacheHitCount),\n            @"actionAnalysisBudgetExhausted": @(actionAnalysisBudgetExhausted)\n        },'''
if old not in source:
    raise SystemExit("summary anchor missing")
source = source.replace(old, new, 1)

old = '''        @"safety": @{\n            @"readOnly": @YES, @"selectorInvoked": @NO, @"blockInvoked": @NO,\n            @"hookInstalled": @NO, @"memoryWritten": @NO,\n            @"stateMutationCandidateIsNotProofOfWrite": @YES\n        }\n    };'''
new = '''        @"safety": @{\n            @"readOnly": @YES, @"selectorInvoked": @NO, @"blockInvoked": @NO,\n            @"hookInstalled": @NO, @"memoryWritten": @NO,\n            @"stateMutationCandidateIsNotProofOfWrite": @YES\n        }\n    };'''
# keep return block stable; completion logging is inserted before return expression instead.
if old not in source:
    raise SystemExit("safety anchor missing")

marker = '    return @{\n        @"schema": @"com.hfa.menu-implementation-inventory/v1",'
insert = '''    HFADiagnosticsLog(@"menu-implementation-inventory", @"complete", @{\n        @"featureCount": @(featureRecords.count), @"runtimeMethodCount": @(runtimeMethodCount),\n        @"memoryPatchCount": @(patchCount), @"stateMutationCandidateCount": @(mutationCandidateCount),\n        @"uniqueActionAnalysisCount": @(uniqueActionAnalysisCount),\n        @"actionAnalysisCacheHitCount": @(actionAnalysisCacheHitCount),\n        @"actionAnalysisBudgetExhausted": @(actionAnalysisBudgetExhausted)\n    });\n\n    return @{\n        @"schema": @"com.hfa.menu-implementation-inventory/v1",'''
if marker not in source:
    raise SystemExit("return anchor missing")
source = source.replace(marker, insert, 1)

out = SRC / "HFAMapMenuImplementationInventory25201.mm"
out.write_text("// GENERATED BY tools/generate_v25201_inventory_cache_hotfix.py — do not edit directly.\n" + source)
print(out)

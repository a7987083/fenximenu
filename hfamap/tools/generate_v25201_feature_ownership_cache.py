from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
source = (SRC / "HFAMapFeatureOwnershipCorrelator.mm").read_text()

source = source.replace(
    '#include <stdlib.h>\n',
    '#include <stdlib.h>\n\nstatic const NSUInteger kHFAOwnershipMaxUniqueActions = 12;\nstatic const NSTimeInterval kHFAOwnershipAnalysisBudgetSeconds = 3.0;\n',
    1,
)

old = '''static NSDictionary *HFAAnalyzeActionRecord(NSDictionary *action, NSString *menuPath) {\n    NSDictionary *impl = action[@"implementation"] ?: @{};\n    NSString *runtimeVA = impl[@"runtimeVA"] ?: @"";\n    uintptr_t pointer = HFAPointerFromHex(runtimeVA);\n    NSDictionary *analysis = pointer ? HFAMapAnalyzeStrippedActionIMP((const void *)pointer, menuPath) : @{};\n    return @{ @"event": action[@"event"] ?: @"",\n              @"selector": action[@"selector"] ?: @"",\n              @"targetToken": action[@"targetToken"] ?: @"",\n              @"targetClass": action[@"targetClass"] ?: @"",\n              @"implementation": impl,\n              @"analysis": analysis ?: @{},\n              @"analysisOnly": @YES,\n              @"invokedByAnalyzer": @NO };\n}\n'''
new = '''static NSDictionary *HFAAnalyzeActionRecordCached(NSDictionary *action, NSString *menuPath,\n                                                     NSMutableDictionary *cache,\n                                                     NSUInteger *uniqueCount,\n                                                     NSUInteger *cacheHitCount,\n                                                     NSUInteger *budgetSkipCount,\n                                                     NSTimeInterval deadline) {\n    NSDictionary *impl = action[@"implementation"] ?: @{};\n    NSString *runtimeVA = impl[@"runtimeVA"] ?: @"";\n    uintptr_t pointer = HFAPointerFromHex(runtimeVA);\n    NSString *key = pointer ? [NSString stringWithFormat:@"0x%llX", (unsigned long long)pointer] : @"";\n    NSDictionary *analysis = key.length ? cache[key] : nil;\n    BOOL cacheHit = analysis != nil;\n    BOOL budgetSkipped = NO;\n    if (cacheHit) {\n        if (cacheHitCount) ++(*cacheHitCount);\n        HFADiagnosticsLog(@"feature-ownership-correlator", @"action-cache-hit", @{ @"implementation": key });\n    } else if (!pointer) {\n        analysis = @{};\n    } else if ((uniqueCount && *uniqueCount >= kHFAOwnershipMaxUniqueActions) ||\n               NSDate.date.timeIntervalSince1970 >= deadline) {\n        if (budgetSkipCount) ++(*budgetSkipCount);\n        budgetSkipped = YES;\n        analysis = @{ @"status": @"ownership-budget-skipped", @"analysisOnly": @YES, @"canonicalEligible": @NO };\n        HFADiagnosticsLog(@"feature-ownership-correlator", @"action-skipped-budget", @{ @"implementation": key });\n    } else {\n        if (uniqueCount) ++(*uniqueCount);\n        HFADiagnosticsLog(@"feature-ownership-correlator", @"action-analysis-start", @{\n            @"implementation": key, @"uniqueActionAnalysisCount": @(uniqueCount ? *uniqueCount : 0)\n        });\n        analysis = HFAMapAnalyzeStrippedActionIMP((const void *)pointer, menuPath) ?: @{};\n        cache[key] = analysis;\n        HFADiagnosticsLog(@"feature-ownership-correlator", @"action-analysis-complete", @{\n            @"implementation": key, @"status": analysis[@"status"] ?: @"unknown",\n            @"decodedInstructionCount": analysis[@"decodedInstructionCount"] ?: @0,\n            @"callCount": analysis[@"callCount"] ?: @0\n        });\n    }\n    return @{ @"event": action[@"event"] ?: @"",\n              @"selector": action[@"selector"] ?: @"",\n              @"targetToken": action[@"targetToken"] ?: @"",\n              @"targetClass": action[@"targetClass"] ?: @"",\n              @"implementation": impl,\n              @"analysis": analysis ?: @{},\n              @"analysisCacheHit": @(cacheHit),\n              @"analysisBudgetSkipped": @(budgetSkipped),\n              @"analysisOnly": @YES,\n              @"invokedByAnalyzer": @NO };\n}\n'''
if old not in source:
    raise SystemExit("v25201 ownership helper anchor missing")
source = source.replace(old, new, 1)

old = '''    NSMutableArray *resolved = [NSMutableArray array];\n    NSUInteger exactBlockFeatureCount = 0;\n    NSUInteger actionAnalysisCount = 0;\n    NSUInteger editingActionCount = 0;\n'''
new = '''    NSMutableArray *resolved = [NSMutableArray array];\n    NSMutableDictionary *actionAnalysisCache = [NSMutableDictionary dictionary];\n    NSUInteger exactBlockFeatureCount = 0;\n    NSUInteger actionAnalysisCount = 0;\n    NSUInteger editingActionCount = 0;\n    NSUInteger uniqueActionAnalysisCount = 0, actionCacheHitCount = 0, actionBudgetSkipCount = 0;\n    NSTimeInterval analysisDeadline = NSDate.date.timeIntervalSince1970 + kHFAOwnershipAnalysisBudgetSeconds;\n    HFADiagnosticsLog(@"feature-ownership-correlator", @"start", @{\n        @"featureCount": @(features.count), @"uniqueActionLimit": @(kHFAOwnershipMaxUniqueActions),\n        @"analysisBudgetSeconds": @(kHFAOwnershipAnalysisBudgetSeconds)\n    });\n'''
if old not in source:
    raise SystemExit("v25201 ownership init anchor missing")
source = source.replace(old, new, 1)

old = '[actionAnalyses addObject:HFAAnalyzeActionRecord(action, loadedMenuPath)];'
new = '[actionAnalyses addObject:HFAAnalyzeActionRecordCached(action, loadedMenuPath, actionAnalysisCache, &uniqueActionAnalysisCount, &actionCacheHitCount, &actionBudgetSkipCount, analysisDeadline)];'
if old not in source:
    raise SystemExit("v25201 ownership call anchor missing")
source = source.replace(old, new, 1)

old = '''        @"summary": @{ @"featureCount": @(resolved.count),\n                        @"exactBlockFeatureCount": @(exactBlockFeatureCount),\n                        @"actionAnalysisCount": @(actionAnalysisCount),\n                        @"editingChangedActionCount": @(editingActionCount) },\n'''
new = '''        @"summary": @{ @"featureCount": @(resolved.count),\n                        @"exactBlockFeatureCount": @(exactBlockFeatureCount),\n                        @"actionAnalysisCount": @(actionAnalysisCount),\n                        @"editingChangedActionCount": @(editingActionCount),\n                        @"uniqueActionAnalysisCount": @(uniqueActionAnalysisCount),\n                        @"actionCacheHitCount": @(actionCacheHitCount),\n                        @"actionBudgetSkipCount": @(actionBudgetSkipCount),\n                        @"analysisBudgetSeconds": @(kHFAOwnershipAnalysisBudgetSeconds),\n                        @"analysisTruncated": @(actionBudgetSkipCount > 0) },\n'''
if old not in source:
    raise SystemExit("v25201 ownership summary anchor missing")
source = source.replace(old, new, 1)

source = source.replace('@"buildVersion": @"2.5.14-dev",', '@"buildVersion": @"2.5.20.1-dev",', 1)
source = source.replace('@"componentVersion": @"2.5.14-dev-feature-ownership-correlator",', '@"componentVersion": @"2.5.20.1-dev-feature-ownership-cache",', 1)
source = source.replace(
    '@"actionIMPAnalyzedStatically": @YES },',
    '@"actionIMPAnalyzedStatically": @YES, @"sharedImplementationAnalysisCached": @YES,\n                                 @"boundedAnalysisBudget": @YES },',
    1,
)

out = SRC / "HFAMapFeatureOwnershipCorrelator25201.mm"
out.write_text("// GENERATED BY tools/generate_v25201_feature_ownership_cache.py — do not edit directly.\n" + source)
print(out)

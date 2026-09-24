#import "HFAMapImportedDylibEvidenceAnalyzer.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

static const NSUInteger kHFAMaxEvidenceStrings = 4096;
static const NSUInteger kHFAMaxStringLength = 192;

static NSString *HFARoleForString(NSString *s) {
    if (!s.length) return @"unknown";
    NSString *l = s.lowercaseString;
    if ([l hasSuffix:@".dll"] || [l hasSuffix:@".exe"]) return @"assembly-like";
    if ([l hasSuffix:@".dylib"] || [l containsString:@".framework/"] || [l hasSuffix:@"framework"]) return @"target-image-like";
    if ([l containsString:@"offset"] || [l containsString:@"rva"] || [l containsString:@"address"]) return @"offset-expression-like";
    if ([l containsString:@"patch"] || [l containsString:@"hook"] || [l containsString:@"bytes"] || [l containsString:@"asm"]) return @"patch-primitive-like";
    if ([l containsString:@"method"] || [l containsString:@"class"] || [l containsString:@"namespace"] || [l containsString:@"assembly"]) return @"managed-identity-like";
    if ([s containsString:@":"] && s.length < 128) return @"selector-like";
    NSCharacterSet *ok = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ .$:+-/<>()[]"];
    if ([[s stringByTrimmingCharactersInSet:ok] length] == 0 && s.length >= 3 && s.length <= 80) return @"human-label-like";
    return @"literal";
}

static NSArray<NSDictionary *> *HFAExtractPrintableStrings(NSData *data) {
    const uint8_t *b = (const uint8_t *)data.bytes;
    NSUInteger n = data.length;
    NSMutableArray *out = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    NSUInteger i = 0;
    while (i < n && out.count < kHFAMaxEvidenceStrings) {
        while (i < n && (b[i] < 0x20 || b[i] > 0x7e)) i++;
        NSUInteger start = i;
        while (i < n && b[i] >= 0x20 && b[i] <= 0x7e && (i - start) < kHFAMaxStringLength) i++;
        NSUInteger len = i - start;
        if (len >= 3) {
            NSString *s = [[NSString alloc] initWithBytes:b + start length:len encoding:NSUTF8StringEncoding];
            if (s.length && ![seen containsObject:s]) {
                [seen addObject:s];
                [out addObject:@{ @"value": s, @"fileOffset": @(start), @"fileOffsetHex": [NSString stringWithFormat:@"0x%lX", (unsigned long)start], @"role": HFARoleForString(s) }];
            }
        }
        if (i == start) i++;
    }
    return out;
}

static NSArray *HFAFilterRole(NSArray *records, NSString *role) {
    NSMutableArray *out = [NSMutableArray array];
    for (NSDictionary *r in records) if ([r[@"role"] isEqualToString:role]) [out addObject:r];
    return out;
}

NSDictionary *HFAMapAnalyzeImportedDylibEvidence(NSString *path, NSDictionary *staticCatalog, NSError **error) {
    HFADiagnosticsLog(@"imported-dylib-evidence", @"start", @{ @"path": path ?: @"" });
    if (!path.length) {
        if (error) *error = [NSError errorWithDomain:@"com.hfa.imported-dylib-evidence" code:1 userInfo:@{NSLocalizedDescriptionKey:@"missing-path"}];
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:error];
    if (!data.length) return nil;
    NSArray *strings = HFAExtractPrintableStrings(data);
    NSDictionary *source = staticCatalog[@"source"] ?: @{};
    NSDictionary *evidence = @{
        @"schema": @"com.hfa.imported-dylib-evidence/v1",
        @"version": @"2.5.8-dev-universal-imported-dylib-evidence",
        @"policy": @"UNIVERSAL-ONLY-STRUCTURAL-EVIDENCE-NO-SAMPLE-SPECIAL-CASES",
        @"source": @{ @"path": path, @"fileName": path.lastPathComponent ?: @"dylib", @"size": @(data.length), @"uuid": source[@"uuid"] ?: @"" },
        @"stringEvidence": strings,
        @"featureEvidence": HFAFilterRole(strings, @"human-label-like"),
        @"patchEvidence": HFAFilterRole(strings, @"patch-primitive-like"),
        @"targetImageEvidence": HFAFilterRole(strings, @"target-image-like"),
        @"offsetEvidence": HFAFilterRole(strings, @"offset-expression-like"),
        @"methodEvidence": HFAFilterRole(strings, @"managed-identity-like"),
        @"assemblyEvidence": HFAFilterRole(strings, @"assembly-like"),
        @"selectorEvidence": HFAFilterRole(strings, @"selector-like"),
        @"staticCatalogRuntimeMethodCount": staticCatalog[@"runtimeMethodCount"] ?: @0,
        @"resolutionPolicy": @"Method+Offset | Method-only | Offset-only; ambiguous mappings fail closed"
    };
    HFADiagnosticsLog(@"imported-dylib-evidence", @"classified", @{
        @"featureEvidenceCount": @([evidence[@"featureEvidence"] count]),
        @"patchEvidenceCount": @([evidence[@"patchEvidence"] count]),
        @"targetImageEvidenceCount": @([evidence[@"targetImageEvidence"] count]),
        @"offsetEvidenceCount": @([evidence[@"offsetEvidence"] count]),
        @"methodEvidenceCount": @([evidence[@"methodEvidence"] count])
    });
    return evidence;
}

BOOL HFAMapPersistImportedDylibEvidence(NSDictionary *evidence, NSError **error) {
    if (!evidence) return NO;
    NSData *json = [NSJSONSerialization dataWithJSONObject:evidence options:NSJSONWritingPrettyPrinted error:error];
    if (!json) return NO;
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!docs.length) return NO;
    NSString *file = HFAOutputFileName(@"ImportedDylibEvidence.json");
    NSString *path = [docs stringByAppendingPathComponent:file];
    BOOL ok = [json writeToFile:path options:NSDataWritingAtomic error:error];
    HFADiagnosticsLog(@"imported-dylib-evidence", ok ? @"complete" : @"persist-failed", @{ @"output": path ?: @"", @"recordCount": @([evidence[@"stringEvidence"] count]) });
    return ok;
}

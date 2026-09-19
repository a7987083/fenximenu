#import "ZPAppIdentity.h"

static NSString *ZPSafeFilenameComponent(NSString *value) {
    if (![value isKindOfClass:[NSString class]] || !value.length) return @"unknown";
    NSMutableString *out = [NSMutableString string];
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"];
    BOOL lastUnderscore = NO;
    for (NSUInteger i = 0; i < value.length && out.length < 96; i++) {
        unichar c = [value characterAtIndex:i];
        if ([allowed characterIsMember:c]) {
            [out appendFormat:@"%C", c];
            lastUnderscore = NO;
        } else if (!lastUnderscore) {
            [out appendString:@"_"];
            lastUnderscore = YES;
        }
    }
    while ([out hasPrefix:@"_"]) [out deleteCharactersInRange:NSMakeRange(0, 1)];
    while ([out hasSuffix:@"_"]) [out deleteCharactersInRange:NSMakeRange(out.length - 1, 1)];
    return out.length ? out : @"unknown";
}

NSDictionary *ZPAppIdentity(void) {
    NSBundle *bundle = NSBundle.mainBundle;
    NSString *value = bundle.bundleIdentifier;
    NSString *source = @"CFBundleIdentifier";
    if (!value.length) {
        value = [bundle objectForInfoDictionaryKey:@"CFBundleDisplayName"];
        source = @"CFBundleDisplayName";
    }
    if (!value.length) {
        value = [bundle objectForInfoDictionaryKey:@"CFBundleName"];
        source = @"CFBundleName";
    }
    if (!value.length) { value = @"unknown"; source = @"fallback"; }
    return @{ @"source": source, @"value": value, @"safeValue": ZPSafeFilenameComponent(value) };
}

NSString *ZPLogStem(void) {
    return [NSString stringWithFormat:@"ZPatchIG_%@", ZPAppIdentity()[@"safeValue"] ?: @"unknown"];
}

NSString *ZPLogFilename(NSString *suffix) {
    NSString *clean = [suffix hasPrefix:@"_"] ? [suffix substringFromIndex:1] : (suffix ?: @"log");
    return [NSString stringWithFormat:@"%@_%@", ZPLogStem(), clean];
}

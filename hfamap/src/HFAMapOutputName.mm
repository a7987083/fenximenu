#import "HFAMapOutputName.h"

static NSString *HFAUsableName(id candidate) {
    if (![candidate isKindOfClass:NSString.class]) return nil;
    NSString *name = [candidate stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!name.length) return nil;
    NSMutableString *safe = [NSMutableString string];
    NSCharacterSet *bad = [NSCharacterSet characterSetWithCharactersInString:@"/\\:\n\r\t"];
    for (NSUInteger i = 0; i < name.length && safe.length < 80; ++i) {
        unichar c = [name characterAtIndex:i];
        unichar output = ([bad characterIsMember:c] || c < 32 || c == 127) ? (unichar)'_' : c;
        [safe appendFormat:@"%C", output];
    }
    return safe.length ? safe : nil;
}

NSString *HFAHostAppName(void) {
    static NSString *name;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSDictionary *info = NSBundle.mainBundle.infoDictionary;
        name = [(HFAUsableName(info[@"CFBundleDisplayName"])
                ?: HFAUsableName(info[@"CFBundleExecutable"])
                ?: HFAUsableName(NSProcessInfo.processInfo.processName)
                ?: @"UnknownApp") copy];
    });
    return name;
}

NSString *HFAOutputFileName(NSString *suffix) {
    return [NSString stringWithFormat:@"%@_HFAMap_%@", HFAHostAppName(), suffix];
}

#import "ZONUDIDStore.h"

static NSString * const kZONUDIDKey = @"ZONUDID";

@implementation ZONUDIDStore
+ (NSString *)storedUDID {
    NSString *value = [NSUserDefaults.standardUserDefaults stringForKey:kZONUDIDKey];
    return value.length ? value : nil;
}
+ (void)saveUDID:(NSString *)udid {
    NSString *value = [udid stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!value.length) return;
    [NSUserDefaults.standardUserDefaults setObject:value forKey:kZONUDIDKey];
}
+ (void)clearUDID {
    [NSUserDefaults.standardUserDefaults removeObjectForKey:kZONUDIDKey];
}
@end

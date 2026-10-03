#import "HFAMapOutputName.h"
#include <pthread.h>

static pthread_mutex_t gHFAOutputLock = PTHREAD_MUTEX_INITIALIZER;
static NSString *gHFAOutputTargetFileName;

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


void HFASetOutputTargetFileName(NSString *fileName) {
    NSString *safe = HFAUsableName(fileName.lastPathComponent ?: fileName);
    pthread_mutex_lock(&gHFAOutputLock);
    [gHFAOutputTargetFileName release];
    gHFAOutputTargetFileName = [safe copy];
    pthread_mutex_unlock(&gHFAOutputLock);
}

NSString *HFAOutputDirectoryPath(void) {
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                                NSUserDomainMask, YES) firstObject];
    pthread_mutex_lock(&gHFAOutputLock);
    NSString *target = [gHFAOutputTargetFileName copy];
    pthread_mutex_unlock(&gHFAOutputLock);
    if (!target.length) {
        [target release];
        return documents;
    }
    NSString *directory = [documents stringByAppendingPathComponent:target];
    [NSFileManager.defaultManager createDirectoryAtPath:directory
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:nil];
    [target release];
    return directory;
}

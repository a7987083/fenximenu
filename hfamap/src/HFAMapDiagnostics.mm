#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"
#import <UIKit/UIKit.h>
#include <pthread.h>

static pthread_mutex_t gHFADiagnosticsLock = PTHREAD_MUTEX_INITIALIZER;
static NSString *gHFASessionID;
static NSTimeInterval gHFAStartedAt;

static NSString *HFADocumentsPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                NSUserDomainMask, YES) firstObject];
}

static NSString *HFAJSONString(id value) {
    if (!value || ![NSJSONSerialization isValidJSONObject:value]) return @"{}";
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"{}";
}

static void HFAAppend(NSString *path, NSData *data) {
    if (!path.length || !data.length) return;
    NSFileManager *manager = NSFileManager.defaultManager;
    if (![manager fileExistsAtPath:path]) [manager createFileAtPath:path contents:nil attributes:nil];
    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!handle) return;
    @try { [handle seekToEndOfFile]; [handle writeData:data]; }
    @catch (__unused NSException *exception) {}
    @try { [handle closeFile]; } @catch (__unused NSException *exception) {}
}

NSString *HFADiagnosticsBeginSession(void) {
    pthread_mutex_lock(&gHFADiagnosticsLock);
    gHFASessionID = [NSUUID.UUID.UUIDString copy];
    gHFAStartedAt = NSDate.date.timeIntervalSince1970;
    NSString *session = gHFASessionID;
    pthread_mutex_unlock(&gHFADiagnosticsLock);
    HFADiagnosticsLog(@"session", @"start", @{
        @"version": @"2.4.3-dev-runtime-action-correlator",
        @"hostAppName": HFAHostAppName(),
        @"process": NSProcessInfo.processInfo.processName ?: @"?",
        @"os": UIDevice.currentDevice.systemVersion ?: @"?"
    });
    return session;
}

NSString *HFADiagnosticsSessionID(void) {
    pthread_mutex_lock(&gHFADiagnosticsLock);
    NSString *session = gHFASessionID ?: @"no-session";
    pthread_mutex_unlock(&gHFADiagnosticsLock);
    return session;
}

void HFADiagnosticsLog(NSString *stage, NSString *status, NSDictionary *details) {
    pthread_mutex_lock(&gHFADiagnosticsLock);
    NSString *session = gHFASessionID ?: @"no-session";
    NSTimeInterval now = NSDate.date.timeIntervalSince1970;
    NSTimeInterval elapsed = gHFAStartedAt > 0 ? (now - gHFAStartedAt) * 1000.0 : 0;
    NSMutableDictionary *record = [@{
        @"schema": @"com.hfa.diagnostic-event/v1",
        @"session": session,
        @"time": @(now),
        @"elapsedMs": @(elapsed),
        @"stage": stage ?: @"?",
        @"status": status ?: @"?",
        @"thread": NSThread.isMainThread ? @"main" : @"worker"
    } mutableCopy];
    if (details) [record addEntriesFromDictionary:details];

    NSString *json = [HFAJSONString(record) stringByAppendingString:@"\n"];
    NSString *plain = [NSString stringWithFormat:@"[%@] [+%.1fms] [%@/%@] %@\n",
                       session, elapsed, stage ?: @"?", status ?: @"?",
                       HFAJSONString(details ?: @{})];
    NSString *documents = HFADocumentsPath();
    HFAAppend([documents stringByAppendingPathComponent:HFAOutputFileName(@"Diagnostics.jsonl")],
              [json dataUsingEncoding:NSUTF8StringEncoding]);
    HFAAppend([documents stringByAppendingPathComponent:HFAOutputFileName(@"Diagnostics.log")],
              [plain dataUsingEncoding:NSUTF8StringEncoding]);
    pthread_mutex_unlock(&gHFADiagnosticsLock);
}

void HFADiagnosticsFinishSession(NSString *status, NSDictionary *details) {
    HFADiagnosticsLog(@"session", status ?: @"complete", details);
}

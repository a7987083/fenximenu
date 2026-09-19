#import "HFAMapDiagnostics.h"
#import "ZPAppIdentity.h"
#import <UIKit/UIKit.h>
#include <pthread.h>

static pthread_mutex_t gHFADiagnosticsLock = PTHREAD_MUTEX_INITIALIZER;
static NSString *gHFASessionID;
static NSTimeInterval gHFAStartedAt;
static NSString *HFADocumentsPath(void){return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES) firstObject];}
static NSString *HFAJSONString(id value){if(!value||![NSJSONSerialization isValidJSONObject:value])return @"{}";NSData*d=[NSJSONSerialization dataWithJSONObject:value options:0 error:nil];return d?[[NSString alloc]initWithData:d encoding:NSUTF8StringEncoding]:@"{}";}
static void HFAAppend(NSString *path,NSData *data){if(!path.length||!data.length)return;NSFileManager*m=NSFileManager.defaultManager;if(![m fileExistsAtPath:path])[m createFileAtPath:path contents:nil attributes:nil];NSFileHandle*h=[NSFileHandle fileHandleForWritingAtPath:path];if(!h)return;@try{[h seekToEndOfFile];[h writeData:data];[h closeFile];}@catch(__unused id e){}}
NSString *HFADiagnosticsBeginSession(void){pthread_mutex_lock(&gHFADiagnosticsLock);gHFASessionID=[NSUUID.UUID.UUIDString copy];gHFAStartedAt=NSDate.date.timeIntervalSince1970;NSString*s=gHFASessionID;pthread_mutex_unlock(&gHFADiagnosticsLock);HFADiagnosticsLog(@"session",@"start",@{ @"version":@"zpatchig-0.2.0",@"process":NSProcessInfo.processInfo.processName?:@"?",@"os":UIDevice.currentDevice.systemVersion?:@"?",@"appIdentity":ZPAppIdentity() });return s;}
NSString *HFADiagnosticsSessionID(void){pthread_mutex_lock(&gHFADiagnosticsLock);NSString*s=gHFASessionID?:@"no-session";pthread_mutex_unlock(&gHFADiagnosticsLock);return s;}
void HFADiagnosticsLog(NSString *stage,NSString *status,NSDictionary *details){pthread_mutex_lock(&gHFADiagnosticsLock);NSString*session=gHFASessionID?:@"no-session";NSTimeInterval now=NSDate.date.timeIntervalSince1970;NSTimeInterval elapsed=gHFAStartedAt>0?(now-gHFAStartedAt)*1000.0:0;NSMutableDictionary*r=[@{ @"schema":@"com.hfa.diagnostic-event/v1",@"session":session,@"time":@(now),@"elapsedMs":@(elapsed),@"stage":stage?:@"?",@"status":status?:@"?",@"thread":NSThread.isMainThread?@"main":@"worker",@"appIdentity":ZPAppIdentity() } mutableCopy];if(details)[r addEntriesFromDictionary:details];NSString*json=[HFAJSONString(r) stringByAppendingString:@"\n"];NSString*plain=[NSString stringWithFormat:@"[%@] [+%.1fms] [%@/%@] %@\n",session,elapsed,stage?:@"?",status?:@"?",HFAJSONString(details?:@{})];NSString*docs=HFADocumentsPath();HFAAppend([docs stringByAppendingPathComponent:ZPLogFilename(@"Diagnostics.jsonl")],[json dataUsingEncoding:NSUTF8StringEncoding]);HFAAppend([docs stringByAppendingPathComponent:ZPLogFilename(@"Diagnostics.log")],[plain dataUsingEncoding:NSUTF8StringEncoding]);pthread_mutex_unlock(&gHFADiagnosticsLock);}
void HFADiagnosticsFinishSession(NSString *status,NSDictionary *details){HFADiagnosticsLog(@"session",status?:@"complete",details);}

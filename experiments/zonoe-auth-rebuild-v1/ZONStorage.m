#import "ZONStorage.h"
static NSString * const kUDID=@"zonoe.v2.udid";
static NSString * const kCard=@"zonoe.v2.card";
static NSString * const kVerify=@"zonoe.v2.lastVerify";
@implementation ZONStorage
+ (NSUserDefaults *)d { return NSUserDefaults.standardUserDefaults; }
+ (NSString *)udid { return [[self d] stringForKey:kUDID]; }
+ (void)setUDID:(NSString *)v { if(v.length)[[self d] setObject:v forKey:kUDID]; else [[self d] removeObjectForKey:kUDID]; }
+ (NSString *)card { return [[self d] stringForKey:kCard]; }
+ (void)setCard:(NSString *)v { if(v.length)[[self d] setObject:v forKey:kCard]; else [[self d] removeObjectForKey:kCard]; }
+ (NSDictionary *)lastVerify { id x=[[self d] objectForKey:kVerify]; return [x isKindOfClass:NSDictionary.class]?x:nil; }
+ (void)setLastVerify:(NSDictionary *)r { if(r)[[self d] setObject:r forKey:kVerify]; else [[self d] removeObjectForKey:kVerify]; }
+ (void)clearCardState { [[self d] removeObjectForKey:kCard]; [[self d] removeObjectForKey:kVerify]; }
+ (void)clearUDIDState { [[self d] removeObjectForKey:kUDID]; [[self d] removeObjectForKey:kCard]; [[self d] removeObjectForKey:kVerify]; }
@end

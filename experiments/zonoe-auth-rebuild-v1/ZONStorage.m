#import "ZONStorage.h"
static NSString * const kUDID=@"zonoe.v2.udid";
static NSString * const kLegacyUDID=@"zonoe.auth.udid";
static NSString * const kCard=@"zonoe.v2.card";
static NSString * const kVerify=@"zonoe.v2.lastVerify";
static NSString * const kActivation=@"zonoe.v2.lastActivation";
static NSString * const kJustActivated=@"zonoe.v2.justActivated";
@implementation ZONStorage
+ (NSUserDefaults *)d { return NSUserDefaults.standardUserDefaults; }
+ (NSString *)udid { NSString *v=[[self d] stringForKey:kUDID]; return v.length?v:[[self d] stringForKey:kLegacyUDID]; }
+ (void)setUDID:(NSString *)v { if(v.length){[[self d] setObject:v forKey:kUDID];[[self d] setObject:v forKey:kLegacyUDID];} else {[[self d] removeObjectForKey:kUDID];[[self d] removeObjectForKey:kLegacyUDID];} }
+ (NSString *)card { return [[self d] stringForKey:kCard]; }
+ (void)setCard:(NSString *)v { if(v.length)[[self d] setObject:v forKey:kCard]; else [[self d] removeObjectForKey:kCard]; }
+ (NSDictionary *)lastVerify { id x=[[self d] objectForKey:kVerify]; return [x isKindOfClass:NSDictionary.class]?x:nil; }
+ (void)setLastVerify:(NSDictionary *)r { if(r)[[self d] setObject:r forKey:kVerify]; else [[self d] removeObjectForKey:kVerify]; }
+ (id)lastActivationObject { return [[self d] objectForKey:kActivation]; }
+ (void)setLastActivationObject:(id)obj { if(obj && [NSPropertyListSerialization propertyList:obj isValidForFormat:NSPropertyListBinaryFormat_v1_0]) [[self d] setObject:obj forKey:kActivation]; else if(obj) [[self d] setObject:[obj description] forKey:kActivation]; else [[self d] removeObjectForKey:kActivation]; }
+ (BOOL)justActivated { return [[self d] boolForKey:kJustActivated]; }
+ (void)setJustActivated:(BOOL)v { [[self d] setBool:v forKey:kJustActivated]; }
+ (void)clearCardState { [[self d] removeObjectForKey:kCard]; [[self d] removeObjectForKey:kVerify]; [[self d] removeObjectForKey:kActivation]; [[self d] removeObjectForKey:kJustActivated]; }
+ (void)clearUDIDState { [self clearCardState]; [[self d] removeObjectForKey:kUDID]; [[self d] removeObjectForKey:kLegacyUDID]; }
@end

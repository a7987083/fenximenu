#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONStorage : NSObject
+ (NSString * _Nullable)udid;
+ (void)setUDID:(NSString * _Nullable)udid;
+ (NSString * _Nullable)card;
+ (void)setCard:(NSString * _Nullable)card;
+ (NSDictionary * _Nullable)lastVerify;
+ (void)setLastVerify:(NSDictionary * _Nullable)result;
+ (id _Nullable)lastActivationObject;
+ (void)setLastActivationObject:(id _Nullable)obj;
+ (BOOL)justActivated;
+ (void)setJustActivated:(BOOL)value;
+ (void)clearCardState;
+ (void)clearUDIDState;
@end
NS_ASSUME_NONNULL_END

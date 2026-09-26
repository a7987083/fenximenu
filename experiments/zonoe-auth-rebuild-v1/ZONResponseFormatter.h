#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface ZONResponseFormatter : NSObject
+ (NSString *)displayTextForObject:(id _Nullable)obj;
+ (NSString *)displayTextForDictionary:(NSDictionary * _Nullable)dictionary;
+ (NSString *)titleForNotice:(id _Nullable)notice fallback:(NSString *)fallback;
@end
NS_ASSUME_NONNULL_END

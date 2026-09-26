#import "ZONAPIEndpoints.h"
@implementation ZONAPIEndpoints
+ (NSString *)base { return @"https://app3.zonoeios.xyz"; }
+ (NSURL *)authorizationURL { return [NSURL URLWithString:[[self base] stringByAppendingString:@"/authorization"]]; }
+ (NSURL *)activationURLForUDID:(NSString *)udid card:(NSString *)card {
    NSURLComponents *c=[NSURLComponents componentsWithString:[[self base] stringByAppendingString:@"/appstore"]];
    NSMutableArray *items=[NSMutableArray arrayWithObject:[NSURLQueryItem queryItemWithName:@"udid" value:udid?:@""]];
    if(card.length) [items addObject:[NSURLQueryItem queryItemWithName:@"code" value:card]];
    c.queryItems=items;
    return c.URL;
}
+ (NSURL *)apiFaceURLForUDID:(NSString *)udid { NSURLComponents *c=[NSURLComponents componentsWithString:[[self base] stringByAppendingString:@"/index/index/apiface"]]; c.queryItems=@[[NSURLQueryItem queryItemWithName:@"udid" value:udid?:@""]]; return c.URL; }
+ (NSURL *)legacyDylibConfigURLForUDID:(NSString *)udid { NSURLComponents *c=[NSURLComponents componentsWithString:[[self base] stringByAppendingString:@"/index/index/dylib"]]; c.queryItems=@[[NSURLQueryItem queryItemWithName:@"udid" value:udid?:@""]]; return c.URL; }
+ (NSURL *)unbindQueryURLForUDID:(NSString *)udid { NSURLComponents *c=[NSURLComponents componentsWithString:[[self base] stringByAppendingString:@"/unbind/query"]]; c.queryItems=@[[NSURLQueryItem queryItemWithName:@"udid" value:udid?:@""]]; return c.URL; }
+ (NSURL *)unbindURL { return [NSURL URLWithString:[[self base] stringByAppendingString:@"/unbind"]]; }
+ (NSURL *)runtimeConfigURLForDylibKey:(NSString *)dylibKey { NSURLComponents *c=[NSURLComponents componentsWithString:[[self base] stringByAppendingString:@"/index/dylib_verify/config"]]; c.queryItems=@[[NSURLQueryItem queryItemWithName:@"dylib_key" value:dylibKey?:@""]]; return c.URL; }
+ (NSURL *)verifyURL { return [NSURL URLWithString:[[self base] stringByAppendingString:@"/index/dylib_verify/verify"]]; }
@end

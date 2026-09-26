#import "ZONAPIEndpoints.h"
@implementation ZONAPIEndpoints
+ (NSString *)base { return @"https://app3.zonoeios.xyz"; }
+ (NSURL *)authorizationURL { return [NSURL URLWithString:[[self base] stringByAppendingString:@"/authorization"]]; }
+ (NSURL *)activationURLForUDID:(NSString *)udid card:(NSString *)card {
    NSURLComponents *c=[NSURLComponents componentsWithString:[[self base] stringByAppendingString:@"/appstore"]];
    c.queryItems=@[[NSURLQueryItem queryItemWithName:@"udid" value:udid?:@""],[NSURLQueryItem queryItemWithName:@"code" value:card?:@""]];
    return c.URL;
}
+ (NSURL *)apiFaceURLForUDID:(NSString *)udid {
    NSURLComponents *c=[NSURLComponents componentsWithString:[[self base] stringByAppendingString:@"/index/index/apiface"]];
    c.queryItems=@[[NSURLQueryItem queryItemWithName:@"udid" value:udid?:@""]];
    return c.URL;
}
@end

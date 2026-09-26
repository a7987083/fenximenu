#import "ZONAuthorization.h"
#import "ZONAPIEndpoints.h"
#import "ZONNetwork.h"

@implementation ZONAuthorization

+ (NSString *)decodeHTMLEntities:(NSString *)text {
    if (!text.length) return @"";
    NSString *s = text;
    NSDictionary<NSString *, NSString *> *entities = @{
        @"&nbsp;": @" ", @"&amp;": @"&", @"&lt;": @"<", @"&gt;": @">",
        @"&quot;": @"\"", @"&#39;": @"'"
    };
    for (NSString *key in entities) {
        s = [s stringByReplacingOccurrencesOfString:key withString:entities[key]];
    }
    return s;
}

+ (NSString *)plainTextFromHTMLFragment:(NSString *)html {
    if (!html.length) return @"";
    NSRegularExpression *tags = [NSRegularExpression regularExpressionWithPattern:@"<[^>]+>" options:NSRegularExpressionCaseInsensitive error:nil];
    NSString *plain = [tags stringByReplacingMatchesInString:html options:0 range:NSMakeRange(0, html.length) withTemplate:@""];
    plain = [self decodeHTMLEntities:plain];
    return [plain stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
}

+ (NSString *)messageFromHTML:(NSString *)html {
    if (!html.length) return @"";

    // Preferred server UI contract: <div class="msg err">...</div> / <div class="msg ok">...</div>
    NSString *pattern = @"<div[^>]*class\\s*=\\s*['\"][^'\"]*\\bmsg\\b[^'\"]*['\"][^>]*>(.*?)</div>";
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern options:(NSRegularExpressionCaseInsensitive | NSRegularExpressionDotMatchesLineSeparators) error:nil];
    NSTextCheckingResult *m = [re firstMatchInString:html options:0 range:NSMakeRange(0, html.length)];
    if (m.numberOfRanges > 1) {
        NSString *fragment = [html substringWithRange:[m rangeAtIndex:1]];
        NSString *message = [self plainTextFromHTMLFragment:fragment];
        if (message.length) return message;
    }

    // Fallback to <title> only; never expose the whole HTML document to UI.
    NSRegularExpression *titleRE = [NSRegularExpression regularExpressionWithPattern:@"<title[^>]*>(.*?)</title>" options:(NSRegularExpressionCaseInsensitive | NSRegularExpressionDotMatchesLineSeparators) error:nil];
    NSTextCheckingResult *titleMatch = [titleRE firstMatchInString:html options:0 range:NSMakeRange(0, html.length)];
    if (titleMatch.numberOfRanges > 1) {
        NSString *fragment = [html substringWithRange:[titleMatch rangeAtIndex:1]];
        NSString *title = [self plainTextFromHTMLFragment:fragment];
        if (title.length) return title;
    }

    return @"服务器返回了网页响应，但没有可识别的提示信息";
}

+ (void)queryCard:(NSString *)card udid:(NSString *)udid completion:(void (^)(NSDictionary *, NSError * _Nullable))completion {
    NSDictionary *body = @{@"code": card ?: @"", @"udid": udid ?: @""};
    [ZONNetwork POST:[ZONAPIEndpoints authorizationURL] formBody:body timeout:12 completion:^(NSDictionary *json, NSData *data, NSHTTPURLResponse *response, NSError *error) {
        NSDictionary *result = [json isKindOfClass:NSDictionary.class] ? json : @{};

        if (!result.count && data.length) {
            NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
            NSString *contentType = response.allHeaderFields[@"Content-Type"];
            BOOL looksHTML = [contentType.lowercaseString containsString:@"text/html"] ||
                             [text.lowercaseString containsString:@"<html"] ||
                             [text.lowercaseString containsString:@"<body"];
            NSString *message = looksHTML ? [self messageFromHTML:text] : [text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
            result = @{
                @"message": message.length ? message : @"服务器未返回可显示信息",
                @"response_format": looksHTML ? @"html" : @"text"
            };
        }

        if (completion) completion(result, error);
    }];
}

+ (BOOL)resultNeedsActivation:(NSDictionary *)result {
    id activated = result[@"activated"] ?: result[@"is_activated"] ?: result[@"bound"] ?: result[@"is_bound"];
    if ([activated respondsToSelector:@selector(boolValue)]) return ![activated boolValue];

    NSString *code = [result[@"code"] isKindOfClass:NSString.class] ? [result[@"code"] lowercaseString] : @"";
    if ([code containsString:@"not_activated"] || [code containsString:@"unbound"] || [code containsString:@"not_bound"] || [code containsString:@"need_activation"]) return YES;

    NSString *action = [result[@"action"] isKindOfClass:NSString.class] ? [result[@"action"] lowercaseString] : @"";
    if ([action containsString:@"activate"] || [action containsString:@"bind"]) return YES;

    return NO;
}

@end

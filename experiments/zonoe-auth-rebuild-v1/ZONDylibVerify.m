#import "ZONDylibVerify.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

static void ZONVerifyImageAnchor(void) {}

@implementation ZONDylibVerifyConfiguration
- (instancetype)init {
    self = [super init];
    if (self) {
        _bootstrapURLs = @[];
        _dylibBuild = @"";
        _requestTimeout = 10.0;
    }
    return self;
}
@end

@implementation ZONDylibVerifyResult
- (instancetype)init {
    self = [super init];
    if (self) {
        _code = @"unknown";
        _action = @"disable_feature";
        _message = @"";
        _token = @"";
        _accessLevel = @"block";
        _permissions = @{};
        _appIdentity = @{};
        _appUpdate = @{};
        _protocolVersion = 2;
    }
    return self;
}
@end

@interface ZONDylibVerify ()
@property(nonatomic,strong) ZONDylibVerifyConfiguration *configuration;
@end

@implementation ZONDylibVerify

- (instancetype)initWithConfiguration:(ZONDylibVerifyConfiguration *)configuration {
    self = [super init];
    if (self) _configuration = configuration;
    return self;
}

+ (NSString *)hexForBytes:(const unsigned char *)bytes length:(NSUInteger)length {
    NSMutableString *s = [NSMutableString stringWithCapacity:length * 2];
    for (NSUInteger i = 0; i < length; i++) [s appendFormat:@"%02x", bytes[i]];
    return s;
}

+ (NSString *)sha256ForFile:(NSString *)path {
    NSFileHandle *h = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!h) return @"";
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    while (YES) {
        @autoreleasepool {
            NSData *d = [h readDataOfLength:1024 * 1024];
            if (!d.length) break;
            CC_SHA256_Update(&ctx, d.bytes, (CC_LONG)d.length);
        }
    }
    [h closeFile];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &ctx);
    return [self hexForBytes:digest length:sizeof(digest)];
}

+ (NSString *)currentDylibSHA256 {
    Dl_info info;
    if (dladdr((const void *)&ZONVerifyImageAnchor, &info) == 0 || !info.dli_fname) return @"";
    return [self sha256ForFile:[NSString stringWithUTF8String:info.dli_fname]];
}

+ (NSString *)currentAppMachOUUID {
    const struct mach_header *header = _dyld_get_image_header(0);
    if (!header) return @"";
    BOOL is64 = header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64;
    uintptr_t cursor = (uintptr_t)header + (is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *cmd = (const struct load_command *)cursor;
        if (cmd->cmd == LC_UUID) {
            const struct uuid_command *u = (const struct uuid_command *)cmd;
            const unsigned char *b = u->uuid;
            return [NSString stringWithFormat:@"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]];
        }
        if (cmd->cmdsize == 0) break;
        cursor += cmd->cmdsize;
    }
    return @"";
}

- (NSString *)hmacSHA256Hex:(NSString *)message key:(NSString *)key {
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *msgData = [message dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keyData.bytes, keyData.length, msgData.bytes, msgData.length, digest);
    return [ZONDylibVerify hexForBytes:digest length:sizeof(digest)];
}

- (NSString *)nonce {
    return [[[NSUUID UUID].UUIDString lowercaseString] stringByReplacingOccurrencesOfString:@"-" withString:@""];
}

- (NSURL *)endpointFromBootstrapObject:(NSDictionary *)json {
    NSDictionary *config = [json[@"config"] isKindOfClass:NSDictionary.class] ? json[@"config"] : json;
    NSArray *api = [config[@"api_endpoints"] isKindOfClass:NSArray.class] ? config[@"api_endpoints"] : nil;
    NSString *path = [config[@"verify_path"] isKindOfClass:NSString.class] ? config[@"verify_path"] : @"/index/dylib_verify/verify";
    NSString *base = [api.firstObject isKindOfClass:NSString.class] ? api.firstObject : nil;
    if (!base.length) return nil;
    while ([base hasSuffix:@"/"]) base = [base substringToIndex:base.length - 1];
    if (![path hasPrefix:@"/"]) path = [@"/" stringByAppendingString:path];
    return [NSURL URLWithString:[base stringByAppendingString:path]];
}

- (void)resolveEndpoint:(void (^)(NSURL *endpoint))completion {
    NSURL *bootstrap = self.configuration.bootstrapURLs.firstObject;
    if (!bootstrap) { completion(self.configuration.endpointURL); return; }
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:bootstrap cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:self.configuration.requestTimeout];
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSURL *resolved = nil;
        if (data.length) {
            id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if ([obj isKindOfClass:NSDictionary.class]) resolved = [self endpointFromBootstrapObject:obj];
        }
        dispatch_async(dispatch_get_main_queue(), ^{ completion(resolved ?: self.configuration.endpointURL); });
    }] resume];
}

- (ZONDylibVerifyResult *)resultFromJSON:(NSDictionary *)json error:(NSError *)error status:(NSInteger)status {
    ZONDylibVerifyResult *r = [ZONDylibVerifyResult new];
    if (error || !json) {
        r.allowed = NO;
        r.code = error ? @"network_error" : @"invalid_response";
        r.message = error.localizedDescription ?: [NSString stringWithFormat:@"HTTP %ld", (long)status];
        return r;
    }
    id ok = json[@"ok"] ?: json[@"allowed"];
    r.allowed = [ok respondsToSelector:@selector(boolValue)] ? [ok boolValue] : NO;
    if ([json[@"code"] isKindOfClass:NSString.class]) r.code = json[@"code"];
    if ([json[@"action"] isKindOfClass:NSString.class]) r.action = json[@"action"];
    if ([json[@"message"] isKindOfClass:NSString.class]) r.message = json[@"message"];
    if ([json[@"token"] isKindOfClass:NSString.class]) r.token = json[@"token"];
    if ([json[@"access_level"] isKindOfClass:NSString.class]) r.accessLevel = json[@"access_level"];
    if ([json[@"permissions"] isKindOfClass:NSDictionary.class]) r.permissions = json[@"permissions"];
    if ([json[@"app_identity"] isKindOfClass:NSDictionary.class]) r.appIdentity = json[@"app_identity"];
    if ([json[@"app_update"] isKindOfClass:NSDictionary.class]) r.appUpdate = json[@"app_update"];
    if ([json[@"notice"] isKindOfClass:NSDictionary.class]) r.notice = json[@"notice"];
    if ([json[@"protocol_version"] respondsToSelector:@selector(integerValue)]) r.protocolVersion = [json[@"protocol_version"] integerValue];
    id grace = json[@"offline_grace_seconds"] ?: json[@"offline_grace"];
    if ([grace respondsToSelector:@selector(doubleValue)]) r.offlineGraceSeconds = [grace doubleValue];
    id server = json[@"server_time"] ?: json[@"time"];
    if ([server respondsToSelector:@selector(doubleValue)]) r.serverTime = [server doubleValue];
    r.offlineCache = [json[@"offline_cache"] respondsToSelector:@selector(boolValue)] ? [json[@"offline_cache"] boolValue] : NO;
    return r;
}

- (void)verifyWithCompletion:(void (^)(ZONDylibVerifyResult *result))completion {
    NSString *udid = self.configuration.udidProvider ? self.configuration.udidProvider() : nil;
    if (!udid.length) {
        ZONDylibVerifyResult *r = [ZONDylibVerifyResult new];
        r.code = @"udid_missing";
        r.message = @"UDID missing";
        completion(r);
        return;
    }

    NSBundle *b = NSBundle.mainBundle;
    NSString *bundleID = b.bundleIdentifier ?: @"";
    NSString *executable = [b objectForInfoDictionaryKey:@"CFBundleExecutable"] ?: @"";
    NSString *appVersion = [b objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSString *appBuild = [b objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";
    NSString *sha = [ZONDylibVerify currentDylibSHA256] ?: @"";
    NSString *uuid = [ZONDylibVerify currentAppMachOUUID] ?: @"";
    NSString *nonce = [self nonce];
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", NSDate.date.timeIntervalSince1970];
    NSString *protocol = @"2";

    NSArray *parts = @[udid, bundleID, self.configuration.dylibKey ?: @"", self.configuration.dylibVersion ?: @"", self.configuration.dylibBuild ?: @"", sha.lowercaseString, timestamp, nonce, protocol, executable, uuid, appVersion, appBuild];
    NSString *canonical = [parts componentsJoinedByString:@"\n"];
    NSString *signature = [self hmacSHA256Hex:canonical key:self.configuration.verifySecret ?: @""];

    NSDictionary *payload = @{
        @"udid":udid,
        @"bundle_id":bundleID,
        @"dylib_key":self.configuration.dylibKey ?: @"",
        @"dylib_version":self.configuration.dylibVersion ?: @"",
        @"dylib_build":self.configuration.dylibBuild ?: @"",
        @"dylib_sha256":sha.lowercaseString,
        @"timestamp":timestamp,
        @"nonce":nonce,
        @"protocol_version":@2,
        @"app_executable":executable,
        @"app_macho_uuid":uuid,
        @"app_version":appVersion,
        @"app_build":appBuild,
        @"signature":signature
    };

    [self resolveEndpoint:^(NSURL *endpoint) {
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:endpoint cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:self.configuration.requestTimeout];
        req.HTTPMethod = @"POST";
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            NSDictionary *json = nil;
            if (data.length) {
                id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                if ([obj isKindOfClass:NSDictionary.class]) json = obj;
            }
            NSInteger status = [(NSHTTPURLResponse *)response statusCode];
            ZONDylibVerifyResult *r = [self resultFromJSON:json error:error status:status];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(r); });
        }] resume];
    }];
}

@end

#import "ZONDylibVerify.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

static void ZONVerifyImageAnchor(void) {}

@implementation ZONDylibVerifyConfiguration
- (instancetype)init { if ((self=[super init])) { _dylibBuild=@""; _bootstrapURLs=@[]; _requestTimeout=10.0; } return self; }
@end

@implementation ZONDylibVerifyResult
- (instancetype)init { if ((self=[super init])) { _code=@"unknown"; _action=@"disable_feature"; _message=@""; _token=@""; _accessLevel=@"block"; _permissions=@{}; _appIdentity=@{}; _appUpdate=@{@"available":@NO}; _protocolVersion=1; } return self; }
@end

@interface ZONDylibVerify ()
@property(nonatomic,strong) ZONDylibVerifyConfiguration *configuration;
@property(nonatomic,strong) NSURLSession *session;
@end

@implementation ZONDylibVerify

- (instancetype)initWithConfiguration:(ZONDylibVerifyConfiguration *)configuration {
    NSParameterAssert(configuration);
    if ((self=[super init])) {
        _configuration=configuration;
        NSURLSessionConfiguration *c=[NSURLSessionConfiguration ephemeralSessionConfiguration];
        c.timeoutIntervalForRequest=MAX(3.0,configuration.requestTimeout);
        c.timeoutIntervalForResource=MAX(5.0,configuration.requestTimeout+5.0);
        _session=[NSURLSession sessionWithConfiguration:c];
    }
    return self;
}

- (NSString *)hmac:(NSString *)message key:(NSString *)key {
    NSData *kd=[key dataUsingEncoding:NSUTF8StringEncoding], *md=[message dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char dig[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,kd.bytes,kd.length,md.bytes,md.length,dig);
    NSMutableString *hex=[NSMutableString stringWithCapacity:64];
    for(NSUInteger i=0;i<CC_SHA256_DIGEST_LENGTH;i++) [hex appendFormat:@"%02x",dig[i]];
    return hex;
}

- (NSString *)nonce {
    NSMutableData *d=[NSMutableData dataWithLength:24];
    if(SecRandomCopyBytes(kSecRandomDefault,24,d.mutableBytes)!=errSecSuccess) return NSUUID.UUID.UUIDString.lowercaseString;
    const uint8_t *b=d.bytes; NSMutableString *s=[NSMutableString stringWithCapacity:48];
    for(NSUInteger i=0;i<24;i++) [s appendFormat:@"%02x",b[i]]; return s;
}

- (ZONDylibVerifyResult *)resultAllowed:(BOOL)allowed code:(NSString *)code action:(NSString *)action message:(NSString *)message {
    ZONDylibVerifyResult *r=[ZONDylibVerifyResult new]; r.allowed=allowed; r.code=code?:@"unknown"; r.action=action?:@"disable_feature"; r.message=message?:@""; return r;
}

- (ZONDylibVerifyResult *)resultFromJSON:(NSDictionary *)json {
    ZONDylibVerifyResult *r=[ZONDylibVerifyResult new];
    r.allowed=[json[@"ok"] boolValue];
    r.code=[json[@"code"] isKindOfClass:NSString.class]?json[@"code"]:@"unknown";
    r.action=[json[@"action"] isKindOfClass:NSString.class]?json[@"action"]:@"disable_feature";
    r.message=[json[@"message"] isKindOfClass:NSString.class]?json[@"message"]:@"";
    r.token=[json[@"token"] isKindOfClass:NSString.class]?json[@"token"]:@"";
    r.accessLevel=[json[@"access_level"] isKindOfClass:NSString.class]?json[@"access_level"]:(r.allowed?@"basic":@"block");
    r.permissions=[json[@"permissions"] isKindOfClass:NSDictionary.class]?json[@"permissions"]:@{};
    r.appIdentity=[json[@"app_identity"] isKindOfClass:NSDictionary.class]?json[@"app_identity"]:@{};
    r.appUpdate=[json[@"app_update"] isKindOfClass:NSDictionary.class]?json[@"app_update"]:@{@"available":@NO};
    r.notice=[json[@"notice"] isKindOfClass:NSDictionary.class]?json[@"notice"]:nil;
    r.protocolVersion=MAX(1,[json[@"protocol_version"] integerValue]);
    r.offlineGraceSeconds=[json[@"offline_grace_seconds"] doubleValue];
    r.serverTime=[json[@"server_time"] doubleValue];
    return r;
}

- (BOOL)constantTime:(NSString *)a equals:(NSString *)b {
    NSData *x=[a.lowercaseString dataUsingEncoding:NSUTF8StringEncoding], *y=[b.lowercaseString dataUsingEncoding:NSUTF8StringEncoding];
    if(!x.length||x.length!=y.length) return NO; const uint8_t *xb=x.bytes,*yb=y.bytes; uint8_t diff=0; for(NSUInteger i=0;i<x.length;i++) diff|=xb[i]^yb[i]; return diff==0;
}

- (BOOL)validateBootstrap:(NSDictionary *)j {
    if(![j isKindOfClass:NSDictionary.class]||![j[@"ok"] boolValue]) return NO;
    NSArray *apis=[j[@"api_endpoints"] isKindOfClass:NSArray.class]?j[@"api_endpoints"]:nil;
    NSArray *boots=[j[@"bootstrap_urls"] isKindOfClass:NSArray.class]?j[@"bootstrap_urls"]:nil;
    NSString *path=[j[@"verify_path"] isKindOfClass:NSString.class]?j[@"verify_path"]:nil;
    NSString *sig=[j[@"signature"] isKindOfClass:NSString.class]?j[@"signature"]:nil;
    NSInteger v=[j[@"config_version"] integerValue], exp=[j[@"expires_at"] integerValue];
    if(!apis||!boots||!path.length||sig.length!=64||v<1||exp<=0||exp<(NSInteger)NSDate.date.timeIntervalSince1970) return NO;
    NSString *canon=[@[ [NSString stringWithFormat:@"%ld",(long)v], [apis componentsJoinedByString:@","], [boots componentsJoinedByString:@","], path, [NSString stringWithFormat:@"%ld",(long)exp] ] componentsJoinedByString:@"\n"];
    return [self constantTime:[self hmac:canon key:self.configuration.verifySecret] equals:sig];
}

- (NSArray<NSURL *> *)endpointsFromBootstrap:(NSDictionary *)j {
    NSMutableArray *r=[NSMutableArray array];
    if([self validateBootstrap:j]) {
        NSString *path=[j[@"verify_path"] hasPrefix:@"/"]?j[@"verify_path"]:[@"/" stringByAppendingString:j[@"verify_path"]];
        for(id value in j[@"api_endpoints"]) if([value isKindOfClass:NSString.class]) {
            NSString *base=[value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]; while([base hasSuffix:@"/"]) base=[base substringToIndex:base.length-1];
            NSURL *u=[NSURL URLWithString:[base stringByAppendingString:path]]; if(u) [r addObject:u];
        }
    }
    if(self.configuration.endpointURL && ![r containsObject:self.configuration.endpointURL]) [r addObject:self.configuration.endpointURL];
    return r;
}

- (void)resolveEndpoints:(void(^)(NSArray<NSURL *> *))completion {
    NSURL *bootstrap=self.configuration.bootstrapURLs.firstObject;
    if(!bootstrap) { completion(self.configuration.endpointURL?@[self.configuration.endpointURL]:@[]); return; }
    NSMutableURLRequest *q=[NSMutableURLRequest requestWithURL:bootstrap]; q.cachePolicy=NSURLRequestReloadIgnoringLocalCacheData; [q setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    __weak typeof(self) w=self;
    [[self.session dataTaskWithRequest:q completionHandler:^(NSData *data,NSURLResponse *resp,NSError *err){
        __strong typeof(w) self=w; if(!self) return; NSDictionary *j=(!err&&data.length)?[NSJSONSerialization JSONObjectWithData:data options:0 error:nil]:nil; NSArray *e=[self endpointsFromBootstrap:j]; completion(e.count?e:(self.configuration.endpointURL?@[self.configuration.endpointURL]:@[]));
    }] resume];
}

- (void)sendBody:(NSData *)body endpoints:(NSArray<NSURL *> *)endpoints index:(NSUInteger)i completion:(void(^)(ZONDylibVerifyResult *))completion {
    if(i>=endpoints.count){ completion([self resultAllowed:NO code:@"network_unavailable" action:@"disable_feature" message:@"Verification service unavailable"]); return; }
    NSMutableURLRequest *q=[NSMutableURLRequest requestWithURL:endpoints[i]]; q.HTTPMethod=@"POST"; q.HTTPBody=body; [q setValue:@"application/json" forHTTPHeaderField:@"Content-Type"]; [q setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    __weak typeof(self) w=self;
    [[self.session dataTaskWithRequest:q completionHandler:^(NSData *data,NSURLResponse *resp,NSError *err){
        __strong typeof(w) self=w; if(!self) return; NSHTTPURLResponse *h=[resp isKindOfClass:NSHTTPURLResponse.class]?(id)resp:nil;
        if(err||h.statusCode>=500||!data.length){ [self sendBody:body endpoints:endpoints index:i+1 completion:completion]; return; }
        NSDictionary *j=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil]; if(![j isKindOfClass:NSDictionary.class]){ completion([self resultAllowed:NO code:@"response_invalid" action:@"disable_feature" message:@"Invalid verification response"]); return; }
        completion([self resultFromJSON:j]);
    }] resume];
}

- (void)verifyWithCompletion:(void (^)(ZONDylibVerifyResult *result))completion {
    if(!completion) return;
    NSString *udid=self.configuration.udidProvider?self.configuration.udidProvider():@"";
    NSString *bid=NSBundle.mainBundle.bundleIdentifier?:@"";
    NSString *exe=[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleExecutable"]?:@"";
    NSString *appVersion=[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"]?:@"";
    NSString *appBuild=[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"]?:@"";
    NSString *uuid=ZONDylibVerify.currentAppMachOUUID?:@"";
    if(!udid.length){ completion([self resultAllowed:NO code:@"udid_missing" action:@"block" message:@"UDID unavailable"]); return; }
    if(!bid.length||!exe.length||!uuid.length||self.configuration.verifySecret.length<32){ completion([self resultAllowed:NO code:@"client_config_invalid" action:@"block" message:@"Verification client configuration is incomplete"]); return; }
    NSString *sha=ZONDylibVerify.currentDylibSHA256?:@""; NSInteger ts=(NSInteger)floor(NSDate.date.timeIntervalSince1970); NSString *nonce=self.nonce; NSInteger pv=2;
    NSArray *parts=@[udid,bid,self.configuration.dylibKey?:@"",self.configuration.dylibVersion?:@"",self.configuration.dylibBuild?:@"",sha.lowercaseString?:@"",[NSString stringWithFormat:@"%ld",(long)ts],nonce,[NSString stringWithFormat:@"%ld",(long)pv],exe,uuid.uppercaseString,appVersion,appBuild];
    NSString *sig=[self hmac:[parts componentsJoinedByString:@"\n"] key:self.configuration.verifySecret];
    NSDictionary *payload=@{@"protocol_version":@(pv),@"udid":udid,@"bundle_id":bid,@"dylib_key":self.configuration.dylibKey?:@"",@"dylib_version":self.configuration.dylibVersion?:@"",@"dylib_build":self.configuration.dylibBuild?:@"",@"dylib_sha256":sha,@"app_executable":exe,@"app_macho_uuid":uuid,@"app_version":appVersion,@"app_build":appBuild,@"timestamp":@(ts),@"nonce":nonce,@"signature":sig};
    NSData *body=[NSJSONSerialization dataWithJSONObject:payload options:0 error:nil]; if(!body){ completion([self resultAllowed:NO code:@"json_error" action:@"disable_feature" message:@"Unable to encode request"]); return; }
    __weak typeof(self) w=self; [self resolveEndpoints:^(NSArray<NSURL *> *e){ __strong typeof(w) self=w; if(self) [self sendBody:body endpoints:e index:0 completion:completion]; }];
}

+ (NSString *)currentAppMachOUUID {
    const struct mach_header *h=_dyld_get_image_header(0); if(!h) return @""; BOOL is64=(h->magic==MH_MAGIC_64||h->magic==MH_CIGAM_64); uintptr_t p=(uintptr_t)h+(is64?sizeof(struct mach_header_64):sizeof(struct mach_header));
    for(uint32_t i=0;i<h->ncmds;i++){ const struct load_command *c=(const void *)p; if(!c||c->cmdsize<sizeof(*c)) break; if((c->cmd&0x7fffffff)==LC_UUID&&c->cmdsize>=sizeof(struct uuid_command)){ const uint8_t *u=((const struct uuid_command *)c)->uuid; return [NSString stringWithFormat:@"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]];} p+=c->cmdsize; }
    return @"";
}

+ (NSString *)currentDylibSHA256 {
    Dl_info info; if(dladdr((const void *)&ZONVerifyImageAnchor,&info)==0||!info.dli_fname) return @""; NSInputStream *s=[NSInputStream inputStreamWithFileAtPath:[NSString stringWithUTF8String:info.dli_fname]]; [s open]; CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx); uint8_t buf[65536]; NSInteger n=0; while((n=[s read:buf maxLength:sizeof(buf)])>0) CC_SHA256_Update(&ctx,buf,(CC_LONG)n); [s close]; if(n<0) return @""; unsigned char d[CC_SHA256_DIGEST_LENGTH]; CC_SHA256_Final(d,&ctx); NSMutableString *hex=[NSMutableString stringWithCapacity:64]; for(NSUInteger i=0;i<CC_SHA256_DIGEST_LENGTH;i++) [hex appendFormat:@"%02x",d[i]]; return hex;
}
@end

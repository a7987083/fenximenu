#import "ZONLicenseStatus.h"
#import "ZONAPIEndpoints.h"
#import "ZONNetwork.h"
#import "ZONDylibConfig.h"
#import <CommonCrypto/CommonHMAC.h>

@implementation ZONLicenseStatus
+ (NSString *)hmacHex:(NSString *)text key:(NSString *)key {
    const char *keyBytes=key.UTF8String?:"";
    const char *dataBytes=text.UTF8String?:"";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH]={0};
    CCHmac(kCCHmacAlgSHA256,keyBytes,strlen(keyBytes),dataBytes,strlen(dataBytes),digest);
    NSMutableString *out=[NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    for(int i=0;i<CC_SHA256_DIGEST_LENGTH;i++) [out appendFormat:@"%02x",digest[i]];
    return out;
}
+ (BOOL)constantEquals:(NSString *)a b:(NSString *)b {
    if(a.length!=b.length || a.length==0) return NO;
    const char *aa=a.UTF8String,*bb=b.UTF8String; unsigned char diff=0;
    for(NSUInteger i=0;i<a.length;i++) diff|=(unsigned char)(aa[i]^bb[i]);
    return diff==0;
}
+ (BOOL)verifySignature:(NSDictionary *)d {
    NSString *udid=[d[@"udid"] description]?:@"";
    NSString *expire=[d[@"expire"] description]?:@"";
    NSString *ts=[d[@"ts"] description]?:@"";
    NSString *nonce=[d[@"nonce"] description]?:@"";
    NSString *serverSig=[d[@"signature"] isKindOfClass:NSString.class]?d[@"signature"]:([d[@"sign"] isKindOfClass:NSString.class]?d[@"sign"]:@"");
    if(!serverSig.length || !udid.length || !expire.length || !ts.length || !nonce.length) return NO;
    NSString *canonical=[NSString stringWithFormat:@"%@|%@|%@|%@",udid,expire,ts,nonce];
    NSString *expected=[self hmacHex:canonical key:[ZONDylibConfig verifySecret]];
    return [self constantEquals:expected.lowercaseString b:serverSig.lowercaseString];
}
+ (void)fetchForUDID:(NSString *)udid completion:(void (^)(NSDictionary *, BOOL, NSError * _Nullable))completion {
    [ZONNetwork GET:[ZONAPIEndpoints apiFaceURLForUDID:udid] timeout:12 completion:^(NSDictionary *json, NSData *data, NSHTTPURLResponse *response, NSError *error) {
        NSDictionary *result=[json isKindOfClass:NSDictionary.class]?json:@{};
        if(!result.count && data.length){
            NSString *text=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]?:@"";
            result=@{@"message":text};
        }
        BOOL sig=[self verifySignature:result];
        NSMutableDictionary *m=[result mutableCopy]?:[NSMutableDictionary dictionary];
        m[@"signature_valid"]=@(sig);
        if(completion) completion(m.copy,sig,error);
    }];
}
@end

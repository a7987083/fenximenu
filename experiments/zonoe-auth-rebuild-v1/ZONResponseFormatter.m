#import "ZONResponseFormatter.h"

@implementation ZONResponseFormatter
+ (NSDictionary<NSString *, NSString *> *)labels {
    static NSDictionary *m; static dispatch_once_t once;
    dispatch_once(&once, ^{ m=@{@"ok":@"验证结果",@"allowed":@"允许使用",@"code":@"状态码",@"action":@"服务端动作",@"message":@"服务器消息",@"msg":@"服务器消息",@"token":@"授权令牌",@"token_present":@"授权令牌",@"access_level":@"当前等级",@"level":@"当前等级",@"vip_level":@"当前等级",@"expire":@"到期时间",@"expires_at":@"到期时间",@"expire_time":@"到期时间",@"remaining":@"剩余时间",@"remaining_time":@"剩余时间",@"remaining_seconds":@"剩余秒数",@"permissions":@"权限",@"app_identity":@"应用身份",@"app_update":@"应用更新",@"notice":@"公告",@"protocol_version":@"协议版本",@"offline_grace_seconds":@"离线宽限时间",@"offline_cache":@"离线缓存",@"server_time":@"服务器时间",@"udid":@"设备 UDID",@"bundle_id":@"Bundle ID",@"app_version":@"应用版本",@"app_build":@"应用 Build",@"app_executable":@"主程序",@"app_macho_uuid":@"Mach-O UUID",@"device_count":@"设备数量",@"device_limit":@"设备上限",@"status":@"状态",@"title":@"标题",@"content":@"内容",@"text":@"内容",@"version":@"版本",@"url":@"地址",@"force":@"强制更新"}; });
    return m;
}
+ (NSString *)labelForKey:(NSString *)key { return [self labels][key.lowercaseString] ?: key; }
+ (NSString *)scalarText:(id)value key:(NSString *)key {
    if(!value||value==NSNull.null)return @"无";
    if([value isKindOfClass:NSNumber.class]){
        const char *t=[(NSNumber *)value objCType];
        if(strcmp(t,@encode(BOOL))==0||strcmp(t,"c")==0)return [(NSNumber *)value boolValue]?@"是":@"否";
        if([key.lowercaseString containsString:@"server_time"]||[key.lowercaseString hasSuffix:@"_time"]||[key.lowercaseString containsString:@"timestamp"]){ NSTimeInterval ts=[(NSNumber *)value doubleValue]; if(ts>1000000000&&ts<5000000000){ NSDateFormatter *f=[NSDateFormatter new]; f.locale=[NSLocale localeWithLocaleIdentifier:@"zh_CN"]; f.dateFormat=@"yyyy-MM-dd HH:mm:ss"; return [NSString stringWithFormat:@"%@ (%@)",[f stringFromDate:[NSDate dateWithTimeIntervalSince1970:ts]],value]; }}
        if([key.lowercaseString containsString:@"seconds"]){ NSInteger s=[(NSNumber *)value integerValue],d=s/86400,h=(s%86400)/3600,m=(s%3600)/60; if(d>0)return [NSString stringWithFormat:@"%ld天 %ld小时 %ld分钟 (%@秒)",(long)d,(long)h,(long)m,value]; if(h>0)return [NSString stringWithFormat:@"%ld小时 %ld分钟 (%@秒)",(long)h,(long)m,value]; }
        return [(NSNumber *)value stringValue];
    }
    NSString *s=[value isKindOfClass:NSString.class]?value:[value description];
    if([key.lowercaseString isEqualToString:@"token"]&&s.length)return @"已获取（安全隐藏）";
    return s.length?s:@"空";
}
+ (void)appendObject:(id)obj key:(NSString *)key depth:(NSUInteger)depth to:(NSMutableString *)out {
    NSString *indent=[@"    " stringByPaddingToLength:depth*4 withString:@" " startingAtIndex:0];
    if([obj isKindOfClass:NSDictionary.class]){ NSDictionary *d=obj; if(key.length)[out appendFormat:@"%@%@：\n",indent,[self labelForKey:key]]; NSArray *keys=[[d allKeys] sortedArrayUsingComparator:^NSComparisonResult(id a,id b){return [[a description] compare:[b description]];}]; for(id k in keys)[self appendObject:d[k] key:[k description] depth:(key.length?depth+1:depth) to:out]; return; }
    if([obj isKindOfClass:NSArray.class]){ NSArray *a=obj; [out appendFormat:@"%@%@：\n",indent,[self labelForKey:key]]; if(!a.count){[out appendFormat:@"%@    无\n",indent];return;} [a enumerateObjectsUsingBlock:^(id v,NSUInteger idx,BOOL *stop){ if([v isKindOfClass:NSDictionary.class]||[v isKindOfClass:NSArray.class]){[out appendFormat:@"%@    [%lu]\n",indent,(unsigned long)(idx+1)];[self appendObject:v key:@"" depth:depth+2 to:out];}else [out appendFormat:@"%@    • %@\n",indent,[self scalarText:v key:key]]; }]; return; }
    [out appendFormat:@"%@%@：%@\n",indent,[self labelForKey:key],[self scalarText:obj key:key]];
}
+ (NSString *)displayTextForObject:(id)obj { if(!obj||obj==NSNull.null)return @"服务器未返回可显示内容"; if([obj isKindOfClass:NSString.class])return [(NSString *)obj length]?obj:@"服务器返回空内容"; NSMutableString *s=[NSMutableString string]; [self appendObject:obj key:@"" depth:0 to:s]; return [s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]; }
+ (NSString *)displayTextForDictionary:(NSDictionary *)dictionary { return [self displayTextForObject:dictionary?:@{}]; }
+ (NSString *)titleForNotice:(id)notice fallback:(NSString *)fallback { if([notice isKindOfClass:NSDictionary.class]){id t=notice[@"title"]; if([t isKindOfClass:NSString.class]&&[t length])return t;} return fallback.length?fallback:@"公告"; }
@end

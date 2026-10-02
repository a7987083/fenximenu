from pathlib import Path

root = Path(__file__).resolve().parents[2]
makefile = root / "hfamap/Makefile"
cyber = root / "hfamap/src/HFAMapCyberUI.m"
jsonexp = root / "hfamap/src/HFAMapJSONExport.m"

s = makefile.read_text()
needle = "src/HFAMapCyberUI.m"
if "src/HFAMapUnifiedIL2CPPTrace.mm" not in s:
    s = s.replace(needle, needle + " src/HFAMapUnifiedIL2CPPTrace.mm")
makefile.write_text(s)

s = cyber.read_text()
if "HFAUnifiedIL2CPPTraceArm" not in s:
    s = s.replace(
        "extern unsigned HFAAppLocalExecuteParser(void);",
        """extern unsigned HFAAppLocalExecuteParser(void);
extern BOOL HFAUnifiedIL2CPPTraceIsArmed(void);
extern NSDictionary *HFAUnifiedIL2CPPTraceArm(NSTimeInterval duration);
extern NSDictionary *HFAUnifiedIL2CPPTraceStop(NSString *reason);"""
    )
    marker = "- (void)actionCyberExport:(UIButton *)sender {"
    pos = s.index(marker)
    end = s.index("\n}\n\n@end", pos)
    insertion = r'''
- (void)actionCyberTrace:(UIButton *)sender {
    if (HFAUnifiedIL2CPPTraceIsArmed()) {
        NSDictionary *result = HFAUnifiedIL2CPPTraceStop(@"manual-stop");
        HFACyberUIAppendLog([NSString stringWithFormat:@"[TRACE] %@ file=%@",
                             result[@"status"] ?: @"?", result[@"file"] ?: @"?"]);
        [sender setTitle:@"跟踪功能(8s)" forState:UIControlStateNormal];
        return;
    }
    NSDictionary *result = HFAUnifiedIL2CPPTraceArm(8.0);
    NSString *status = result[@"status"] ?: @"?";
    HFACyberUIAppendLog([NSString stringWithFormat:@"[TRACE] status=%@ mainExecutable=%@",
                         status, result[@"mainExecutable"] ?: @"?"]);
    if ([status isEqualToString:@"armed"]) {
        HFACyberUIAppendLog(@"[TRACE] 现在只操作一次原菜单目标功能；只关联点击后的 0~500ms IL2CPP 调用。");
        [sender setTitle:@"停止跟踪" forState:UIControlStateNormal];
    }
}
'''
    s = s[:end+3] + insertion + s[end+3:]
    old = 'UIButton *exportButton = HFACyberButton(@"解析并导出", [UIColor cyanColor], CGRectMake(10.0, 75.0, leftWidth - 20.0, 36.0), @selector(actionCyberExport:));\n    [leftPanel addSubview:exportButton];'
    new = old + '\n    UIButton *traceButton = HFACyberButton(@"跟踪功能(8s)", HFACyberColor(0.35, 1.0, 0.45, 1.0), CGRectMake(10.0, 130.0, leftWidth - 20.0, 36.0), @selector(actionCyberTrace:));\n    [leftPanel addSubview:traceButton];'
    if old not in s:
        raise SystemExit("CyberUI button anchor missing")
    s = s.replace(old, new)
cyber.write_text(s)

s = jsonexp.read_text()
if "HFAJSONNormalizeMainImageAliases" not in s:
    anchor = "static const char *HFAJSONBase(const char *path) {"
    p = s.index(anchor)
    end = s.index("\n}\n", p) + 3
    helper = r'''
static NSString *HFAJSONRealMainExecutableName(void) {
    NSString *name = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleExecutable"];
    if (![name isKindOfClass:[NSString class]] || !name.length)
        name = NSBundle.mainBundle.executablePath.lastPathComponent;
    return name.length ? name : @"MainExecutable";
}

static id HFAJSONNormalizeMainImageAliases(id value) {
    if ([value isKindOfClass:[NSArray class]]) {
        NSMutableArray *out = [NSMutableArray arrayWithCapacity:[value count]];
        for (id child in (NSArray *)value)
            [out addObject:HFAJSONNormalizeMainImageAliases(child) ?: [NSNull null]];
        return out;
    }
    if (![value isKindOfClass:[NSDictionary class]]) return value;
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    for (id key in (NSDictionary *)value) {
        id child = value[key];
        if ([key isKindOfClass:[NSString class]] &&
            [child isKindOfClass:[NSString class]] &&
            ([(NSString *)key isEqualToString:@"image"] ||
             [(NSString *)key isEqualToString:@"menuImage"] ||
             [(NSString *)key isEqualToString:@"declaredImage"] ||
             [(NSString *)key isEqualToString:@"resolvedImage"] ||
             [(NSString *)key isEqualToString:@"targetImage"]) &&
            [(NSString *)child isEqualToString:@"@main"]) {
            out[key] = HFAJSONRealMainExecutableName();
        } else {
            out[key] = HFAJSONNormalizeMainImageAliases(child) ?: [NSNull null];
        }
    }
    return out;
}
'''
    s = s[:end] + helper + s[end:]
    old = '        NSError *error = nil;\n        NSData *json = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:&error];'
    new = '        root = [[HFAJSONNormalizeMainImageAliases(root) mutableCopy] autorelease];\n        root[@"mainExecutable"] = HFAJSONRealMainExecutableName();\n\n' + old
    if old not in s:
        raise SystemExit("JSON export serialization anchor missing")
    s = s.replace(old, new)
jsonexp.write_text(s)

print("v1.9.37.11 unified IL2CPP runtime resolver applied")

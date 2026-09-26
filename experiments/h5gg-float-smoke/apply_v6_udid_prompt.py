from pathlib import Path

p = Path(__file__).with_name('H5GGFloatSmoke.m')
s = p.read_text()
s = s.replace('#import "ZONDylibVerify.h"', '#import "ZONDylibVerify.h"\n#import "ZONUDIDPrompt.h"')
old = '''    NSString *udid = [self autoUDID];
    if (udid.length <= 8) {
        [self presentTitle:@"无法验证" message:@"没有取得 UDID。请确认当前注入环境已经提供 UDID。"];
        return;
    }
    [self checkLegacyAuthorizationForUDID:udid activationSuccessMessage:nil];'''
new = '''    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSString *udid = [defaults stringForKey:@"ZONUDID"];
    if (udid.length > 8) {
        [self checkLegacyAuthorizationForUDID:udid activationSuccessMessage:nil];
        return;
    }
    NSString *prefill = [self autoUDID];
    __weak typeof(self) weakSelf = self;
    [ZONUDIDPrompt presentFrom:[self presenter] prefilled:prefill completion:^(NSString *value) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self || value.length <= 8) return;
        [defaults setObject:value forKey:@"ZONUDID"];
        [self checkLegacyAuthorizationForUDID:value activationSuccessMessage:nil];
    }];'''
if old not in s:
    raise SystemExit('V6 patch target not found')
p.write_text(s.replace(old, new))

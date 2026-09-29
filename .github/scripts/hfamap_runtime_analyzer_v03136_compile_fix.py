from pathlib import Path

EXPORTER=Path('hfamap/src/HFAMapJSONExport.m')
s=EXPORTER.read_text()
old='if([[x[@"id"] isKindOfClass:[NSString class]]?x[@"id"]:@""] isEqualToString:identifier])'
new='if([([x[@"id"] isKindOfClass:[NSString class]] ? x[@"id"] : @"") isEqualToString:identifier])'
if old not in s:
    raise SystemExit('v03136 exporter expression anchor missing')
s=s.replace(old,new,1)
EXPORTER.write_text(s)
print('v0.3.13.6 compile fix applied')

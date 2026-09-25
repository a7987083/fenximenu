from pathlib import Path

P = Path('hfamap/src/HFAMapGenericMenuResolver.m')
s = P.read_text()


def span(text, name):
    needle = name + '('
    i = text.find(needle)
    if i < 0: raise SystemExit(name + ': missing')
    start = text.rfind('\n', 0, i) + 1
    brace = text.find('{', i)
    depth = 0; instr = False; esc = False
    for j in range(brace, len(text)):
        ch = text[j]
        if instr:
            if esc: esc = False
            elif ch == '\\': esc = True
            elif ch == '"': instr = False
            continue
        if ch == '"': instr = True; continue
        if ch == '{': depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0: return start, j + 1
    raise SystemExit(name + ': unterminated')


def replace(text, name, new):
    a,b = span(text,name)
    return text[:a] + new + text[b:]

if '#import "HFAMapOutputPaths.h"' not in s:
    pos = 0
    lines=s.splitlines(True)
    for i,line in enumerate(lines):
        if line.startswith('#import '): pos=i+1
    lines.insert(pos,'#import "HFAMapOutputPaths.h"\n')
    s=''.join(lines)

s = replace(s, 'HFAGenericLog', r'''static void HFAGenericLog(const char *fmt, ...) {
    @autoreleasepool {
        NSString *path = HFAOutputPath(@"HFAMap_Learn.log");
        FILE *f = fopen(path.fileSystemRepresentation, "a");
        if (!f) return;
        va_list ap;
        va_start(ap, fmt);
        vfprintf(f, fmt, ap);
        va_end(ap);
        fflush(f);
        fclose(f);
    }
}''')

s = replace(s, 'HFAGenericJSON', r'''static void HFAGenericJSON(NSDictionary *record) {
    if (!record || ![NSJSONSerialization isValidJSONObject:record]) return;
    @autoreleasepool {
        @try {
            NSMutableDictionary *envelope = [record mutableCopy];
            envelope[@"hfamapVersion"] = @"1.9.28";
            envelope[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
            NSData *json = [NSJSONSerialization dataWithJSONObject:envelope options:0 error:nil];
            if (!json) return;
            NSString *path = HFAOutputPath(@"HFAMap_MenuMap.jsonl");
            NSFileManager *fm = [NSFileManager defaultManager];
            if (![fm fileExistsAtPath:path]) [fm createFileAtPath:path contents:nil attributes:nil];
            NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
            if (!handle) return;
            [handle seekToEndOfFile];
            [handle writeData:json];
            [handle writeData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];
            [handle closeFile];
        } @catch (__unused id exception) {
            HFAGenericLog("[GENERIC-JSON-ERROR] objc-exception\n");
        }
    }
}''')

if 'Documents/HFAMap_' in s:
    raise SystemExit('generic resolver still contains direct Documents/HFAMap_ path')
P.write_text(s)
print('generic resolver bundle output paths fixed')

from pathlib import Path
import re

ROOT = Path('hfamap')
SRC = ROOT / 'src'
MAKEFILE = ROOT / 'Makefile'

HEADER = SRC / 'HFAMapOutputPaths.h'
IMPL = SRC / 'HFAMapOutputPaths.m'

HEADER.write_text(r'''#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSString *HFAOutputDirectory(void);
FOUNDATION_EXPORT NSString *HFAOutputPath(NSString *filename);
FOUNDATION_EXPORT NSString *HFAOutputBundleIdentifier(void);
''')

IMPL.write_text(r'''#import "HFAMapOutputPaths.h"

static NSString *HFASafePathComponent(NSString *value) {
    if (![value isKindOfClass:[NSString class]] || !value.length) return @"unknown.bundle";
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"];
    NSMutableString *out = [NSMutableString stringWithCapacity:value.length];
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar ch = [value characterAtIndex:i];
        [out appendFormat:[allowed characterIsMember:ch] ? @"%C" : @"_", ch];
    }
    return out.length ? out : @"unknown.bundle";
}

NSString *HFAOutputBundleIdentifier(void) {
    NSString *bundleID = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleIdentifier"];
    if (![bundleID isKindOfClass:[NSString class]] || !bundleID.length)
        bundleID = [NSBundle mainBundle].bundleIdentifier;
    return HFASafePathComponent(bundleID ?: @"unknown.bundle");
}

NSString *HFAOutputDirectory(void) {
    static NSString *directory = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *docs = documents.firstObject;
        if (!docs.length) docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        NSString *folder = [NSString stringWithFormat:@"HFAMap_%@", HFAOutputBundleIdentifier()];
        NSString *candidate = [docs stringByAppendingPathComponent:folder];
        NSError *error = nil;
        BOOL ok = [[NSFileManager defaultManager] createDirectoryAtPath:candidate
                                            withIntermediateDirectories:YES
                                                             attributes:nil
                                                                  error:&error];
        directory = [(ok ? candidate : docs) copy];
    });
    return directory;
}

NSString *HFAOutputPath(NSString *filename) {
    if (![filename isKindOfClass:[NSString class]] || !filename.length)
        return HFAOutputDirectory();
    return [HFAOutputDirectory() stringByAppendingPathComponent:filename.lastPathComponent];
}
''')


def ensure_import(text: str) -> str:
    if '#import "HFAMapOutputPaths.h"' in text:
        return text
    lines = text.splitlines(True)
    insert = 0
    for i, line in enumerate(lines):
        if line.startswith('#import '):
            insert = i + 1
    lines.insert(insert, '#import "HFAMapOutputPaths.h"\n')
    return ''.join(lines)


for path in list(SRC.glob('*.m')) + list(SRC.glob('*.mm')):
    if path.name == 'HFAMapOutputPaths.m':
        continue
    text = path.read_text()
    original = text

    text = re.sub(
        r'\[NSHomeDirectory\(\) stringByAppendingPathComponent:@"Documents/(HFAMap_[^"]+)"\]',
        r'HFAOutputPath(@"\1")',
        text,
    )

    if path.name == 'HFAMapJSONExport.m':
        text = re.sub(
            r'static NSString \*HFAJSONDocuments\(void\) \{\s*return \[NSHomeDirectory\(\) stringByAppendingPathComponent:@"Documents"\];\s*\}',
            'static NSString *HFAJSONDocuments(void) {\n    return HFAOutputDirectory();\n}',
            text,
            count=1,
        )

    if text != original:
        text = ensure_import(text)
        path.write_text(text)

cyber = SRC / 'HFAMapCyberUI.m'
s = cyber.read_text()
s = ensure_import(s)
s = re.sub(r'header\.text = @"[^\n"]*HFAMap[^\n"]*";',
           'header.text = @"  HFAMap RuntimeAnalyzer v0.3.2 AutoBackend";', s, count=1)
s = re.sub(r'HFACyberUIAppendLog\(@"\[System\] HFAMap[^\n"]*ready\."\);',
           'HFACyberUIAppendLog(@"[System] HFAMap RuntimeAnalyzer v0.3.2 AutoBackend ready.");', s, count=1)
if '[System] output=%@' not in s:
    anchor = 'HFACyberUIAppendLog(@"[System] HFAMap RuntimeAnalyzer v0.3.2 AutoBackend ready.");'
    if anchor in s:
        s = s.replace(anchor,
                      anchor + '\n    HFACyberUIAppendLog([NSString stringWithFormat:@"[System] output=%@", HFAOutputDirectory()]);',
                      1)
cyber.write_text(s)

app = SRC / 'HFAMapAppLocalResolver.m'
s = app.read_text()
s, count = re.subn(
    r'@"HFAMap(?:Universal)?[^\n"]*AppLocalMenuResolver"',
    '@"HFAMap RuntimeAnalyzer v0.3.2 AutoBackend"',
    s,
    count=1,
)
if count == 0 and '@"analyzer"' in s:
    s = re.sub(r'(@"analyzer"\s*:\s*)@"[^"]*"',
               r'\1@"HFAMap RuntimeAnalyzer v0.3.2 AutoBackend"', s, count=1)
app.write_text(s)

make = MAKEFILE.read_text()
if 'src/HFAMapOutputPaths.m' not in make:
    marker = 'src/HFAMapCyberUI.m'
    if marker not in make:
        raise SystemExit('Makefile source anchor missing')
    make = make.replace(marker, marker + ' src/HFAMapOutputPaths.m', 1)
MAKEFILE.write_text(make)

# Strong self-checks. The first scan button must remain the exact v0.3-style
# discovery boundary: candidate discovery only, no parser/backend analyzer call.
ui = cyber.read_text()
scan_start = ui.find('- (void)actionCyberScan:')
scan_end = ui.find('- (void)actionCyberExport:', scan_start)
if scan_start < 0 or scan_end < 0:
    raise SystemExit('UI scan/export actions not found')
scan_body = ui[scan_start:scan_end]
if 'HFAAppLocalScanCandidates()' not in scan_body:
    raise SystemExit('baseline discovery call missing')
if 'HFAAppLocalExecuteParser()' in scan_body or 'HFAAnalyzerV02ScanSelectedImage' in scan_body:
    raise SystemExit('deep resolver leaked into discovery button')
if 'HFAMap RuntimeAnalyzer v0.3.2 AutoBackend' not in ui:
    raise SystemExit('v0.3.2 UI version missing')
if 'HFAOutputDirectory()' not in (SRC / 'HFAMapJSONExport.m').read_text():
    raise SystemExit('JSON exporter is not routed to bundle output directory')
app_text = app.read_text()
if 'HFAOutputPath(@"HFAMap_Learn.log")' not in app_text:
    raise SystemExit('AppLocal learning log is not routed to bundle output directory')
if 'HFAOutputPath(@"HFAMap_AppLocalCandidates.json")' not in app_text:
    raise SystemExit('AppLocal candidate index is not routed to bundle output directory')
if 'src/HFAMapOutputPaths.m' not in MAKEFILE.read_text():
    raise SystemExit('output path helper missing from Makefile')

leftovers = []
for path in list(SRC.glob('*.m')) + list(SRC.glob('*.mm')):
    if path.name == 'HFAMapOutputPaths.m':
        continue
    text = path.read_text()
    if 'Documents/HFAMap_' in text:
        leftovers.append(path.name)
if leftovers:
    raise SystemExit('direct Documents/HFAMap_ paths remain: ' + ','.join(leftovers))

print('v0.3.2 output layout + UI version patch applied; baseline discovery boundary verified')

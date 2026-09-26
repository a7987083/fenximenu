from pathlib import Path

SRC = Path('hfamap/src/HFAMapRuntimeAnalyzerV02.m')
UI = Path('hfamap/src/HFAMapCyberUI.m')
MAKE = Path('hfamap/Makefile')

s = SRC.read_text()
if '#import "HFARuntimeSemanticAnalyzer.h"' not in s:
    s = '#import "HFARuntimeSemanticAnalyzer.h"\n' + s

needle = 'b[@"backendType"]=stype;b[@"hookReturnEvidence"]=HFAV033HookReturnEvidence(repl,l);'
replacement = '''b[@"backendType"]=stype;b[@"hookReturnEvidence"]=HFAV033HookReturnEvidence(repl,l);
        NSDictionary *sem34=HFASemanticAnalyzeReplacement(repl,slot);NSString *stype34=[sem34[@"semanticType"] isKindOfClass:NSString.class]?sem34[@"semanticType"]:@"unknown-runtime";
        b[@"semanticEvidence"]=sem34;b[@"legacySemanticType"]=stype;
        if(![stype34 isEqual:@"unknown-runtime"]){b[@"semanticType"]=stype34;b[@"backendType"]=@"runtime-semantic";}else b[@"semanticType"]=stype;
        uintptr_t targetRuntime=(uintptr_t)[target[@"runtimeAddress"] unsignedLongLongValue];NSDictionary *own34=HFAIL2CPPDescribeOwningMethod(targetRuntime);b[@"owningMethod"]=own34?:@{};'''
if needle not in s:
    raise SystemExit('v034 semantic integration anchor missing')
s = s.replace(needle, replacement, 1)

# Preserve v0.3.3/v0.3.2 compatibility outputs while introducing a canonical
# v0.3.4 evidence file in the same per-bundle output folder.
out_old = 'NSString *p33=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v033.json");NSString *p32=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v032.json");NSString *p03=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v03.json");[json writeToFile:p33 atomically:YES];[json writeToFile:p32 atomically:YES];[json writeToFile:p03 atomically:YES];'
out_new = 'NSString *p34=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v034.json");NSString *p33=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v033.json");NSString *p32=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v032.json");NSString *p03=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v03.json");[json writeToFile:p34 atomically:YES];[json writeToFile:p33 atomically:YES];[json writeToFile:p32 atomically:YES];[json writeToFile:p03 atomically:YES];'
if out_old not in s:
    raise SystemExit('v034 output integration anchor missing')
s = s.replace(out_old, out_new, 1)

s = s.replace('com.hfa.runtime-analyzer/v0.3.3', 'com.hfa.runtime-analyzer/v0.3.4', 1)
s = s.replace('[V033-BACKEND]', '[V034-BACKEND]').replace('[V033-SCAN-END]', '[V034-SCAN-END]').replace('[V033-DECRYPT]', '[V034-DECRYPT]')
SRC.write_text(s)

ui = UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.3 StaticParity', 'HFAMap RuntimeAnalyzer v0.3.4 SemanticBackend', 2)
UI.write_text(ui)

m = MAKE.read_text()
if 'src/HFARuntimeSemanticAnalyzer.m' not in m:
    lines = m.splitlines()
    done = False
    for i, line in enumerate(lines):
        if '_FILES' in line and '=' in line and 'HFAMap' in line:
            lines[i] = line + ' src/HFARuntimeSemanticAnalyzer.m'
            done = True
            break
    if not done:
        raise SystemExit('v034 Makefile FILES anchor missing')
    MAKE.write_text('\n'.join(lines) + '\n')

# Hard regression gates.
ss = SRC.read_text()
required = [
    '#import "HFARuntimeSemanticAnalyzer.h"',
    'HFASemanticAnalyzeReplacement(repl,slot)',
    'HFAIL2CPPDescribeOwningMethod(targetRuntime)',
    '@"semanticEvidence"', '@"semanticType"', '@"owningMethod"',
    'com.hfa.runtime-analyzer/v0.3.4',
    'HFAMap_RuntimeAnalyzer_v034.json',
    '[V034-BACKEND]', '[V034-SCAN-END]', '[V034-DECRYPT]'
]
for x in required:
    if x not in ss:
        raise SystemExit('v034 generated source missing: ' + x)
if 'HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v034.json")' not in ss:
    raise SystemExit('v034 bundle output routing missing')
if 'Documents/HFAMap_RuntimeAnalyzer' in ss:
    raise SystemExit('v034 direct Documents output regression')
print('v0.3.4 semantic backend integration applied')

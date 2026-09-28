from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
CLUSTER=Path(__file__).with_name('hfamap_runtime_analyzer_v03134_static_cluster_ownership.py')
subprocess.check_call(['python3',str(CLUSTER)],cwd=ROOT)

APPLOCAL=Path('hfamap/src/HFAMapAppLocalResolver.m')


def function_span(text, name):
    needle=name+'('
    pos=0
    while True:
        i=text.find(needle,pos)
        if i<0: raise SystemExit(f'{name}: function not found')
        line_start=text.rfind('\n',0,i)+1
        prefix=text[line_start:i].strip()
        brace=text.find('{',i)
        semi=text.find(';',i)
        if brace>=0 and (semi<0 or brace<semi) and prefix and not prefix.startswith(('if','for','while','return')):
            depth=0; instr=False; esc=False
            for j in range(brace,len(text)):
                ch=text[j]
                if instr:
                    if esc: esc=False
                    elif ch=='\\': esc=True
                    elif ch=='"': instr=False
                    continue
                if ch=='"': instr=True; continue
                if ch=='{': depth+=1
                elif ch=='}':
                    depth-=1
                    if depth==0:return line_start,j+1
            raise SystemExit(f'{name}: closing brace not found')
        pos=i+len(needle)

s=APPLOCAL.read_text()
start,end=function_span(s,'HFAAppLocalScanCandidates')
fn=s[start:end]
old='''        HFAAppLocalWriteIndex(found, discovered.count);\n        HFAAppLocalLog([NSString stringWithFormat:@"[SELECT-WAIT] candidates=%lu manualSelectionRequired=1", (unsigned long)found.count]);\n        if (found.count) HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 扫描完成：发现 %lu 个候选，请手动选择", (unsigned long)found.count]);\n        else HFACyberUIAppendLog(@"❌ 没有识别到已知菜单 dylib");\n        return (unsigned)found.count;'''
new='''        HFAAppLocalWriteIndex(found, discovered.count);\n        if (found.count == 1) {\n            NSDictionary *record = found.firstObject;\n            @synchronized([NSObject class]) {\n                snprintf(gHFAAppLocalPrimaryImage, sizeof(gHFAAppLocalPrimaryImage), "%s", [record[@"image"] UTF8String] ?: "");\n                snprintf(gHFAAppLocalPrimaryFamily, sizeof(gHFAAppLocalPrimaryFamily), "%s", [record[@"family"] UTF8String] ?: "");\n                snprintf(gHFAAppLocalPrimaryVariant, sizeof(gHFAAppLocalPrimaryVariant), "%s", [record[@"variant"] UTF8String] ?: "");\n                snprintf(gHFAAppLocalPrimaryPath, sizeof(gHFAAppLocalPrimaryPath), "%s", [record[@"path"] UTF8String] ?: "");\n                gHFAAppLocalPrimaryLoadedIndex = [record[@"loadedIndex"] intValue];\n            }\n            HFAAppLocalLog([NSString stringWithFormat:@"[AUTO-SELECT] candidates=1 index=0 image=%@ family=%@ variant=%@ loaded=%@ loadedIndex=%@ path=%@",\n                            record[@"image"], record[@"family"], record[@"variant"],\n                            [record[@"loaded"] boolValue] ? @"yes" : @"no", record[@"loadedIndex"], record[@"path"]]);\n            HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 已自动选择唯一候选：%@", record[@"image"]]);\n        } else if (found.count > 1) {\n            HFAAppLocalLog([NSString stringWithFormat:@"[SELECT-WAIT] candidates=%lu manualSelectionRequired=1", (unsigned long)found.count]);\n            HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 扫描完成：发现 %lu 个候选，请手动选择", (unsigned long)found.count]);\n        } else {\n            HFAAppLocalLog(@"[SELECT-WAIT] candidates=0 manualSelectionRequired=0");\n            HFACyberUIAppendLog(@"❌ 没有识别到已知菜单 dylib");\n        }\n        return (unsigned)found.count;'''
if old not in fn: raise SystemExit('v03134 unique auto-select anchor missing')
fn=fn.replace(old,new,1)
s=s[:start]+fn+s[end:]
APPLOCAL.write_text(s)

out=APPLOCAL.read_text()
for marker in ['[AUTO-SELECT] candidates=1','found.count == 1','found.count > 1','manualSelectionRequired=0']:
    if marker not in out: raise SystemExit('missing auto-select marker '+marker)
print('v0.3.13.4 unique dylib auto-selection applied')

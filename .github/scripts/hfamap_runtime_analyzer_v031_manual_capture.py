from pathlib import Path

ROOT = Path('hfamap')
UI = ROOT / 'src/HFAMapCyberUI.m'
MAKE = ROOT / 'Makefile'

ui = UI.read_text()
make = MAKE.read_text()

proto = 'extern BOOL HFAManualCaptureStart8s(void);\nextern BOOL HFAManualCaptureIsActive(void);\n'
anchor = 'extern unsigned HFAAppLocalExecuteParser(void);\n'
if proto.strip() not in ui:
    if anchor not in ui:
        raise SystemExit('CyberUI extern anchor missing')
    ui = ui.replace(anchor, anchor + proto, 1)

if 'actionCyberCapture8s:' not in ui:
    method_anchor = '- (void)actionCyberExport:(UIButton *)sender {'
    start = ui.find(method_anchor)
    if start < 0:
        raise SystemExit('CyberUI export action missing')
    depth = 0
    brace = ui.find('{', start)
    end = -1
    for i in range(brace, len(ui)):
        if ui[i] == '{':
            depth += 1
        elif ui[i] == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end < 0:
        raise SystemExit('CyberUI export method end missing')
    method = r'''

- (void)actionCyberCapture8s:(UIButton *)sender {
    if (HFAManualCaptureIsActive()) {
        HFACyberUIAppendLog(@"⚠️ 8 秒捕获已经在运行");
        return;
    }
    sender.enabled = NO;
    HFACyberUIAppendLog(@"\n[COMMAND] 8 秒手动捕获");
    BOOL started = HFAManualCaptureStart8s();
    if (!started) {
        sender.enabled = YES;
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8200 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
        sender.enabled = YES;
    });
}
'''
    ui = ui[:end] + method + ui[end:]

button_anchor = '    [leftPanel addSubview:exportButton];\n'
button_code = '''    UIButton *captureButton = HFACyberButton(@"8秒手动捕获", [UIColor greenColor], CGRectMake(10.0, 130.0, leftWidth - 20.0, 36.0), @selector(actionCyberCapture8s:));\n    [leftPanel addSubview:captureButton];\n'''
if '8秒手动捕获' not in ui:
    if button_anchor not in ui:
        raise SystemExit('CyberUI button anchor missing')
    ui = ui.replace(button_anchor, button_anchor + button_code, 1)

ready_anchor = '    HFACyberUIAppendLog(@"[System] 先扫描菜单模块，再解析并导出。");\n'
ready_code = '    HFACyberUIAppendLog(@"[System] v0.3.1：解析后可启动 8 秒手动多功能捕获。\");\n'
if 'v0.3.1：解析后可启动' not in ui:
    if ready_anchor not in ui:
        raise SystemExit('CyberUI ready anchor missing')
    ui = ui.replace(ready_anchor, ready_anchor + ready_code, 1)

source = 'src/HFAMapManualCapture.m'
if source not in make:
    marker = 'HFAMapUniversal_FILES = '
    p = make.find(marker)
    if p < 0:
        raise SystemExit('Makefile files line missing')
    e = make.find('\n', p)
    if e < 0:
        raise SystemExit('Makefile files line end missing')
    make = make[:e] + ' ' + source + make[e:]

for token in ('HFAManualCaptureStart8s', 'actionCyberCapture8s:', '8秒手动捕获'):
    if token not in ui:
        raise SystemExit(f'missing CyberUI token: {token}')
if source not in make:
    raise SystemExit('manual capture source not in Makefile')

UI.write_text(ui)
MAKE.write_text(make)
print('v0.3.1 manual capture wiring applied')

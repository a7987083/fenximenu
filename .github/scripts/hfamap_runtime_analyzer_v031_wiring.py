from pathlib import Path

root = Path('hfamap')
ui_path = root / 'src/HFAMapCyberUI.m'
make_path = root / 'Makefile'
ui = ui_path.read_text()
make = make_path.read_text()

anchor = 'extern unsigned HFAAppLocalExecuteParser(void);\n'
proto = 'extern BOOL HFAManualCaptureStart8s(void);\nextern BOOL HFAManualCaptureIsActive(void);\n'
if 'HFAManualCaptureStart8s' not in ui:
    if anchor not in ui:
        raise SystemExit('extern anchor missing')
    ui = ui.replace(anchor, anchor + proto, 1)

if 'actionCyberCapture8s:' not in ui:
    end_impl = ui.find('\n@end\n')
    if end_impl < 0:
        raise SystemExit('controller end missing')
    method = '''\n- (void)actionCyberCapture8s:(UIButton *)sender {\n    if (HFAManualCaptureIsActive()) return;\n    sender.enabled = NO;\n    HFACyberUIAppendLog(@"\\n[COMMAND] 8 秒手动捕获");\n    if (!HFAManualCaptureStart8s()) { sender.enabled = YES; return; }\n    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8200 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{ sender.enabled = YES; });\n}\n'''
    ui = ui[:end_impl] + method + ui[end_impl:]

if '8秒手动捕获' not in ui:
    anchor = '    [leftPanel addSubview:exportButton];\n'
    if anchor not in ui:
        raise SystemExit('button anchor missing')
    button = '    UIButton *captureButton = HFACyberButton(@"8秒手动捕获", [UIColor greenColor], CGRectMake(10.0, 130.0, leftWidth - 20.0, 36.0), @selector(actionCyberCapture8s:));\n    [leftPanel addSubview:captureButton];\n'
    ui = ui.replace(anchor, anchor + button, 1)

source = 'src/HFAMapManualCapture.m'
if source not in make:
    marker = 'HFAMapUniversal_FILES = '
    p = make.find(marker)
    if p < 0:
        raise SystemExit('Makefile anchor missing')
    e = make.find('\n', p)
    make = make[:e] + ' ' + source + make[e:]

ui_path.write_text(ui)
make_path.write_text(make)
print('v0.3.1 manual capture final wiring applied')

from pathlib import Path

cyber = Path('hfamap/src/HFAMapCyberUI.m')
text = cyber.read_text()
marker = '[System] HFAMap v1.9.37.4 ManualCandidateSelection ready.'
anchor = 'HFACyberUIAppendLog(@"[System] 先扫描菜单模块，手动选择目标，再解析并导出。");'
if marker not in text:
    if anchor not in text:
        raise SystemExit('manual-selection system anchor missing')
    text = text.replace(anchor, anchor + '\n    HFACyberUIAppendLog(@"' + marker + '");', 1)
cyber.write_text(text)
print('finalized v19374 explicit runtime marker')

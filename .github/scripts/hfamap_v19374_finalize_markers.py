from pathlib import Path

cyber = Path('hfamap/src/HFAMapCyberUI.m')
text = cyber.read_text()

runtime_marker = '[System] HFAMap v1.9.37.4 ManualCandidateSelection ready.'
panel_anchor = 'id HFACyberUICreatePanel(id hostWindow) {'
if runtime_marker not in text:
    if panel_anchor not in text:
        raise SystemExit('HFACyberUICreatePanel anchor missing')
    text = text.replace(panel_anchor, panel_anchor + '\n    HFACyberUIAppendLog(@"' + runtime_marker + '");', 1)

selector_marker = '[SELECTOR-OPEN] manual candidate picker'
selector_anchor = '- (void)showCandidateSelector {'
if selector_marker not in text:
    if selector_anchor not in text:
        raise SystemExit('showCandidateSelector anchor missing')
    text = text.replace(selector_anchor, selector_anchor + '\n    HFACyberUIAppendLog(@"' + selector_marker + '");', 1)

cyber.write_text(text)
print('finalized v19374 runtime + selector ASCII markers')

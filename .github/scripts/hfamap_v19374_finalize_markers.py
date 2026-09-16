from pathlib import Path

cyber = Path('hfamap/src/HFAMapCyberUI.m')
text = cyber.read_text()
old = '[System] HFAMap AppLocalMenuResolver ready.'
new = '[System] HFAMap v1.9.37.4 ManualCandidateSelection ready.'
if old in text:
    text = text.replace(old, new, 1)
elif new not in text:
    raise SystemExit('Cyber UI ready marker missing')
cyber.write_text(text)
print('finalized v19374 explicit runtime marker')

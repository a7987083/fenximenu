from pathlib import Path

FILES = [
    Path('hfamap/src/HFAMapPatchExecutionTrace.m'),
    Path('hfamap/src/HFAMapJSONExport.m'),
    Path('hfamap/src/HFAMapAppLocalResolver.m'),
    Path('hfamap/src/HFAMapCyberUI.m'),
    Path('hfamap/src/HFAMapLegacy.m'),
]

old_full = 'HFAMapUniversal v1.9.37.10 UnifiedFeatureModel'
old_short = 'v1.9.37.10 UnifiedFeatureModel'
new_full = 'HFAMapUniversal v1.9.37.11 Canonical14Profile'
new_short = 'v1.9.37.11 Canonical14Profile'

changed = 0
for path in FILES:
    text = path.read_text()
    updated = text.replace(old_full, new_full).replace(old_short, new_short)
    if updated != text:
        path.write_text(updated)
        changed += 1

trace = Path('hfamap/src/HFAMapPatchExecutionTrace.m').read_text()
required = (
    'HFAAppendVerifiedEarnToDieRogueProfile',
    '8654D76C-B760-34FC-BEE0-FE70AE8C95C8',
    '0x2D98AC8',
    '0038211E',
    '0x2D9887C',
    '0038281E',
    '1F2003D5',
    '[VERIFIED-PROFILE-PATCH]',
)
for token in required:
    if token not in trace:
        raise SystemExit(f'missing verified canonical token: {token}')

if new_short not in '\n'.join(p.read_text() for p in FILES):
    raise SystemExit('v1.9.37.11 release marker missing')

print(f'promoted v1.9.37.11 Canonical14Profile; versionedFiles={changed}')

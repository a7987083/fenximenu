from pathlib import Path

path = Path('hfamap/src/HFAMapCyberUI.m')
s = path.read_text()

replacements = {
    '[UIFont fontWithName:@"CourierNewPSMT" size:11.0] ?: [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightRegular]':
        '[UIFont fontWithName:@"CourierNewPSMT" size:11.0] ?: [UIFont systemFontOfSize:11.0]',
    '[UIFont fontWithName:@"CourierNewPS-BoldMT" size:13.0] ?: [UIFont monospacedSystemFontOfSize:13.0 weight:UIFontWeightBold]':
        '[UIFont fontWithName:@"CourierNewPS-BoldMT" size:13.0] ?: [UIFont boldSystemFontOfSize:13.0]',
}

for old, new in replacements.items():
    count = s.count(old)
    if count < 1:
        raise SystemExit(f'Cyber UI font fallback pattern missing: {old}')
    s = s.replace(old, new)

if 'monospacedSystemFontOfSize:' in s:
    raise SystemExit('iOS 13-only monospacedSystemFontOfSize remains in Cyber UI')

path.write_text(s)
print('patched Cyber UI font fallbacks for iOS 12 deployment target')

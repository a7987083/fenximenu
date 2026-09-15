from pathlib import Path

legacy_path = Path('hfamap/src/HFAMapLegacy.m')
cyber_path = Path('hfamap/src/HFAMapCyberUI.m')
s = legacy_path.read_text()

old_globals = 'static id gTarget=0,gButton=0,gPanel=0,gWindow=0,gStatus=0;'
new_globals = 'static id gTarget=0,gButton=0,gPanel=0,gWindow=0;'
if s.count(old_globals) != 1:
    raise SystemExit(f'legacy UI globals expected once, got {s.count(old_globals)}')
s = s.replace(old_globals, new_globals, 1)


def remove_function(text, name):
    needle = name + '('
    pos = 0
    while True:
        i = text.find(needle, pos)
        if i < 0:
            raise SystemExit(f'{name}: function not found')
        line_start = text.rfind('\n', 0, i) + 1
        prefix = text[line_start:i].strip()
        brace = text.find('{', i)
        semi = text.find(';', i)
        if brace >= 0 and (semi < 0 or brace < semi) and prefix and not prefix.startswith(('if', 'for', 'while', 'return')):
            depth = 0
            for j in range(brace, len(text)):
                if text[j] == '{':
                    depth += 1
                elif text[j] == '}':
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        if end < len(text) and text[end] == '\n':
                            end += 1
                        return text[:line_start] + text[end:]
            raise SystemExit(f'{name}: closing brace not found')
        pos = i + len(needle)

for fn in ('mklabel', 'settext'):
    s = remove_function(s, fn)

for forbidden in ('gStatus', 'mklabel(', 'settext('):
    if forbidden in s:
        raise SystemExit(f'legacy UI cleanup incomplete: {forbidden}')

legacy_path.write_text(s)

# Keep the user-approved Courier look, but use iOS 12-safe fallbacks. The
# project deployment target is iOS 12, while monospacedSystemFontOfSize:weight:
# is iOS 13+. CourierNew remains the first choice, so the appearance is unchanged
# on normal devices; only the fallback API changes.
cyber = cyber_path.read_text()
replacements = {
    '[UIFont fontWithName:@"CourierNewPSMT" size:11.0] ?: [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightRegular]':
        '[UIFont fontWithName:@"CourierNewPSMT" size:11.0] ?: [UIFont systemFontOfSize:11.0]',
    '[UIFont fontWithName:@"CourierNewPS-BoldMT" size:13.0] ?: [UIFont monospacedSystemFontOfSize:13.0 weight:UIFontWeightBold]':
        '[UIFont fontWithName:@"CourierNewPS-BoldMT" size:13.0] ?: [UIFont boldSystemFontOfSize:13.0]',
}
for old, new in replacements.items():
    if old not in cyber:
        raise SystemExit(f'Cyber UI font fallback pattern missing: {old}')
    cyber = cyber.replace(old, new)
if 'monospacedSystemFontOfSize:' in cyber:
    raise SystemExit('iOS 13-only monospaced font fallback remains in Cyber UI')
cyber_path.write_text(cyber)

print('removed obsolete legacy panel helpers; patched Cyber UI font fallbacks for iOS 12')

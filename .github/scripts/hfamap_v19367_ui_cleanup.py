from pathlib import Path

path = Path('hfamap/src/HFAMapLegacy.m')
s = path.read_text()

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

path.write_text(s)
print('removed obsolete v1.9.36 panel status/label helpers after Cyber UI migration')

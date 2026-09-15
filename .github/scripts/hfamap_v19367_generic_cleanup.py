from pathlib import Path

path = Path('hfamap/src/HFAMapGenericMenuResolver.m')
s = path.read_text()


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
        if brace >= 0 and (semi < 0 or brace < semi) and prefix and not prefix.startswith(('if','for','while','return')):
            depth = 0
            for j in range(brace, len(text)):
                if text[j] == '{': depth += 1
                elif text[j] == '}':
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        if end < len(text) and text[end] == '\n': end += 1
                        return text[:line_start] + text[end:]
            raise SystemExit(f'{name}: closing brace not found')
        pos = i + len(needle)

# Discovery is now owned by AppLocalMenuResolver. Preserve object-level parsing
# (HFAGenericMenuObserveObject, descriptor inspection, feature extraction), but
# delete helpers/state that only served the old global class/image discovery.
obsolete = (
    'HFASeenClass',
    'HFALogMethod',
    'HFABytesContain',
    'HFAImageContainsCString',
    'HFAShouldScanImage',
)
for fn in obsolete:
    s = remove_function(s, fn)

for line in (
    'static Class gSeenClasses[512];\n',
    'static unsigned gSeenClassCount;\n',
):
    if s.count(line) != 1:
        raise SystemExit(f'generic discovery state expected once: {line.strip()} count={s.count(line)}')
    s = s.replace(line, '', 1)

for token in tuple(fn + '(' for fn in obsolete) + ('gSeenClasses', 'gSeenClassCount'):
    if token in s:
        raise SystemExit(f'generic cleanup incomplete: {token}')

path.write_text(s)
print('removed obsolete GenericMenu global class/image discovery helpers')

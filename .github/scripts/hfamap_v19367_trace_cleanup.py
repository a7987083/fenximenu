from pathlib import Path

path = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
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

# v1.9.36.7 no longer installs process-wide dynamic-registration discovery.
# Remove the complete obsolete helper chain and its storage. Do not fake-call
# dead functions or retain dead state solely to satisfy -Werror.
obsolete = (
    'HFADynamicRegistration4',
    'HFAInstallDynamicRegistrationHooks',
    'HFARecordDynamicRegistration',
    'HFADynamicRegistrationHookFor',
    'HFACopyNSString',
)
for fn in obsolete:
    s = remove_function(s, fn)

for line in (
    'static HFADynamicRegistrationHook gDynamicRegistrationHooks[128];\n',
    'static unsigned gDynamicRegistrationHookCount;\n',
):
    if s.count(line) != 1:
        raise SystemExit(f'dynamic registration state expected once: {line.strip()} count={s.count(line)}')
    s = s.replace(line, '', 1)

for token in tuple(fn + '(' for fn in obsolete) + (
    'gDynamicRegistrationHooks',
    'gDynamicRegistrationHookCount',
):
    if token in s:
        raise SystemExit(f'trace cleanup incomplete: {token}')

path.write_text(s)
print('removed complete obsolete dynamic-registration helper chain and storage')

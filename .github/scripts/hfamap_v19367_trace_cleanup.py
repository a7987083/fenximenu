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
# Remove the complete obsolete registration helper chain rather than retaining
# unreachable callbacks/recorders that can both trigger -Werror and invite
# accidental reintroduction of process-wide class discovery later.
for fn in ('HFADynamicRegistration4',
           'HFAInstallDynamicRegistrationHooks',
           'HFARecordDynamicRegistration'):
    s = remove_function(s, fn)

for forbidden in ('HFADynamicRegistration4(',
                  'HFAInstallDynamicRegistrationHooks(',
                  'HFARecordDynamicRegistration('):
    if forbidden in s:
        raise SystemExit(f'trace cleanup incomplete: {forbidden}')

path.write_text(s)
print('removed obsolete dynamic-registration callback/install/record chain')

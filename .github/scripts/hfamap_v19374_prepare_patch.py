from pathlib import Path

p = Path('.github/scripts/hfamap_v19374_manual_candidate_selection.py')
text = p.read_text()

anchor = '''def replace_named_function(text, name, replacement):\n    start, end = function_span(text, name)\n    return text[:start] + replacement + text[end:]\n\n'''
helper = anchor + '''def objc_method_span(text, selector):\n    needle = '- (void)' + selector\n    i = text.find(needle)\n    if i < 0:\n        raise SystemExit(f'{selector}: Objective-C method not found')\n    line_start = text.rfind('\\n', 0, i) + 1\n    brace = text.find('{', i)\n    if brace < 0:\n        raise SystemExit(f'{selector}: opening brace not found')\n    depth = 0\n    for j in range(brace, len(text)):\n        if text[j] == '{':\n            depth += 1\n        elif text[j] == '}':\n            depth -= 1\n            if depth == 0:\n                return line_start, j + 1\n    raise SystemExit(f'{selector}: closing brace not found')\n\n\ndef replace_objc_method(text, selector, replacement):\n    start, end = objc_method_span(text, selector)\n    return text[:start] + replacement + text[end:]\n\n'''

if 'def objc_method_span' not in text:
    if anchor not in text:
        raise SystemExit('replace_named_function anchor missing')
    text = text.replace(anchor, helper, 1)

text = text.replace("cyber = replace_named_function(cyber, '- (void)actionCyberScan:', scan_method)",
                    "cyber = replace_objc_method(cyber, 'actionCyberScan:', scan_method)")
text = text.replace("cyber = replace_named_function(cyber, '- (void)actionCyberExport:', export_method)",
                    "cyber = replace_objc_method(cyber, 'actionCyberExport:', export_method)")

p.write_text(text)
print('prepared v19374 patch: Objective-C method span resolver enabled')

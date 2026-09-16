from pathlib import Path

patcher = Path('.github/scripts/hfamap_v193710_unified_feature_model_v4.py')
code = compile(patcher.read_text(), str(patcher), 'exec')
exec(code, {'__name__': '__main__'})

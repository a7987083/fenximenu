from pathlib import Path

# Apply the v1.9.37.10 feature/export patch.
patcher = Path('.github/scripts/hfamap_v193710_unified_feature_model_v3.py')
code = compile(patcher.read_text(), str(patcher), 'exec')
exec(code, {'__name__': '__main__'})

# v1.9.37.10 must not modify the parser backend. v3 updates visible version
# markers globally, so restore the FamilyRuntimeResolver marker to the exact
# v1.9.37.9-generated text. This keeps the resolver byte-for-byte identical to
# the pre-v1.9.37.10 snapshot while other output/export modules retain .10.
family_path = Path('hfamap/src/HFAMapFamilyRuntimeResolver.m')
family = family_path.read_text()
family = family.replace('HFAMapUniversal v1.9.37.10 UnifiedFeatureModel',
                        'HFAMapUniversal v1.9.37.9 CompleteFeatureExport')
family = family.replace('v1.9.37.10 UnifiedFeatureModel',
                        'v1.9.37.9 CompleteFeatureExport')
family_path.write_text(family)
print('restored FamilyRuntimeResolver byte-compatible v1.9.37.9 marker')

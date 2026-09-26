from pathlib import Path

ROOT=Path('hfamap')
HDR=ROOT/'src'/'HFARuntimeSemanticAnalyzer.h'
SRC=ROOT/'src'/'HFAMapRuntimeAnalyzerV02.m'

h=HDR.read_text()
old='FOUNDATION_EXPORT NSArray<NSDictionary<NSString*,id>*> *HFASemanticFeatureBindings(NSArray *runtimeEvidence,NSDictionary *semanticEvidence,uintptr_t anchorAddress);'
new='FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> * _Nonnull HFASemanticFeatureBindings(NSArray * _Nonnull runtimeEvidence, NSDictionary * _Nonnull semanticEvidence, uintptr_t anchorAddress);'
if old not in h:
    raise SystemExit('v035 nullability declaration anchor missing')
h=h.replace(old,new,1)
HDR.write_text(h)

s=SRC.read_text()
start=s.find('static NSArray *HFAV035DescriptorlessActionBackends(')
end=s.find('static NSArray *HFAV035TargetConflicts(',start)
if start<0 or end<0:
    raise SystemExit('v035 descriptorless helper span missing')
fn=s[start:end]
old='''[fs addObject:b];}}\n    }\n    NSArray *ordered='''
new='''[fs addObject:b];}}\n    NSArray *ordered='''
if old not in fn:
    raise SystemExit('v035 extra-brace anchor missing')
fn=fn.replace(old,new,1)
s=s[:start]+fn+s[end:]
SRC.write_text(s)

# Structural sanity for the repaired helper.
fn=s[start:s.find('static NSArray *HFAV035TargetConflicts(',start)]
if 'NSArray *ordered=' not in fn or 'return out;' not in fn:
    raise SystemExit('v035 helper structure incomplete after fix')
if old in fn:
    raise SystemExit('v035 extra brace remains')
print('v0.3.5 generated compile fixes applied')

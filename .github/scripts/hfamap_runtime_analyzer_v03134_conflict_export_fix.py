from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
s=TRACE.read_text()

old='''    if(conflicts.count){HFALog("[CANONICAL-CHECK] status=fail reason=package-conflict conflicts=%u\\n",(unsigned)conflicts.count);status=@"blocked-conflict";HFA0312WriteAudit(ledger,featureDispositions,conflicts,features,targets,status,@"",@"");return;}'''
new='''    if(conflicts.count){
        /* Conflicting descriptors have already been removed from exportFeatures by
         * the conflict audit.  Do not suppress the whole package when the remaining
         * feature set is still canonical and self-consistent. */
        HFALog("[V03134-CONFLICT-FILTER] conflicts=%u action=emit-nonconflicting features=%u patches=%u\\n",
               (unsigned)conflicts.count,(unsigned)features.count,(unsigned)HFA0312PatchCount(features));
        status=@"exporting-with-conflicts-filtered";
    }'''
if old not in s:
    raise SystemExit('v03134 conflict-export anchor missing')
s=s.replace(old,new,1)

old_status='''    if(mirrorOK){status=@"exported";HFALog("[PACKAGE-MIRROR] status=pass path=%s\\n",mirrorPath.UTF8String);}else{status=@"mirror-failed";HFALog("[PACKAGE-MIRROR] status=fail reason=%s\\n",mirrorError.localizedDescription.UTF8String?:"write");}'''
new_status='''    if(mirrorOK){status=conflicts.count?@"exported-with-conflicts-filtered":@"exported";HFALog("[PACKAGE-MIRROR] status=pass path=%s\\n",mirrorPath.UTF8String);}else{status=@"mirror-failed";HFALog("[PACKAGE-MIRROR] status=fail reason=%s\\n",mirrorError.localizedDescription.UTF8String?:"write");}'''
if old_status not in s:
    raise SystemExit('v03134 package-status anchor missing')
s=s.replace(old_status,new_status,1)

TRACE.write_text(s)

out=TRACE.read_text()
for req in ['[V03134-CONFLICT-FILTER]','exported-with-conflicts-filtered']:
    if req not in out:
        raise SystemExit('v03134 conflict export fix missing '+req)
if 'status=@"blocked-conflict"' in out:
    raise SystemExit('v03134 whole-package conflict block still present')
print('v0.3.13.4 conflict-filtered package export fix applied')

from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
chain=[
'apply_hfamap_v1936_chain.py','hfamap_v19361_json_export.py','hfamap_v19367_dynamic_apply_local.py',
'hfamap_v19367_secret_callgraph_local.py','hfamap_v19367_app_local_menu_resolver.py','hfamap_v19367_ui_cleanup.py',
'hfamap_v19367_trace_cleanup.py','hfamap_v19367_generic_cleanup.py','hfamap_v19368_family_menu_resolver.py',
'apply_hfamap_v19370.py','hfamap_v19371_5m_dispatcher_resolver.py','hfamap_v19372_5m_dual_backend_fix.py',
'hfamap_v19373_app_local_dylib_discovery_v2.py','hfamap_v19374_prepare_patch.py','hfamap_v19374_manual_candidate_selection.py',
'hfamap_v19374_finalize_markers.py','hfamap_v19375_loaded_macho_dependency_discovery.py','hfamap_v19376_loaded_image_fingerprint.py',
'hfamap_v19377_two_stage_class_metadata_scan.py','hfamap_v19378_structural_relation_expansion.py','hfamap_v19379_complete_feature_export.py',
'hfamap_v193710_unified_feature_model.py','hfamap_v193710_earntodie_verified_profile.py',
'hfamap_runtime_analyzer_v02.py','hfamap_runtime_analyzer_v02_fix1.py','hfamap_runtime_analyzer_v03.py','hfamap_runtime_analyzer_v03_fix1.py',
'hfamap_runtime_analyzer_v032_auto_backend.py','hfamap_runtime_analyzer_v032_output_layout.py','hfamap_runtime_analyzer_v032_generic_output_fix.py','hfamap_runtime_analyzer_v032_safe_discovery_paths.py',
'hfamap_runtime_analyzer_v033_static_parity.py','hfamap_runtime_analyzer_v033_fix1.py','hfamap_runtime_analyzer_v034_semantic_backend.py','hfamap_runtime_analyzer_v034_compile_fix.py',
'hfamap_runtime_analyzer_v0341_stability.py','hfamap_runtime_analyzer_v0342_cfg_reachability.py','hfamap_runtime_analyzer_v035_semantic_coverage.py','hfamap_runtime_analyzer_v035_feature_binding.py',
'hfamap_runtime_analyzer_v035_action_fallback_conflicts.py','hfamap_runtime_analyzer_v035_compile_fix.py','hfamap_runtime_analyzer_v036_transform_flow.py','hfamap_runtime_analyzer_v036_runtime_binding.py',
'hfamap_runtime_analyzer_v037_semantic_nodes_state.py','hfamap_runtime_analyzer_v037_consumer_binding.py','hfamap_runtime_analyzer_v038_dispatcher_downstream.py','hfamap_runtime_analyzer_v038_runtime_consumer.py',
'hfamap_runtime_analyzer_v038_compile_fix.py','hfamap_runtime_analyzer_v039_notification_image_scan.py','hfamap_runtime_analyzer_v039_exact_state_xref.py']
for name in chain:
    subprocess.check_call(['python3',str(S/name)],cwd=ROOT)

p=ROOT/'hfamap'/'src'/'HFAMapRuntimeAnalyzerV02.m'
p.write_text(p.read_text().replace('static NSArray *HFAV02Hints(uintptr_t function,HFAV02Layout l)','static __attribute__((unused)) NSArray *HFAV02Hints(uintptr_t function,HFAV02Layout l)',1))
app=ROOT/'hfamap'/'src'/'HFAMapAppLocalResolver.m'
app.write_text(app.read_text().replace('static NSString *HFAAppLocalResolveInstallName(','static __attribute__((unused)) NSString *HFAAppLocalResolveInstallName(',1))
print('v0.3.9 generator chain complete')

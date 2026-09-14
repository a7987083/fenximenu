import subprocess

subprocess.run(['python3', '.github/scripts/apply_hfamap_v1936_chain.py'], check=True)
subprocess.run(['python3', '.github/scripts/hfamap_v1937_feature_v2_ui.py'], check=True)

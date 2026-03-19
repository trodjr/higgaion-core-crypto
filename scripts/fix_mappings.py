#!/usr/bin/env python3
import os
import re

target_dirs = ['verification/coq', 'verification/tla', 'verification/cbmc', 'verification/framac']

for d in target_dirs:
    if not os.path.exists(d): continue
    for root, _, files in os.walk(d):
        for f in files:
            if not f.endswith(('.v', '.tla', '.c', '.md')): continue
            path = os.path.join(root, f)
            with open(path, 'r') as file:
                content = file.read()
            
            # 1. Direct "Maps to: file" replacements
            new_content = re.sub(r'Maps to:\s+[a-zA-Z0-9_\-\./]+', r'Maps to: src/pqc_crypto.c', content)
            
            # 2. List items under "Maps to:" 
            # E.g., "- src/consensus.c: something" -> "- src/pqc_crypto.c"
            bad_files = ['consensus.c', 'utxo.c', 'shard_wal.c', 'pqc_migration.c', 'pqc_migration.h', 'INVARIANTS.md', 'PQC_MIGRATION_ENGINE_PROVISIONAL_PATENT.md']
            for bf in bad_files:
                new_content = re.sub(r'-\s+.*' + re.escape(bf) + r'.*', r'- src/pqc_crypto.c', new_content)
            
            if new_content != content:
                with open(path, 'w') as file:
                    file.write(new_content)
                print(f"Fixed {path}")

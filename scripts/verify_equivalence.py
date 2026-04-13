#!/usr/bin/env python3
import os
import re
import sys

def main():
    coq_dir = 'verification/coq'
    tla_dir = 'verification/tla'
    
    if not os.path.exists(coq_dir):
        print(f"Error: Directory {coq_dir} not found.")
        sys.exit(1)

    # Regex to find "Maps to:" and then extract file paths
    # Matches lines like: "   Maps to: pqc_migration.c" or "- src/pqc_crypto.c: "
    file_pattern = re.compile(r'(?:Maps to:[\s]*|-[\s]+)([a-zA-Z0-9_/-]+\.[a-z]+)')

    success = True
    print("Running Equivalence Map Verification...")

    for root_dir in [coq_dir, tla_dir]:
        if not os.path.exists(root_dir):
            continue
            
        for root, _, files in os.walk(root_dir):
            for file in files:
                if not file.endswith('.v') and not file.endswith('.tla'):
                    continue
                
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    content = f.read()

                # Find "Maps to:" blocks
                blocks = re.split(r'Maps to:', content, flags=re.IGNORECASE)
                if len(blocks) < 2:
                    continue
                
                print(f"Checking mappings in {filepath}...")
                for block in blocks[1:]:
                    # Read until end of comment block (* or ) or double newline
                    end_idx = block.find('*)')
                    if end_idx == -1:
                        end_idx = block.find('\n\n')
                    
                    if end_idx != -1:
                        block = block[:end_idx]
                        
                    for line in block.split('\n'):
                        match = file_pattern.search(line)
                        if match:
                            target_file = match.group(1)
                            
                            # Attempt to find the file from the root of the repo
                            if not os.path.exists(target_file):
                                # Sometimes it's just the basename
                                found = False
                                for search_root, _, search_files in os.walk('.'):
                                    if target_file in search_files:
                                        found = True
                                        break
                                if not found:
                                    print(f"  [ERROR] Coq/TLA maps to non-existent file: {target_file}")
                                    success = False
                                else:
                                    print(f"  [OK] Found mapped file (by basename): {target_file}")
                            else:
                                print(f"  [OK] Found mapped file: {target_file}")

    if not success:
        print("\nEQUIVALENCE MAP FAILURE: Proof models map to source execution artifacts that do not exist (HIG-006 violation).")
        sys.exit(1)
    else:
        print("\nEQUIVALENCE MAP SUCCESS: All proofs map to executable code.")
        sys.exit(0)

if __name__ == "__main__":
    current_dir = os.path.basename(os.getcwd())
    if current_dir != 'higgaion-core-crypto':
        print("Please run from the root of higgaion-core-crypto")
        sys.exit(1)
    main()

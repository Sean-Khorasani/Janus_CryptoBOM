#!/usr/bin/env python3
import os
import re
import sys
import urllib.parse

def get_paths():
    # The script is located in scripts/, so the project root is one level up.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    docs_dir = os.path.join(project_root, 'docs')
    
    files = {
        'README.md': os.path.join(project_root, 'README.md'),
        'docs/case_studies.md': os.path.join(docs_dir, 'case_studies.md'),
        'docs/design.md': os.path.join(docs_dir, 'design.md'),
        'docs/deployment.md': os.path.join(docs_dir, 'deployment.md')
    }
    return project_root, files

def check_tier_1(files):
    print("\n--- Running Tier 1: Documentation Completeness ---")
    passed = True
    for name, path in files.items():
        if os.path.exists(path):
            print(f"  [PASS] {name} exists.")
        else:
            print(f"  [FAIL] {name} is missing.")
            passed = False
    return passed

def check_tier_2(files):
    print("\n--- Running Tier 2: Content Validation ---")
    passed = True
    
    # 1. Check docs/case_studies.md (10 case studies)
    cs_path = files['docs/case_studies.md']
    if os.path.exists(cs_path):
        with open(cs_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Find headers starting with ## or more containing "Case Study"
        headers_matches = re.findall(r'^#{2,6}\s+.*Case Study.*', content, re.MULTILINE | re.IGNORECASE)
        # Also count occurrences of "Case Study X" (e.g. Case Study 1, Case Study 2...)
        unique_cs = set(re.findall(r'\bCase\s+Study\s+(\d+)\b', content, re.IGNORECASE))
        
        count = max(len(headers_matches), len(unique_cs))
        if count == 10:
            print(f"  [PASS] docs/case_studies.md contains exactly 10 case studies (found {count}).")
        else:
            print(f"  [FAIL] docs/case_studies.md must contain exactly 10 case studies (found {count}).")
            passed = False
    else:
        print("  [FAIL] docs/case_studies.md is missing, cannot validate case studies count.")
        passed = False
        
    # 2. Check docs/design.md (at least 5 Mermaid diagrams)
    design_path = files['docs/design.md']
    if os.path.exists(design_path):
        with open(design_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        mermaid_blocks = re.findall(r'```mermaid', content)
        count = len(mermaid_blocks)
        if count >= 5:
            print(f"  [PASS] docs/design.md contains {count} Mermaid diagrams (minimum 5).")
        else:
            print(f"  [FAIL] docs/design.md contains {count} Mermaid diagrams (minimum 5).")
            passed = False
    else:
        print("  [FAIL] docs/design.md is missing, cannot validate Mermaid diagrams count.")
        passed = False

    # 3. Check docs/deployment.md (environment variables definitions)
    dep_path = files['docs/deployment.md']
    if os.path.exists(dep_path):
        with open(dep_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        has_env_keyword = "environment variable" in content.lower() or "environment variables" in content.lower()
        env_vars = re.findall(r'\b[A-Z_][A-Z0-9_]{3,30}\b', content)
        
        # Filter typical false positives (like TCP, SSL, JVM, etc. unless they appear as variables)
        env_vars_filtered = [v for v in env_vars if v not in ('HTML', 'HTTPS', 'HTTP', 'JSON', 'REST', 'YAML', 'TOML', 'PQC', 'EST', 'ACME', 'CA', 'TPM', 'HSM', 'CNG', 'AST', 'DLL', 'SIEM', 'OSV', 'SPA', 'VITE')]
        
        if has_env_keyword or len(env_vars_filtered) > 0:
            print(f"  [PASS] docs/deployment.md contains environment variables definitions (found keywords or env vars).")
        else:
            print(f"  [FAIL] docs/deployment.md must contain environment variables definitions.")
            passed = False
    else:
        print("  [FAIL] docs/deployment.md is missing, cannot validate environment variables.")
        passed = False
        
    return passed

def check_tier_3(files, project_root):
    print("\n--- Running Tier 3: Link & Asset Integrity ---")
    passed = True
    
    # 1. Verify references to dashboard_preview_1780512832245.png and dashboard_preview_1780620392773.png
    ref_1 = False
    ref_2 = False
    
    for name, path in files.items():
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            if 'dashboard_preview_1780512832245.png' in content:
                ref_1 = True
            if 'dashboard_preview_1780620392773.png' in content:
                ref_2 = True
                
    if ref_1:
        print("  [PASS] Reference to dashboard_preview_1780512832245.png found.")
    else:
        print("  [FAIL] Reference to dashboard_preview_1780512832245.png is missing across all docs.")
        passed = False
        
    if ref_2:
        print("  [PASS] Reference to dashboard_preview_1780620392773.png found.")
    else:
        print("  [FAIL] Reference to dashboard_preview_1780620392773.png is missing across all docs.")
        passed = False
        
    # 2. Check for broken relative links & image assets
    for name, path in files.items():
        if not os.path.exists(path):
            continue
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        file_dir = os.path.dirname(path)
        
        # Find all markdown links [text](link) and images ![alt](link)
        links = re.findall(r'!?\[([^\]]*?)\]\(([^)]*?)\)', content)
        
        # Also find HTML image tag sources <img src="url">
        html_images = re.findall(r'<img\s+[^>]*?src=["\'\s]([^"\'\s>]+)["\'\s]', content)
        
        all_links = [l[1].strip() for l in links] + [img.strip() for img in html_images]
        
        for link in all_links:
            # Parse URL scheme
            parsed = urllib.parse.urlparse(link)
            
            # Skip remote URLs
            if parsed.scheme in ('http', 'https', 'mailto', 'ftp', 'git', 'tel'):
                continue
            
            # Skip pure anchors
            if link.startswith('#'):
                continue
            
            # Resolve file URLs
            if parsed.scheme == 'file':
                path_str = parsed.path
                # On Windows, parsed.path might start with /D:/...
                if path_str.startswith('/') and len(path_str) > 2 and path_str[2] == ':':
                    path_str = path_str[1:]
                resolved_path = os.path.abspath(path_str)
            else:
                # Remove anchor part
                target_path = link.split('#')[0]
                if not target_path:
                    continue
                # Decode URL
                target_path = urllib.parse.unquote(target_path)
                # Resolve path relative to current document
                resolved_path = os.path.abspath(os.path.join(file_dir, target_path))
            
            if os.path.exists(resolved_path):
                # File exists!
                pass
            else:
                print(f"  [FAIL] Broken relative link in {name}: '{link}' (Resolved path: {resolved_path} not found).")
                passed = False
                
    return passed

def check_tier_4(files):
    print("\n--- Running Tier 4: No Placeholders ---")
    passed = True
    
    placeholders = [
        (re.compile(r'\bTODO\b'), "TODO"),
        (re.compile(r'\bTBD\b'), "TBD"),
        (re.compile(r'\[placeholder\]', re.IGNORECASE), "[placeholder]"),
        (re.compile(r'\[tbd\]', re.IGNORECASE), "[TBD]"),
        (re.compile(r'\[insert.*?\]', re.IGNORECASE), "[insert ...]"),
        (re.compile(r'\[draft\]', re.IGNORECASE), "[draft]")
    ]
    
    for name, path in files.items():
        if not os.path.exists(path):
            continue
            
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            for pattern, label in placeholders:
                if pattern.search(line):
                    print(f"  [FAIL] Placeholder '{label}' found in {name} on line {line_num}: {line.strip()}")
                    passed = False
                    
    if passed:
        print("  [PASS] No placeholders found in any existing documentation files.")
        
    return passed

def main():
    project_root, files = get_paths()
    print(f"Starting documentation E2E validation. Root: {project_root}")
    
    t1 = check_tier_1(files)
    t2 = check_tier_2(files)
    t3 = check_tier_3(files, project_root)
    t4 = check_tier_4(files)
    
    print("\n--- Verification Summary ---")
    print(f"Tier 1 (Completeness): {'PASSED' if t1 else 'FAILED'}")
    print(f"Tier 2 (Content):      {'PASSED' if t2 else 'FAILED'}")
    print(f"Tier 3 (Integrity):    {'PASSED' if t3 else 'FAILED'}")
    print(f"Tier 4 (Placeholders): {'PASSED' if t4 else 'FAILED'}")
    
    if t1 and t2 and t3 and t4:
        print("\nSUCCESS: All documentation verification tiers passed!")
        sys.exit(0)
    else:
        print("\nFAILURE: One or more verification tiers failed.")
        sys.exit(1)

if __name__ == '__main__':
    main()

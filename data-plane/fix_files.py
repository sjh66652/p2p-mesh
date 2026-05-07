#!/usr/bin/env python3
"""Fix truncated files in the build directory by writing proper content."""
import os

BUILD = '/tmp/p2p-build/src'

# File contents as dictionaries — each keyed by relative path
files = {}

# crypto/noise.rs (627 lines) — from Read tool
files['crypto/noise.rs'] = open(r'\\?\\C:\\Users\\baiduren\\Desktop\\p2p-mesh\\data-plane\\src\\crypto\\noise.rs').read()

# Write each file that needs fixing
for relpath in files:
    path = os.path.join(BUILD, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(files[relpath])
    print(f"Fixed: {relpath} ({len(files[relpath])} bytes)")

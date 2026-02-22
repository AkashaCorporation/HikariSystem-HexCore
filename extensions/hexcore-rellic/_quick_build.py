#!/usr/bin/env python3
"""
Quick build for hexcore-rellic (stub mode — LLVM only, no Clang/Z3).

This script does the minimum needed to build and test the .node addon
with the stub Rellic pipeline (no real decompilation, just pseudo-C
skeleton generation from LLVM IR).

Steps:
  1. Copy deps/llvm/ from hexcore-remill (reuse existing /MT libs)
  2. Run node-gyp rebuild
  3. Run npm test (smoke tests)

Usage:
    python _quick_build.py                          # full quick build
    python _quick_build.py --remill-deps <path>     # custom remill deps
    python _quick_build.py --step copy              # only copy deps
    python _quick_build.py --step build             # only node-gyp
    python _quick_build.py --step test              # only test

Prerequisites:
    - VS2022 Developer Command Prompt (vcvarsall x64)
    - Node.js 18+ with node-gyp
    - hexcore-remill deps already built (for LLVM libs)

Copyright (c) HikariSystem. All rights reserved.
Licensed under MIT License.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DEPS_DIR = SCRIPT_DIR / 'deps'
DEFAULT_REMILL_DEPS = SCRIPT_DIR.parent / 'hexcore-remill' / 'deps'


def run(cmd, cwd=None, check=True):
    print(f"\n{'=' * 60}")
    print(f"CMD: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    print(f"CWD: {cwd or os.getcwd()}")
    print(f"{'=' * 60}")
    r = subprocess.run(cmd, cwd=cwd)
    if check and r.returncode != 0:
        print(f"FAILED with exit code {r.returncode}")
        sys.exit(r.returncode)
    return r.returncode


def copy_llvm(remill_deps):
    """Copy LLVM headers + libs from hexcore-remill."""
    print("\n>>> COPYING LLVM DEPS FROM REMILL <<<\n")

    src = Path(remill_deps) / 'llvm'
    dst = DEPS_DIR / 'llvm'

    if not src.exists():
        print(f"  ERROR: {src} not found")
        print(f"  Make sure hexcore-remill deps are built.")
        sys.exit(1)

    # Check if already copied
    dst_lib = dst / 'lib'
    if dst_lib.exists():
        existing = list(dst_lib.glob('*.lib'))
        if len(existing) > 50:
            print(f"  LLVM deps already present ({len(existing)} libs)")
            print(f"  Skipping copy. Delete deps/llvm/ to force re-copy.")
            return

    # Copy include
    dst_inc = dst / 'include'
    if dst_inc.exists():
        shutil.rmtree(dst_inc)
    print(f"  Copying headers...")
    shutil.copytree(str(src / 'include'), str(dst_inc))

    # Copy lib
    if dst_lib.exists():
        shutil.rmtree(dst_lib)
    print(f"  Copying libs...")
    shutil.copytree(str(src / 'lib'), str(dst_lib))

    libs = list(dst_lib.glob('*.lib'))
    total_mb = sum(f.stat().st_size for f in libs) / (1024 * 1024)
    print(f"  Copied {len(libs)} LLVM libs ({total_mb:.0f} MB)")


def find_node_gyp():
    """Find node-gyp executable, trying multiple strategies."""
    # Strategy 1: node-gyp directly in PATH
    for cmd in [['node-gyp', '--version'], ['npx', 'node-gyp', '--version']]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(SCRIPT_DIR))
            if r.returncode == 0:
                print(f"  Found: {' '.join(cmd[:-1])} ({r.stdout.strip()})")
                return cmd[:-1]  # remove --version
        except FileNotFoundError:
            continue

    # Strategy 2: Find node.exe and use it to run node-gyp
    node_candidates = [
        Path(os.environ.get('PROGRAMFILES', '')) / 'nodejs' / 'node.exe',
        Path(os.environ.get('APPDATA', '')) / 'nvm' / 'current' / 'node.exe',
        Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs' / 'nodejs' / 'node.exe',
        Path(r'C:\Program Files\nodejs\node.exe'),
    ]
    for node_exe in node_candidates:
        if node_exe.exists():
            # Try npx via full path
            npx_exe = node_exe.parent / 'npx.cmd'
            if npx_exe.exists():
                try:
                    r = subprocess.run(
                        [str(npx_exe), 'node-gyp', '--version'],
                        capture_output=True, text=True, cwd=str(SCRIPT_DIR))
                    if r.returncode == 0:
                        print(f"  Found: {npx_exe} ({r.stdout.strip()})")
                        return [str(npx_exe), 'node-gyp']
                except FileNotFoundError:
                    pass

            # Try node-gyp.cmd via full path
            node_gyp_cmd = node_exe.parent / 'node_modules' / '.bin' / 'node-gyp.cmd'
            if not node_gyp_cmd.exists():
                node_gyp_cmd = node_exe.parent / 'node-gyp.cmd'
            if node_gyp_cmd.exists():
                print(f"  Found: {node_gyp_cmd}")
                return [str(node_gyp_cmd)]

    return None


def build():
    """Run node-gyp rebuild."""
    print("\n>>> NODE-GYP REBUILD <<<\n")

    # Verify deps exist
    llvm_lib = DEPS_DIR / 'llvm' / 'lib' / 'LLVMCore.lib'
    if not llvm_lib.exists():
        print(f"  ERROR: {llvm_lib} not found")
        print(f"  Run: python _quick_build.py --step copy")
        sys.exit(1)

    # Find node-gyp
    gyp_cmd = find_node_gyp()
    if not gyp_cmd:
        print("  ERROR: node-gyp not found!")
        print("  Make sure Node.js is in your PATH.")
        print("  Try running from a regular terminal (not VS Developer Prompt):")
        print("    npx node-gyp rebuild")
        print("")
        print("  Or add Node.js to PATH in VS Developer Prompt:")
        print('    set PATH=C:\\Program Files\\nodejs;%PATH%')
        print("  Then retry.")
        sys.exit(1)

    run(gyp_cmd + ['rebuild'], cwd=str(SCRIPT_DIR))

    # Verify output
    node_file = SCRIPT_DIR / 'build' / 'Release' / 'hexcore_rellic.node'
    if node_file.exists():
        size_mb = node_file.stat().st_size / (1024 * 1024)
        print(f"\n  SUCCESS: {node_file.name} ({size_mb:.1f} MB)")
    else:
        print(f"\n  ERROR: .node not found!")
        sys.exit(1)


def find_node():
    """Find node.exe, trying multiple strategies."""
    # Strategy 1: node directly in PATH
    try:
        r = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if r.returncode == 0:
            print(f"  Found: node ({r.stdout.strip()})")
            return 'node'
    except FileNotFoundError:
        pass

    # Strategy 2: Common install locations
    candidates = [
        Path(r'C:\Program Files\nodejs\node.exe'),
        Path(os.environ.get('PROGRAMFILES', '')) / 'nodejs' / 'node.exe',
        Path(os.environ.get('APPDATA', '')) / 'nvm' / 'current' / 'node.exe',
        Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs' / 'nodejs' / 'node.exe',
    ]
    for node_exe in candidates:
        if node_exe.exists():
            try:
                r = subprocess.run([str(node_exe), '--version'],
                                   capture_output=True, text=True)
                if r.returncode == 0:
                    print(f"  Found: {node_exe} ({r.stdout.strip()})")
                    return str(node_exe)
            except FileNotFoundError:
                continue

    return None


def test():
    """Run smoke tests."""
    print("\n>>> SMOKE TESTS <<<\n")

    node_cmd = find_node()
    if not node_cmd:
        print("  ERROR: node.exe not found!")
        print("  Add Node.js to PATH:")
        print('    set PATH=C:\\Program Files\\nodejs;%PATH%')
        sys.exit(1)

    run([node_cmd, 'test/test.js'], cwd=str(SCRIPT_DIR))


def main():
    parser = argparse.ArgumentParser(
        description='Quick build for hexcore-rellic (stub mode)')
    parser.add_argument('--remill-deps', type=str,
                        default=str(DEFAULT_REMILL_DEPS),
                        help=f'Path to hexcore-remill deps/ (default: {DEFAULT_REMILL_DEPS})')
    parser.add_argument('--step', choices=['copy', 'build', 'test'],
                        help='Run a single step')
    args = parser.parse_args()

    os.chdir(SCRIPT_DIR)

    if args.step == 'copy':
        copy_llvm(args.remill_deps)
        return
    if args.step == 'build':
        build()
        return
    if args.step == 'test':
        test()
        return

    # Full pipeline
    print('=' * 60)
    print('  HEXCORE-RELLIC QUICK BUILD (STUB MODE)')
    print('  1. Copy LLVM deps from hexcore-remill')
    print('  2. node-gyp rebuild')
    print('  3. Smoke tests')
    print('=' * 60)

    copy_llvm(args.remill_deps)
    build()
    test()

    print('\n' + '=' * 60)
    print('  BUILD OK!')
    print('')
    print('  Test in dev mode:')
    print('    .\\scripts\\code.bat')
    print('')
    print('  When ready for release:')
    print('    python _rebuild_all.py  (full build with Clang+Z3)')
    print('=' * 60)


if __name__ == '__main__':
    main()

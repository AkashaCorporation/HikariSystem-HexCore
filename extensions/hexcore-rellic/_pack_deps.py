#!/usr/bin/env python3
"""
Pack rellic deps into a zip for GitHub Release.

This creates a deps archive that the CI workflow downloads before
running prebuildify. The archive contains:
  - deps/llvm/lib/*.lib          (LLVM 18 libs)
  - deps/llvm/include/           (LLVM 18 headers)
  - deps/clang/lib/*.lib         (Clang 18 libs)
  - deps/clang/include/          (Clang 18 headers)
  - deps/z3/lib/*.lib            (Z3 lib)
  - deps/z3/include/             (Z3 headers)
  - deps/rellic/lib/*.lib        (Rellic lib)
  - deps/rellic/include/         (Rellic headers)

Usage:
  python _pack_deps.py                    # creates rellic-deps-win32-x64.zip
  python _pack_deps.py --output my.zip    # custom output name

Upload the resulting zip as a release asset to:
  https://github.com/LXrdKnowkill/hexcore-rellic/releases

Copyright (c) HikariSystem. All rights reserved.
"""
import os, sys, zipfile, argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEPS_DIR = os.path.join(SCRIPT_DIR, "deps")
DEFAULT_OUTPUT = "rellic-deps-win32-x64.zip"


def pack_deps(output_path):
    if not os.path.isdir(DEPS_DIR):
        print(f"ERROR: deps/ directory not found at {DEPS_DIR}")
        sys.exit(1)

    total_files = 0
    total_bytes = 0

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED,
                         compresslevel=6) as zf:
        for root, dirs, files in os.walk(DEPS_DIR):
            for f in files:
                fpath = os.path.join(root, f)
                # Include: .lib, .a, .h, .hpp, .hh, .inc, .def, .td, .gen
                ext = os.path.splitext(f)[1].lower()
                if ext in ('.lib', '.a', '.h', '.hpp', '.hh', '.inc',
                           '.def', '.td', '.gen', '.modulemap'):
                    arcname = os.path.relpath(fpath, SCRIPT_DIR)
                    zf.write(fpath, arcname)
                    size = os.path.getsize(fpath)
                    total_files += 1
                    total_bytes += size

    mb = total_bytes / (1024 * 1024)
    zip_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"Packed {total_files} files ({mb:.1f} MB) -> {output_path} ({zip_mb:.1f} MB)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pack rellic deps for CI")
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT,
                        help=f"Output zip path (default: {DEFAULT_OUTPUT})")
    args = parser.parse_args()
    pack_deps(args.output)

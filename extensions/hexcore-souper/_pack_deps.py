#!/usr/bin/env python3
"""
Pack souper deps into a zip for GitHub Release.

Creates souper-deps-win32-x64.zip containing:
  - deps/souper/lib/*.lib       (Souper static libs)
  - deps/souper/include/        (Souper headers)
  - deps/alive2/lib/*.lib       (Alive2 libs)
  - deps/alive2/include/        (Alive2 headers)
  - deps/klee/include/          (KLEE headers)
  - deps/llvm/lib/*.lib         (LLVM 18 libs)
  - deps/llvm/include/          (LLVM headers)
  - deps/z3/lib/*.lib           (Z3 lib)
  - deps/z3/include/            (Z3 headers)
  - deps/z3/libz3.dll           (Z3 runtime DLL)

Usage:
  python _pack_deps.py
  python _pack_deps.py --output my.zip
"""
import os, sys, zipfile, argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEPS_DIR = os.path.join(SCRIPT_DIR, "deps")
DEFAULT_OUTPUT = "souper-deps-win32-x64.zip"


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
                ext = os.path.splitext(f)[1].lower()
                # Include: libs, headers, DLLs
                if ext in ('.lib', '.h', '.hpp', '.hh', '.inc', '.def',
                           '.td', '.gen', '.modulemap', '.dll'):
                    arcname = os.path.relpath(fpath, SCRIPT_DIR)
                    zf.write(fpath, arcname)
                    size = os.path.getsize(fpath)
                    total_files += 1
                    total_bytes += size

    mb = total_bytes / (1024 * 1024)
    zip_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"Packed {total_files} files ({mb:.1f} MB) -> {output_path} ({zip_mb:.1f} MB)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pack souper deps for CI")
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    pack_deps(args.output)

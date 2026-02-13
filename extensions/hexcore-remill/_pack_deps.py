#!/usr/bin/env python3
"""
Pack remill deps into a zip for GitHub Release.

This creates a deps archive that the CI workflow downloads before
running prebuildify. The archive contains:
  - deps/remill/lib/*.lib        (12 remill/sleigh libs)
  - deps/remill/include/         (remill headers)
  - deps/remill/share/semantics/ (.bc bitcode files)
  - deps/llvm/lib/*.lib          (152 LLVM libs)
  - deps/llvm/include/           (LLVM headers)
  - deps/xed/lib/*.lib           (XED libs)
  - deps/xed/include/            (XED headers)
  - deps/glog/lib/*.lib          (glog lib)
  - deps/glog/include/           (glog headers)
  - deps/gflags/lib/*.lib        (gflags lib)
  - deps/gflags/include/         (gflags headers)

Usage:
  python _pack_deps.py                    # creates remill-deps-win32-x64.zip
  python _pack_deps.py --output my.zip    # custom output name
"""
import os, sys, zipfile, argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEPS_DIR = os.path.join(SCRIPT_DIR, "deps")
DEFAULT_OUTPUT = "remill-deps-win32-x64.zip"


def pack_deps(output_path):
    if not os.path.isdir(DEPS_DIR):
        print(f"ERROR: deps/ directory not found at {DEPS_DIR}")
        sys.exit(1)

    total_files = 0
    total_bytes = 0

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED,
                         compresslevel=6) as zf:
        for root, dirs, files in os.walk(DEPS_DIR):
            # Skip README and other non-essential files at deps root
            for f in files:
                fpath = os.path.join(root, f)
                # Include: .lib, .h, .hpp, .hh, .inc, .def, .td, .bc, .gen
                ext = os.path.splitext(f)[1].lower()
                if ext in ('.lib', '.h', '.hpp', '.hh', '.inc', '.def',
                           '.td', '.bc', '.gen', '.modulemap'):
                    arcname = os.path.relpath(fpath, SCRIPT_DIR)
                    zf.write(fpath, arcname)
                    size = os.path.getsize(fpath)
                    total_files += 1
                    total_bytes += size

    mb = total_bytes / (1024 * 1024)
    zip_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"Packed {total_files} files ({mb:.1f} MB) -> {output_path} ({zip_mb:.1f} MB)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pack remill deps for CI")
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT,
                        help=f"Output zip path (default: {DEFAULT_OUTPUT})")
    args = parser.parse_args()
    pack_deps(args.output)

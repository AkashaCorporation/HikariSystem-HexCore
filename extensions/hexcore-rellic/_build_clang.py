#!/usr/bin/env python3
"""
Build Clang 18.1.8 static libraries for hexcore-rellic.

Usage:
    python _build_clang.py [--llvm-src C:\\llvm-project-18.1.8]

Prerequisites:
    - VS2022 with MSVC 14.44 toolset
    - LLVM/Clang 21 as host compiler (clang-cl in PATH)
    - CMake 3.21+ and Ninja in PATH
    - Run from VS Developer Command Prompt:
      vcvarsall.bat x64 -vcvars_ver=14.44

This script builds only the Clang libraries needed by Rellic:
    clangAST, clangBasic, clangLex, clangSema, clangFrontend,
    clangSerialization, clangDriver, clangParse, clangEdit, clangAnalysis

Copyright (c) HikariSystem. All rights reserved.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

CLANG_LIBS = [
    'clangAST',
    'clangBasic',
    'clangLex',
    'clangSema',
    'clangFrontend',
    'clangSerialization',
    'clangDriver',
    'clangParse',
    'clangEdit',
    'clangAnalysis',
]

def main():
    parser = argparse.ArgumentParser(description='Build Clang 18.1.8 static libs')
    parser.add_argument('--llvm-src', required=True, help='Path to llvm-project-18.1.8 source')
    parser.add_argument('--llvm-build', help='Path to existing LLVM 18 build dir (for LLVM_DIR)')
    parser.add_argument('--output', default='deps/clang', help='Output directory')
    args = parser.parse_args()

    llvm_src = Path(args.llvm_src)
    clang_src = llvm_src / 'clang'
    if not clang_src.exists():
        print(f'ERROR: Clang source not found at {clang_src}')
        sys.exit(1)

    build_dir = Path('clang-build')
    install_dir = Path('clang-install')
    output_dir = Path(args.output)

    # Configure
    cmake_args = [
        'cmake', '-G', 'Ninja',
        '-S', str(clang_src),
        '-B', str(build_dir),
        '-DCMAKE_C_COMPILER=clang-cl',
        '-DCMAKE_CXX_COMPILER=clang-cl',
        '-DCMAKE_BUILD_TYPE=Release',
        '-DBUILD_SHARED_LIBS=OFF',
        f'-DCMAKE_INSTALL_PREFIX={install_dir}',
    ]
    if args.llvm_build:
        cmake_args.append(f'-DLLVM_DIR={args.llvm_build}/lib/cmake/llvm')

    print(f'Configuring Clang build...')
    subprocess.check_call(cmake_args)

    # Build only needed targets
    print(f'Building Clang libraries: {", ".join(CLANG_LIBS)}')
    build_args = ['cmake', '--build', str(build_dir), '--target'] + CLANG_LIBS
    subprocess.check_call(build_args)

    # Copy to output
    output_dir.mkdir(parents=True, exist_ok=True)
    include_dst = output_dir / 'include'
    lib_dst = output_dir / 'lib'

    if include_dst.exists():
        shutil.rmtree(include_dst)
    if lib_dst.exists():
        shutil.rmtree(lib_dst)

    # Copy headers
    shutil.copytree(clang_src / 'include', include_dst)
    # Also copy generated headers from build dir
    gen_include = build_dir / 'include'
    if gen_include.exists():
        shutil.copytree(gen_include, include_dst, dirs_exist_ok=True)

    # Copy libs
    lib_dst.mkdir(parents=True, exist_ok=True)
    lib_dir = build_dir / 'lib'
    for lib_name in CLANG_LIBS:
        for ext in ['.lib', '.a']:
            lib_file = lib_dir / f'{lib_name}{ext}'
            if lib_file.exists():
                shutil.copy2(lib_file, lib_dst)
                print(f'  Copied {lib_file.name}')

    print(f'\nClang libs installed to {output_dir}')

if __name__ == '__main__':
    main()

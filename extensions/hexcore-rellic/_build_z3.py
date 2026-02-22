#!/usr/bin/env python3
"""
Download and install Z3 4.13.4 pre-built static library for hexcore-rellic.

Z3 distributes pre-built packages on GitHub Releases. This script downloads
the Windows x64 build, extracts the headers and static lib, and installs
them to deps/z3/.

Usage:
    python _build_z3.py                     # download + install
    python _build_z3.py --verify            # only verify installed files
    python _build_z3.py --from-zip z3.zip   # install from local zip

Prerequisites:
    - Internet access (for download) OR a local zip file
    - Python 3.8+

The Z3 release used is 4.13.4 (latest stable as of 2025).
If you need a different version, use --version.

Copyright (c) HikariSystem. All rights reserved.
Licensed under MIT License.
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DEPS_DIR = SCRIPT_DIR / 'deps'

# Z3 release info
Z3_VERSION = '4.13.4'
Z3_REPO = 'Z3Prover/z3'

IS_WINDOWS = platform.system() == 'Windows'


def get_z3_url(version):
    """Build the download URL for Z3 pre-built package."""
    if IS_WINDOWS:
        # Z3 Windows releases: z3-{version}-x64-win.zip
        filename = f'z3-{version}-x64-win.zip'
    else:
        filename = f'z3-{version}-x64-glibc-2.35.zip'

    url = f'https://github.com/{Z3_REPO}/releases/download/z3-{version}/{filename}'
    return url, filename


def download_z3(version, output_dir):
    """Download Z3 pre-built package from GitHub Releases."""
    url, filename = get_z3_url(version)
    output_path = output_dir / filename

    if output_path.exists():
        print(f'  Already downloaded: {output_path}')
        return output_path

    print(f'  Downloading Z3 {version}...')
    print(f'  URL: {url}')

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        urllib.request.urlretrieve(url, str(output_path))
        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f'  Downloaded: {output_path} ({size_mb:.1f} MB)')
        return output_path
    except Exception as e:
        print(f'  ERROR: Download failed: {e}')
        print(f'  Try downloading manually from:')
        print(f'    {url}')
        print(f'  Then run: python _build_z3.py --from-zip {filename}')
        sys.exit(1)


def install_z3(zip_path):
    """Extract Z3 headers and lib from the downloaded zip."""
    print(f'\n>>> INSTALLING Z3 FROM {zip_path} <<<\n')

    output_dir = DEPS_DIR / 'z3'
    include_dst = output_dir / 'include'
    lib_dst = output_dir / 'lib'

    # Clean previous install
    if include_dst.exists():
        shutil.rmtree(include_dst)
    if lib_dst.exists():
        shutil.rmtree(lib_dst)

    include_dst.mkdir(parents=True, exist_ok=True)
    lib_dst.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(str(zip_path), 'r') as zf:
        # Find the root directory inside the zip (e.g. "z3-4.13.4-x64-win/")
        names = zf.namelist()
        root_prefix = names[0].split('/')[0] + '/'

        # Extract headers
        header_count = 0
        for name in names:
            rel = name[len(root_prefix):] if name.startswith(root_prefix) else name
            if rel.startswith('include/') and not rel.endswith('/'):
                # Strip the "include/" prefix
                header_rel = rel[len('include/'):]
                dst = include_dst / header_rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(name) as src, open(str(dst), 'wb') as f:
                    f.write(src.read())
                header_count += 1

        print(f'  Headers: {header_count} files -> {include_dst}')

        # Extract libraries
        lib_count = 0
        for name in names:
            rel = name[len(root_prefix):] if name.startswith(root_prefix) else name
            basename = os.path.basename(rel)

            # Look for static lib
            if basename in ('libz3.lib', 'z3.lib', 'libz3.a'):
                dst = lib_dst / 'libz3.lib' if IS_WINDOWS else lib_dst / 'libz3.a'
                with zf.open(name) as src, open(str(dst), 'wb') as f:
                    f.write(src.read())
                size_kb = dst.stat().st_size / 1024
                print(f'  Library: {basename} -> {dst.name} ({size_kb:.1f} KB)')
                lib_count += 1

            # Also grab the DLL if present (for reference, not used in static build)
            if basename in ('libz3.dll', 'z3.dll'):
                dst = lib_dst / basename
                with zf.open(name) as src, open(str(dst), 'wb') as f:
                    f.write(src.read())
                print(f'  DLL (reference): {basename}')

        if lib_count == 0:
            # Z3 pre-built might only have DLL, not static lib
            # In that case we need the .lib import library
            for name in names:
                basename = os.path.basename(name)
                if basename.endswith('.lib') and 'z3' in basename.lower():
                    dst = lib_dst / 'libz3.lib'
                    with zf.open(name) as src, open(str(dst), 'wb') as f:
                        f.write(src.read())
                    size_kb = dst.stat().st_size / 1024
                    print(f'  Library: {basename} -> libz3.lib ({size_kb:.1f} KB)')
                    lib_count += 1
                    break

        if lib_count == 0:
            print('  WARNING: No Z3 static library found in zip!')
            print('  Available files:')
            for name in names:
                if name.endswith(('.lib', '.a', '.dll', '.so', '.dylib')):
                    print(f'    {name}')

    print(f'\n  Z3 installed to {output_dir}')
    return output_dir


def verify_z3():
    """Verify Z3 installation."""
    print('\n>>> VERIFYING Z3 INSTALLATION <<<\n')

    output_dir = DEPS_DIR / 'z3'
    ok = True

    # Check headers
    z3_h = output_dir / 'include' / 'z3.h'
    z3pp_h = output_dir / 'include' / 'z3++.h'

    if z3_h.exists():
        print(f'  z3.h: OK')
    else:
        print(f'  z3.h: MISSING')
        ok = False

    if z3pp_h.exists():
        print(f'  z3++.h: OK')
    else:
        print(f'  z3++.h: MISSING (optional for C++ API)')

    # Check library
    if IS_WINDOWS:
        lib_path = output_dir / 'lib' / 'libz3.lib'
    else:
        lib_path = output_dir / 'lib' / 'libz3.a'

    if lib_path.exists():
        size_mb = lib_path.stat().st_size / (1024 * 1024)
        print(f'  {lib_path.name}: OK ({size_mb:.1f} MB)')
    else:
        print(f'  {lib_path.name}: MISSING')
        ok = False

    # Check CRT on Windows
    if IS_WINDOWS and lib_path.exists():
        try:
            r = subprocess.run(
                ['dumpbin', '/directives', str(lib_path)],
                capture_output=True, text=True)
            defaults = set()
            for line in r.stdout.split('\n'):
                if '/DEFAULTLIB:' in line:
                    val = line.strip().split('/DEFAULTLIB:')[1].strip().strip('"')
                    defaults.add(val.lower())

            if 'libcmt' in defaults or 'libcmt.lib' in defaults:
                crt = 'MT'
            elif 'msvcrt' in defaults or 'msvcrt.lib' in defaults:
                crt = 'MD'
            else:
                crt = '???'

            print(f'  CRT: {crt}  ({", ".join(sorted(defaults))})')

            if crt == 'MD':
                print('  NOTE: Z3 pre-built uses /MD (dynamic CRT).')
                print('  This MAY cause CRT mismatch with LLVM/Clang (/MT).')
                print('  If linking fails, you may need to build Z3 from source with /MT.')
                print('  For now, try linking anyway — node-gyp may handle it.')
        except FileNotFoundError:
            print('  CRT check: dumpbin not found (run from VS Developer Prompt)')

    if ok:
        print('\n  Z3 installation: OK')
    else:
        print('\n  Z3 installation: INCOMPLETE')

    return ok


def main():
    parser = argparse.ArgumentParser(
        description='Download and install Z3 for hexcore-rellic')
    parser.add_argument('--version', default=Z3_VERSION,
                        help=f'Z3 version (default: {Z3_VERSION})')
    parser.add_argument('--from-zip', type=str,
                        help='Install from local zip file instead of downloading')
    parser.add_argument('--verify', action='store_true',
                        help='Only verify installed Z3')
    parser.add_argument('--download-only', action='store_true',
                        help='Only download, do not install')
    args = parser.parse_args()

    os.chdir(SCRIPT_DIR)

    if args.verify:
        ok = verify_z3()
        sys.exit(0 if ok else 1)

    if args.from_zip:
        zip_path = Path(args.from_zip)
        if not zip_path.exists():
            print(f'ERROR: {zip_path} not found')
            sys.exit(1)
        install_z3(zip_path)
        verify_z3()
        return

    # Download
    print('=' * 60)
    print(f'  Z3 {args.version} DOWNLOAD + INSTALL')
    print('=' * 60)

    tmp_dir = SCRIPT_DIR / 'z3-download'
    zip_path = download_z3(args.version, tmp_dir)

    if args.download_only:
        print(f'\nDownloaded to: {zip_path}')
        return

    # Install
    install_z3(zip_path)

    # Verify
    verify_z3()

    # Cleanup
    print(f'\nZ3 zip kept at: {zip_path}')
    print('Delete it manually if you want to save space.')

    print('\n' + '=' * 60)
    print('  Z3 READY!')
    print('  Next: python _build_clang.py (if not done)')
    print('        python _build_rellic.py')
    print('        npx node-gyp rebuild')
    print('=' * 60)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Copy hexcore-souper source files to the standalone repo directory.

Excludes: deps/, build/, node_modules/, _*.py scripts.

Usage:
  python _copy_to_standalone.py
  python _copy_to_standalone.py --target C:\path\to\standalone
"""
import os, shutil, argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TARGET = r"C:\Users\Mazum\Desktop\StandalonePackagesHexCore\hexcore-souper"

EXCLUDE_DIRS = {"deps", "build", "build-win", "node_modules", ".git", "prebuilds"}
EXCLUDE_FILES = {
    "_rebuild_mt.py",
    "_write_gyp.py",
    "_pack_deps.py",
    "_copy_to_standalone.py",
}


def copy_to_standalone(target):
    if not os.path.isdir(target):
        os.makedirs(target, exist_ok=True)

    copied = 0
    for root, dirs, files in os.walk(SCRIPT_DIR):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f in EXCLUDE_FILES:
                continue
            src = os.path.join(root, f)
            rel = os.path.relpath(src, SCRIPT_DIR)
            dst = os.path.join(target, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            print(f"  {rel}")
            copied += 1

    # Create deps/README.md
    deps_readme = os.path.join(target, "deps", "README.md")
    os.makedirs(os.path.dirname(deps_readme), exist_ok=True)
    with open(deps_readme, "w", encoding="utf-8") as f:
        f.write("""# Dependencies

Download deps from the GitHub Release:
```powershell
gh release download v0.1.0 -p "souper-deps-win32-x64.zip" -R AkashaCorporation/hexcore-souper
Expand-Archive souper-deps-win32-x64.zip -DestinationPath . -Force
```
""")
    copied += 1

    print(f"\n{copied} files copied to {target}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET)
    args = parser.parse_args()
    copy_to_standalone(args.target)

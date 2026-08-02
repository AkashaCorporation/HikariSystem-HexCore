#!/usr/bin/env python3
"""
Copy hexcore-remill source files to the standalone repo directory.

Copies everything needed for the standalone npm package, excluding:
  - deps/          (too large, distributed as release asset)
  - build/         (compiled output)
  - node_modules/  (npm install)
  - Logs.txt       (dev logs)
  - _rebuild_mt.py (internal build script)
  - _write_gyp.py  (internal build script)
  - _pack_deps.py  (internal build script)
  - _copy_to_standalone.py (this script)

Usage:
  python _copy_to_standalone.py
  python _copy_to_standalone.py --target C:\path\to\standalone
"""
import os, sys, shutil, argparse, json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TARGET = r"C:\Users\Mazum\Desktop\StandalonePackagesHexCore\hexcore-remill"

EXCLUDE_DIRS = {"deps", "build", "node_modules", ".git", "__pycache__"}
EXCLUDE_FILES = {
    "Logs.txt",
    "_rebuild_mt.py",
    "_write_gyp.py",
    "_pack_deps.py",
    "_copy_to_standalone.py",
    "shared_buffer_poc.ts",
    "package-lock.json",
}


def copy_to_standalone(target):
    if not os.path.isdir(target):
        os.makedirs(target, exist_ok=True)
        print(f"Created {target}")

    copied = 0
    for root, dirs, files in os.walk(SCRIPT_DIR):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for f in files:
            if f in EXCLUDE_FILES or f.lower().endswith((".log", ".zip")):
                continue

            src = os.path.join(root, f)
            rel = os.path.relpath(src, SCRIPT_DIR)
            if rel.startswith("prebuilds" + os.sep) and f != "hexcore_remill.node":
                continue
            dst = os.path.join(target, rel)

            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            print(f"  {rel}")
            copied += 1

    package_path = os.path.join(target, "package.json")
    with open(package_path, "r", encoding="utf-8") as f:
        standalone_package = json.load(f)
    standalone_package["scripts"]["install"] = (
        "prebuild-install -r napi || node-gyp rebuild")
    standalone_package["devDependencies"] = {
        "node-addon-api": "^8.0.0",
        "node-gyp": "^12.4.0",
        "prebuild-install": "^7.1.0",
        "prebuildify": "^6.0.0",
    }
    with open(package_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(standalone_package, f, indent=2, ensure_ascii=False)
        f.write("\n")
    package_version = standalone_package["version"]

    # Also create a deps/README.md explaining how to get deps
    deps_readme = os.path.join(target, "deps", "README.md")
    os.makedirs(os.path.dirname(deps_readme), exist_ok=True)
    with open(deps_readme, "w", encoding="utf-8") as f:
        f.write(f"""# Dependencies

This directory should contain the pre-compiled native dependencies.

## For CI (GitHub Actions)
Dependencies are automatically downloaded from the GitHub Release
asset `remill-deps-win32-x64.zip` during the prebuild workflow.

## For local development
Run the full rebuild pipeline from the monorepo:
```powershell
cd extensions/hexcore-remill
python _rebuild_mt.py
```

Or download the deps zip from the latest release:
```powershell
gh release download v{package_version} -p "remill-deps-win32-x64.zip" -R AkashaCorporation/hexcore-remill
Expand-Archive remill-deps-win32-x64.zip -DestinationPath .
```
""")
    copied += 1
    print(f"  deps/README.md (generated)")

    print(f"\n{copied} files copied to {target}")
    print(f"\nNext steps:")
    print(f"  1. cd {target}")
    print(f"  2. npm install")
    print(f"  3. Review the standalone diff and tests before staging anything")
    print(f"  4. Pack deps: cd <monorepo>/extensions/hexcore-remill && python _pack_deps.py")
    print(f"  5. Upload the reviewed deps archive with release v{package_version}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Copy to standalone repo")
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET,
                        help=f"Target directory (default: {DEFAULT_TARGET})")
    args = parser.parse_args()
    copy_to_standalone(args.target)

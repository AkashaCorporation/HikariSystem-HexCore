# HexCore Windows Local Build (Quick Guide)

This guide is for building HexCore on a Windows PC with the provided script.

## Prereqs
- Node.js `22.21.1` (matches `.nvmrc`)
- npm 10+
- Python `3.11`
- Visual Studio 2022 Build Tools (Desktop C++ workload + Windows 10/11 SDK)
- Git

Optional:
- GitHub CLI (`gh`) if you want to verify prebuild release assets

## Update the repo
From the repo root:
```powershell
# If you already have the repo
 git pull

# If you are cloning fresh
 git clone https://github.com/LXrdKnowkill/HikariSystem-HexCore.git
 cd HikariSystem-HexCore
```

## Build (recommended)
From the repo root:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-hexcore-win.ps1
```

Optional flags:
```powershell
# Skip extension installs to speed up local troubleshooting
powershell -ExecutionPolicy Bypass -File .\scripts\build-hexcore-win.ps1 -SkipExtensionInstalls

# Increase Node heap if needed
powershell -ExecutionPolicy Bypass -File .\scripts\build-hexcore-win.ps1 -MaxOldSpaceMB 16384
```

Output should end up in `VSCode-win32-x64`.

## If you see: "Entering npm script environment"
This means npm started an interactive shell inside `build\npm\gyp`.

Fix:
1) Type `exit` to leave the shell.
2) Re-run the build script after pulling the latest repo changes.

If needed, you can also set the env var before running:
```powershell
$env:npm_command = 'ci'
```

## Optional: Verify prebuild assets (if gh is installed)
```powershell
& "C:\Program Files\GitHub CLI\gh.exe" release view v1.3.1 -R LXrdKnowkill/hexcore-capstone --json assets --jq ".assets[].name"
& "C:\Program Files\GitHub CLI\gh.exe" release view v1.0.0 -R LXrdKnowkill/hexcore-unicorn --json assets --jq ".assets[].name"
& "C:\Program Files\GitHub CLI\gh.exe" release view v1.0.0 -R LXrdKnowkill/hexcore-llvm-mc --json assets --jq ".assets[].name"
```

## Notes
- The build script installs native engines via `scripts/hexcore-native-install.js`.
- If prebuilt binaries are missing in releases, that step will fail.

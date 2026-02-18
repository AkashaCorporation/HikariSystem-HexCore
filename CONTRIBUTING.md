# Contributing to HikariSystem HexCore

Thank you for your interest in contributing to HexCore! This guide will help you set up a development environment and submit changes.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Node.js | 22.x (dev) / 18+ (production) | Runtime and build |
| Python | 3.11+ | node-gyp (native compilation) |
| Visual Studio Build Tools 2022 | C++ Desktop workload | Native addon compilation (Windows) |
| Git | 2.40+ | Version control |
| npm | 10+ | Package manager |

### Windows — Install Build Tools

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools
# Then open VS Installer and select:
#   "Desktop development with C++"
#   Windows SDK
```

### Linux — Install Build Essentials

```bash
sudo apt install build-essential python3 git
```

## Quick Start

```powershell
# 1. Clone the repository
git clone https://github.com/LXrdKnowkill/HikariSystem-HexCore.git
cd HikariSystem-HexCore

# 2. Set required environment variable
$env:VSCODE_SKIP_NODE_VERSION_CHECK = "1"   # PowerShell
# export VSCODE_SKIP_NODE_VERSION_CHECK=1   # bash

# 3. Install dependencies
npm install

# 4. Install native engine prebuilds (Capstone, Unicorn, LLVM MC, SQLite, Remill)
node scripts/hexcore-native-install.js

# 5. Compile
npm run compile

# 6. Launch HexCore
.\scripts\code.bat          # Windows
./scripts/code.sh           # Linux/Mac
```

> **Important**: `VSCODE_SKIP_NODE_VERSION_CHECK=1` is required because HexCore uses Node.js 22.x for development while the upstream VS Code `.nvmrc` may specify a different version.

## Project Structure

```
HikariSystem-HexCore/
├── src/                    # Core VS Code source (TypeScript)
├── extensions/             # Built-in extensions
│   ├── hexcore-disassembler/   # Disassembler + Pipeline Runner
│   ├── hexcore-debugger/       # Emulation-based debugger (Unicorn)
│   ├── hexcore-hexviewer/      # Binary hex viewer
│   ├── hexcore-peanalyzer/     # PE file analyzer
│   ├── hexcore-elfanalyzer/    # ELF file analyzer
│   ├── hexcore-capstone/       # Native: Capstone disassembly engine
│   ├── hexcore-unicorn/        # Native: Unicorn emulation engine
│   ├── hexcore-remill/         # Native: LLVM IR lifting engine
│   ├── hexcore-llvm-mc/        # Native: LLVM assembler/encoder
│   ├── hexcore-better-sqlite3/ # Native: SQLite database
│   ├── hexcore-strings/        # String extractor + XOR deobfuscation
│   ├── hexcore-entropy/        # Entropy analyzer
│   ├── hexcore-hashcalc/       # Hash calculator
│   ├── hexcore-base64/         # Base64 decoder
│   ├── hexcore-filetype/       # Magic bytes file type detection
│   ├── hexcore-ioc/            # IOC extractor
│   ├── hexcore-minidump/       # Windows minidump parser
│   ├── hexcore-yara/           # YARA rule scanner
│   ├── hexcore-report-composer/ # Pipeline report aggregator
│   ├── hexcore-ai/             # Kimi AI assistant
│   └── hexcore-common/         # Shared utilities
├── build/                  # Build scripts (Gulp)
├── scripts/                # Development and CI scripts
├── docs/                   # Documentation
└── .github/workflows/      # CI/CD pipelines
```

## Running Tests

```powershell
# Unit tests (Electron)
.\scripts\test.bat          # Windows
./scripts/test.sh           # Linux/Mac

# HexCore extension tests (mocha, TDD style)
cd extensions/hexcore-disassembler
npx tsc -p .
npx mocha out/*.test.js --ui tdd

# Native engine tests
cd extensions/hexcore-better-sqlite3 && npm test
cd extensions/hexcore-capstone && npm test
cd extensions/hexcore-unicorn && npm test
```

## Creating a New Extension

1. Copy an existing HexCore extension as a template (e.g., `hexcore-filetype`)
2. Update `package.json` with new name, commands, and activation events
3. Implement functionality in `src/extension.ts`
4. Register the extension in **three** build system files:
   - `build/gulpfile.extensions.ts` — TypeScript compilation
   - `build/npm/dirs.ts` — npm dependency resolution
   - `.github/workflows/hexcore-installer.yml` — Windows AND Linux compile steps
5. If the extension has headless commands, register them in `COMMAND_CAPABILITIES`, `COMMAND_OWNERS`, and `COMMAND_ALIASES` in `extensions/hexcore-disassembler/src/automationPipelineRunner.ts`

## Code Style

- **Indentation**: Tabs, not spaces
- **Naming**: PascalCase for types/enums, camelCase for functions/variables
- **Strings**: Single quotes for code, double quotes for user-facing localized strings
- **Functions**: Prefer `async/await` over `.then()` chains
- **Comments**: JSDoc style, in English
- **Copyright**: All files must include the HikariSystem copyright header

For the complete style guide, see [AGENTS.md](AGENTS.md).

## Native Engine Development

The 5 native engines (Capstone, Unicorn, Remill, LLVM MC, better-sqlite3) have standalone repositories for compilation:

- Standalone repos are maintained separately from the main HexCore repo
- The main repo only contains prebuilt `.node` binaries (fetched by CI)
- **Never** add build tools (`node-gyp`, `prebuild-install`, `prebuildify`) to `devDependencies` in the main repo — they belong in the standalone repos only
- Prebuilds are generated by the `hexcore-native-prebuilds.yml` workflow

For detailed native engine development instructions, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) and [docs/RUNBOOK_NATIVE_PREBUILDS.md](docs/RUNBOOK_NATIVE_PREBUILDS.md).

## Pull Request Process

1. Fork the repository and create a feature branch (`feature/my-feature`)
2. Make your changes following the code style guidelines
3. Ensure TypeScript compiles without errors: `npm run compile`
4. Run relevant tests
5. Write a detailed commit message in English
6. Submit a PR targeting the `main` branch
7. Wait for CI to pass and maintainer review

## Troubleshooting

### `npm install` hangs or shows interactive prompt
Set `VSCODE_SKIP_NODE_VERSION_CHECK=1` before running. If it still hangs, try:
```powershell
Remove-Item -Recurse -Force build/npm/gyp/node_modules
npm install
```

### Native modules fail to load
Run the prebuild installer:
```powershell
node scripts/hexcore-native-install.js
```

### TypeScript compilation fails
Ensure you have the correct Node.js version and all dependencies installed:
```powershell
$env:VSCODE_SKIP_NODE_VERSION_CHECK = "1"
npm install
npm run compile
```

For more troubleshooting tips, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

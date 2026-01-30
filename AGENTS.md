# VS Code Agents Instructions

This file provides instructions for AI coding agents working with the VS Code codebase.

---

## Project Overview

**HikariSystem HexCore** is a specialized IDE for malware analysis and reverse engineering, built on the VS Code foundation with custom extensions designed for security professionals. It combines the full power of VS Code with dedicated tools for binary file analysis, PE executable parsing, cryptographic hash calculation, and string extraction.

### Key Features
- **Hex Viewer** - Professional binary file viewer with virtual scrolling for large files
- **PE Analyzer** - Comprehensive Portable Executable analysis for Windows binaries
- **Hash Calculator** - Fast file hashing with algorithm selection
- **Strings Extractor** - Extract and categorize strings with memory-efficient streaming
- **Entropy Analyzer** - Visual entropy analysis for detecting packed or encrypted regions
- **Base64 Decoder** - Detect and decode Base64 encoded strings in binary files
- **File Type Detector** - Identify true file type using magic bytes signature detection

### NEW in v2.0
- **Disassembler** - Professional disassembly with Capstone engine (x86/x64/ARM)
- **AI Assistant** - Kimi AI integration for automated analysis and CTF help
- **Debugger** - Dynamic analysis with WinDbg/GDB integration
- **YARA Scanner** - Malware detection using YARA rules

---

## Architecture

### Root Folders
- `src/` - Main TypeScript source code with unit tests in `src/vs/*/test/` folders
- `build/` - Build scripts and CI/CD tools
- `extensions/` - Built-in extensions that ship with VS Code, plus HexCore-specific extensions
- `test/` - Integration tests and test infrastructure
- `scripts/` - Development and build scripts
- `resources/` - Static resources (icons, themes, etc.)
- `out/` - Compiled JavaScript output (generated during build)

### Core Architecture (`src/` folder)
The codebase follows a layered architecture:

- `src/vs/base/` - Foundation utilities and cross-platform abstractions
- `src/vs/platform/` - Platform services and dependency injection infrastructure
- `src/vs/editor/` - Text editor implementation with language services, syntax highlighting, and editing features
- `src/vs/workbench/` - Main application workbench for web and desktop
  - `workbench/browser/` - Core workbench UI components (parts, layout, actions)
  - `workbench/services/` - Service implementations
  - `workbench/contrib/` - Feature contributions (git, debug, search, terminal, etc.)
  - `workbench/api/` - Extension host and VS Code API implementation
- `src/vs/code/` - Electron main process specific implementation
- `src/vs/server/` - Server specific implementation

### Built-in Extensions (`extensions/` folder)
The `extensions/` directory contains first-party extensions that ship with VS Code:
- **Language support** - `typescript-language-features/`, `html-language-features/`, `css-language-features/`, etc.
- **Core features** - `git/`, `debug-auto-launch/`, `emmet/`, `markdown-language-features/`
- **Themes** - `theme-*` folders for default color themes
- **Development tools** - `extension-editing/`, `vscode-api-tests/`

### HexCore Extensions (`extensions/hexcore-*` folders)
HexCore-specific extensions for malware analysis:

#### Core Analysis
- `hexcore-hexviewer/` - Binary file viewer with virtual scrolling and data inspector
- `hexcore-peanalyzer/` - PE file analyzer with header parsing and packer detection
- `hexcore-disassembler/` - **NEW v2.0** - Professional disassembly with Capstone engine

#### Security Tools
- `hexcore-hashcalc/` - File hash calculator (MD5, SHA-1, SHA-256, SHA-512)
- `hexcore-strings/` - String extractor with categorization (URLs, IPs, file paths, registry keys)
- `hexcore-entropy/` - Entropy analysis with ASCII graph visualization
- `hexcore-yara/` - **NEW v2.0** - YARA rule scanner for malware detection

#### Dynamic Analysis
- `hexcore-debugger/` - **NEW v2.0** - Debugger integration (WinDbg/GDB)
- `hexcore-sandbox/` - **PLANNED** - Dynamic analysis sandbox

#### AI & Automation
- `hexcore-ai/` - **NEW v2.0** - Kimi AI Assistant integration
- `hexcore-base64/` - Base64 decoder for binary files
- `hexcore-filetype/` - Magic bytes signature detection
- `hexcore-common/` - Shared utilities for HexCore extensions

---

## Technology Stack

- **Runtime**: Node.js 18+, Electron 39.2.7
- **Language**: TypeScript 6.0 (dev preview)
- **Build System**: Gulp 4.0 with custom build scripts
- **Testing**: Mocha, Playwright, Electron test runner
- **Package Manager**: npm
- **Linting**: ESLint with custom local plugins

### v2.0 Additions
- **Disassembly**: Capstone engine bindings
- **Debug**: WinDbg Engine / GDB-MI
- **YARA**: Custom rule engine (wasm bindings planned)

---

## Build and Development Commands

### Development Setup
```powershell
# Clone the repository
git clone https://github.com/LXrdKnowkill/HikariSystem-HexCore.git
cd HikariSystem-HexCore

# Install dependencies
npm install

# Run in development mode (Windows)
$env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
.\scripts\code.bat

# Run in development mode (Linux/Mac)
./scripts/code.sh
```

### Core Build Commands
```bash
# Compile the entire project
npm run compile

# Watch mode for development
npm run watch

# Compile client only
npm run gulp compile-client

# Watch client only
npm run watch-client

# Compile extensions
npm run gulp compile-extensions

# Watch extensions
npm run watch-extensions
```

### HexCore Extension Build Commands
Each HexCore extension can be built independently:
```bash
# Core extensions
cd extensions/hexcore-hexviewer && npm install && npm run compile
cd extensions/hexcore-peanalyzer && npm install && npm run compile
cd extensions/hexcore-hashcalc && npm install && npm run compile
cd extensions/hexcore-strings && npm install && npm run compile
cd extensions/hexcore-entropy && npm install && npm run compile
cd extensions/hexcore-base64 && npm install && npm run compile
cd extensions/hexcore-filetype && npm install && npm run compile
cd extensions/hexcore-common && npm install && npm run compile

# NEW v2.0 extensions
cd extensions/hexcore-disassembler && npm install && npm run compile
cd extensions/hexcore-debugger && npm install && npm run compile
cd extensions/hexcore-ai && npm install && npm run compile
cd extensions/hexcore-yara && npm install && npm run compile
```

---

## Testing

### Running Tests
```bash
# Unit tests (inside Electron)
./scripts/test.sh          # Linux/Mac
scripts\test.bat           # Windows

# Unit tests with debug mode
./scripts/test.sh --debug --glob **/extHost*.test.js

# Browser-based unit tests
npm run test-browser -- --browser webkit --browser chromium

# Node-based unit tests
npm run test-node -- --run src/vs/editor/test/browser/controller/cursor.test.ts

# Extension tests
npm run test-extension

# Smoke tests
npm run smoketest

# Coverage report
./scripts/test.sh --coverage
```

### Test Structure
- `test/unit/` - Unit tests run inside Electron renderer environment
- `test/integration/` - API integration tests
- `test/smoke/` - Automated UI tests
- `test/sanity/` - Release sanity tests

---

## Code Style Guidelines

### Indentation
- **Use tabs, not spaces**

### Naming Conventions
- Use `PascalCase` for `type` names
- Use `PascalCase` for `enum` values
- Use `camelCase` for `function` and `method` names
- Use `camelCase` for `property` names and `local variables`
- Use whole words in names when possible

### Types
- Do not export `types` or `functions` unless you need to share it across multiple components
- Do not introduce new `types` or `values` to the global namespace
- Avoid using `any` or `unknown` as types unless absolutely necessary

### Comments
- Use JSDoc style comments for `functions`, `interfaces`, `enums`, and `classes`
- All comments should be in English

### Strings
- Use "double quotes" for strings shown to the user that need to be externalized (localized)
- Use 'single quotes' otherwise
- All strings visible to the user need to be externalized using the `vs/nls` module
- Externalized strings must not use string concatenation. Use placeholders instead (`{0}`)

### UI Labels
- Use title-style capitalization for command labels, buttons and menu items (each word is capitalized)
- Don't capitalize prepositions of four or fewer letters unless it's the first or last word (e.g. "in", "with", "for")

### Style
- Use arrow functions `=>` over anonymous function expressions
- Only surround arrow function parameters when necessary
- Always surround loop and conditional bodies with curly braces
- Open curly braces always go on the same line as whatever necessitates them
- Parenthesized constructs should have no surrounding whitespace
- Prefer `async` and `await` over `Promise` and `then` calls
- Prefer `export function x() {}` over `export const x = () => {}` in top-level scopes for better stack traces

### Code Quality
- All files must include Microsoft copyright header
- Prefer regex capture groups with names over numbered capture groups
- Never duplicate imports - reuse existing imports if present
- Do not duplicate code - look for existing utility functions before implementing new functionality
- When adding file watching, prefer correlated file watchers (via fileService.createWatcher)
- When adding tooltips to UI elements, prefer the use of IHoverService service

---

## Validating TypeScript Changes

**MANDATORY**: Always check the `VS Code - Build` watch task output for compilation errors before running ANY script or declaring work complete.

- NEVER run tests if there are compilation errors
- Monitor the `VS Code - Build` task outputs for real-time compilation errors
- This task runs `Core - Build` and `Ext - Build` to incrementally compile VS Code TypeScript sources and built-in extensions

### TypeScript Validation Commands
```bash
# Check for layering issues
npm run valid-layers-check

# Monaco typecheck
npm run monaco-compile-check

# Security compile check
npm run tsec-compile-check

# Define class fields check
npm run define-class-fields-check
```

---

## Finding Related Code

1. **Semantic search first**: Use file search for general concepts
2. **Grep for exact strings**: Use grep for error messages or specific function names
3. **Follow imports**: Check what files import the problematic module
4. **Check test files**: Often reveal usage patterns and expected behavior

---

## Extension Development Guidelines

### Creating a New Extension
1. Copy an existing HexCore extension as a template
2. Update `package.json` with new name, commands, and contribution points
3. Implement functionality in `src/extension.ts`
4. Add to `.github/workflows/hexcore-build.yml` workflow
5. Update documentation

### Extension Best Practices
- Use streaming for large files (64KB chunks recommended)
- Provide progress indicators for long-running operations
- Generate Markdown reports for analysis results
- Handle errors gracefully with user-friendly messages
- Prefer Node.js built-ins over third-party dependencies
- Use virtual scrolling for large file viewers

---

## CI/CD

The project uses GitHub Actions for continuous integration:

### Workflows
- `.github/workflows/hexcore-build.yml` - Builds all HexCore extensions and runs linting
- `.github/workflows/hexcore-installer.yml` - Creates Windows installer packages
- `.github/workflows/telemetry.yml` - Telemetry-related checks

### Build Matrix
- Platform: Ubuntu (for extension builds), Windows (for installer)
- Node.js: 18.x

---

## Security Considerations

- All user facing messages must be localized using the applicable localization framework
- When handling binary files, validate file signatures before processing
- Use streaming processing for large files to avoid memory issues
- Sanitize any user input that may be displayed in UI
- Be cautious with file system operations - validate paths

---

## Product Configuration

The `product.json` file defines the product branding:
- Application name: "HexCore"
- Full name: "HikariSystem HexCore"
- Data folder: `.hexcore`
- Protocol: `hexcore://`
- Issue reporting: GitHub Issues

---

## HexCore v2.0 Feature Matrix

| Feature | v1.x | v2.0 | Status |
|---------|------|------|--------|
| Hex Viewer | ✅ | ✅✨ | Improved |
| PE Analyzer | ✅ | ✅✨ | Improved |
| Hash Calculator | ✅ | ✅ | Stable |
| Strings Extractor | ✅ | ✅ | Stable |
| Entropy Analyzer | ✅ | ✅ | Stable |
| Base64 Decoder | ✅ | ✅ | Stable |
| File Type Detector | ✅ | ✅ | Stable |
| **Disassembler** | ❌ | ✅ | **NEW** |
| **Debugger** | ❌ | ✅ | **NEW** |
| **YARA Scanner** | ❌ | ✅ | **NEW** |
| Sandbox | ❌ | 🚧 | Planned |
| Decompiler | ❌ | 🚧 | Planned |
| Collaboration | ❌ | 🚧 | Planned |

Legend: ✅ Available | ✅✨ Improved | 🚧 In Development | ❌ Not Available

---

## Additional Resources

- For detailed architecture and coding guidelines, see `.github/copilot-instructions.md`
- For contribution guidelines, see `CONTRIBUTING.md`
- For end-user documentation, see `README.md`
- For v2.0 roadmap, see `docs/HEXCORE_V2_ROADMAP.md`
- For new extensions documentation, see `docs/NEW_EXTENSIONS.md`

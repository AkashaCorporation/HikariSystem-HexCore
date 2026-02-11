# Contributing to HexCore

Thank you for your interest in contributing to HexCore! This guide will help you set up your development environment and understand our contribution workflow.

## Table of Contents
- [Development Setup](#development-setup)
- [Building from Source](#building-from-source)
- [Running Tests](#running-tests)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)

## Development Setup

### Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js**: v22.21.1 or later
- **Python**: 3.11 or later
- **Visual Studio Build Tools**: 2022 (Windows) or equivalent C++ compiler
- **Git**: Latest version

### Windows-Specific Requirements

On Windows, you need:
- Visual Studio 2022 Build Tools with "Desktop development with C++" workload
- Windows SDK
- node-gyp: `npm install -g node-gyp`

### macOS-Specific Requirements

On macOS, you need:
- Xcode Command Line Tools: `xcode-select --install`
- Homebrew (recommended)

### Linux-Specific Requirements

On Linux, you need:
- GCC/G++ compiler
- Make
- Python development headers

## Building from Source

### Quick Start

For detailed step-by-step instructions, see [BUILD_INSTRUCTIONS.md](BUILD_INSTRUCTIONS.md).

**TL;DR** (Windows):
```powershell
# 1. Copy native binaries to correct locations
.\scripts\copy-hexcore-binaries.ps1

# 2. Install dependencies
npm install
# Note: Type 'exit' when the interactive shell appears

# 3. Build native modules
cd node_modules/@vscode/sqlite3 && node-gyp rebuild && cd ../../..
cd node_modules/@vscode/spdlog && node-gyp rebuild && cd ../../..

# 4. Install ripgrep
npm run postinstall --prefix node_modules/@vscode/ripgrep

# 5. Compile TypeScript
npm run compile

# 6. Launch HexCore
.\scripts\code.bat
```

### Native Modules

HexCore includes three native analysis engines:
- **Capstone**: Disassembly engine
- **Unicorn**: CPU emulation engine
- **LLVM-MC**: Assembly engine

These modules come with prebuilt binaries for common platforms. The build script automatically copies them to the correct locations.

## Running Tests

```bash
# Run all tests
npm test

# Run specific test suite
npm run test:unit
npm run test:integration

# Run tests in watch mode
npm run test:watch
```

## Submitting Changes

### Before You Submit

1. **Search existing issues** to avoid duplicates
2. **Test your changes** thoroughly
3. **Follow code style** guidelines
4. **Update documentation** if needed

### Pull Request Process

1. **Fork the repository** on GitHub
2. **Create a feature branch** from `dev`:
   ```bash
   git checkout -b feature/your-feature-name dev
   ```
3. **Make your changes** with clear, descriptive commits
4. **Test your changes** locally
5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
6. **Open a Pull Request** targeting the `dev` branch

### Commit Message Guidelines

Use clear, descriptive commit messages:

```
[Category] Brief description

Detailed explanation of what changed and why.

Fixes #123
```

**Categories**:
- `[Build]` - Build system changes
- `[Docs]` - Documentation updates
- `[Feature]` - New features
- `[Fix]` - Bug fixes
- `[Refactor]` - Code refactoring
- `[Test]` - Test additions/changes

**Example**:
```
[Build] Fix native module loading on Windows

- Standardize binary naming (hyphen to underscore)
- Add build/Release directory creation
- Simplify Unicorn DLL path resolution

Fixes #42
```

## Code Style

### TypeScript/JavaScript

- Use TypeScript for new code
- Follow existing code style
- Use meaningful variable names
- Add JSDoc comments for public APIs

### Native Code (C++)

- Follow existing C++ style
- Use RAII for resource management
- Add comments for complex logic

### Scripts

- Use PowerShell for Windows scripts
- Use Bash for Unix scripts
- Add comments explaining non-obvious steps

## Development Workflow

### Typical Development Cycle

1. Make changes to source code
2. Run `npm run compile` to rebuild
3. Test changes with `.\scripts\code.bat`
4. Run tests with `npm test`
5. Commit changes

### Hot Reload

For faster development, you can use watch mode:
```bash
npm run watch
```

Then launch HexCore with `.\scripts\code.bat` - changes will be reflected on reload.

## Troubleshooting

### Native Module Issues

If native modules fail to load:
```powershell
# Re-run the binary copy script
.\scripts\copy-hexcore-binaries.ps1

# Verify binaries exist
ls extensions/hexcore-*/build/Release/*.node
```

### Build Errors

If you encounter build errors:
1. Clean node_modules: `rm -rf node_modules`
2. Clean build artifacts: `npm run clean`
3. Reinstall: `npm install`
4. Rebuild: `npm run compile`

### Extension Host Crashes

If the extension host crashes:
1. Check the Developer Tools console (Help > Toggle Developer Tools)
2. Look for error messages in the Output panel
3. Try disabling extensions to isolate the issue

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/LXrdKnowkill/Project-Akasha/issues)
- **Discussions**: [GitHub Discussions](https://github.com/LXrdKnowkill/Project-Akasha/discussions)
- **Documentation**: [docs/](docs/)

## License

By contributing to HexCore, you agree that your contributions will be licensed under the MIT License.

## Code of Conduct

Please be respectful and constructive in all interactions. We're building a welcoming community for reverse engineering and malware analysis.

---

Thank you for contributing to HexCore! 🎉

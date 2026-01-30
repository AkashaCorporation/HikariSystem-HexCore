# HikariSystem HexCore

<p align="center">
  <img alt="HikariSystem HexCore" src="BatHexCore.png" width="200">
</p>

<p align="center">
  <strong>A specialized IDE for malware analysis and reverse engineering</strong>
</p>

<p align="center">
  <a href="#features">Features</a> |
  <a href="#extensions">Extensions</a> |
  <a href="#installation">Installation</a> |
  <a href="#usage">Usage</a> |
  <a href="#license">License</a>
</p>

---

## Overview

HikariSystem HexCore is a comprehensive binary analysis IDE built on VS Code. It provides security researchers with a unified environment for malware analysis, reverse engineering, and threat hunting.

---

## Features

- Professional binary file analysis with hex viewer
- Native multi-architecture disassembler (x86, x64, ARM, ARM64, MIPS)
- PE/ELF executable parsing and inspection
- Cryptographic hash calculation with VirusTotal integration
- String extraction and categorization
- YARA rule scanning
- Entropy analysis for packer/encryption detection
- Integrated debugging capabilities

---

## Extensions

### Core Analysis Tools

| Extension | Version | Description |
|-----------|---------|-------------|
| **Hex Viewer** | 1.2.0 | Professional binary file viewer with virtual scrolling |
| **PE Analyzer** | 1.1.0 | Comprehensive PE executable analysis |
| **Disassembler** | 1.0.0 | Multi-architecture native disassembler |
| **Strings Extractor** | 1.1.0 | Memory-efficient string extraction |
| **Hash Calculator** | 1.1.0 | Fast file hashing with algorithm selection |
| **Entropy Analyzer** | 1.0.0 | Visual entropy analysis for packed regions |
| **Base64 Decoder** | 1.0.0 | Detect and decode Base64 strings |
| **File Type Detector** | 1.0.0 | Magic bytes signature detection |
| **YARA Scanner** | 1.0.0 | YARA rule scanning and matching |
| **Debugger** | 1.0.0 | Integrated debugging for analysis |

---

### Hex Viewer

Professional binary file viewer with virtual scrolling for large files.

- **Virtual Scrolling** - Handles files of any size efficiently
- **Data Inspector** - View bytes as Int8/16/32/64, Float, Unix timestamp
- **Bookmarks** - Save and navigate to important offsets
- **Structure Templates** - Parse common binary structures
- **Search** - Find hex patterns (e.g., `4D 5A` for PE headers)
- **Go to Offset** - Jump directly to any offset
- **Copy Selection** - Export as Hex, C Array, or Python bytes
- **Little/Big Endian** toggle

---

### Disassembler

Native multi-architecture disassembler powered by **Capstone Engine v5.0**.

- **Architectures**: x86, x64, ARM, ARM64, MIPS, RISC-V
- **PE/ELF Support** - Automatic architecture detection
- **Code Analysis** - Function detection, cross-references
- **Detail Mode** - Operands, registers, instruction groups
- **Graph View** - Control flow visualization (planned)

> Powered by [hexcore-capstone](extensions/hexcore-capstone), our custom N-API binding for Capstone.

---

### PE Analyzer

Comprehensive Portable Executable analysis for Windows binaries.

- **DOS/PE/Optional Headers** - Complete header parsing
- **Sections** - Name, size, entropy, permissions (R/W/X)
- **Imports/Exports** - DLLs with imported/exported functions
- **Entropy Analysis** - Visual entropy bar with compression detection
- **Packer Detection** - UPX, VMProtect, Themida, ASPack, and more
- **Suspicious Strings** - Automatic URL, IP, registry key extraction
- **Security Flags** - ASLR, DEP, CFG detection
- **Export to JSON** - Save analysis for external tools

---

### YARA Scanner

Fast YARA rule scanning for threat hunting.

- **Rule Loading** - Load individual rules or rule directories
- **Match Highlighting** - Navigate to matched offsets
- **Custom Rules** - Create and test your own rules
- **Integration** - Works with Hex Viewer and PE Analyzer

---

### Hash Calculator

Fast file hashing with algorithm selection.

- **Algorithms** - MD5, SHA-1, SHA-256, SHA-512
- **Quick Hash** - Instant SHA-256 with clipboard copy
- **Verify Hash** - Compare file against known hash
- **VirusTotal Links** - Quick lookup for malware analysis
- **Streaming** - Efficient for large files

---

### Strings Extractor

Extract and categorize strings with memory-efficient streaming.

- **Streaming Processing** - Handles files of any size (64KB chunks)
- **ASCII and UTF-16LE** extraction
- **Auto-categorization**: URLs, IPs, file paths, registry keys, WinAPI
- **Configurable minimum length**
- **Markdown report** with tables

---

### Entropy Analyzer

Visual entropy analysis with ASCII graph for detecting packed or encrypted regions.

- **Block-by-block entropy** calculation
- **ASCII graph** visualization
- **High entropy region** detection
- **Packer/encryption** assessment

---

## Installation

### Development Mode

```powershell
# Clone the repository
git clone https://github.com/LXrdKnowkill/HikariSystem-HexCore.git
cd HikariSystem-HexCore

# Install dependencies
npm install

# Run in development mode
$env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
.\scripts\code.bat
```

### Requirements

- Node.js 18.x or higher
- npm 8.x or higher
- Windows 10/11
- Visual Studio Build Tools 2022 (for native modules)
- Python 3.x (for node-gyp)

---

## Project Structure

```
HikariSystem-HexCore/
├── extensions/
│   ├── hexcore-hexviewer/      # Binary file viewer
│   ├── hexcore-peanalyzer/     # PE file analyzer
│   ├── hexcore-disassembler/   # Multi-arch disassembler
│   ├── hexcore-capstone/       # Capstone N-API binding
│   ├── hexcore-debugger/       # Integrated debugger
│   ├── hexcore-yara/           # YARA scanner
│   ├── hexcore-hashcalc/       # Hash calculator
│   ├── hexcore-strings/        # Strings extractor
│   ├── hexcore-entropy/        # Entropy analyzer
│   ├── hexcore-base64/         # Base64 decoder
│   └── hexcore-filetype/       # File type detector
├── .agent/
│   └── skills/hexcore/         # AI skill for agent integration
├── docs/                       # Documentation
├── src/                        # Core IDE source
├── resources/                  # Icons and assets
├── build/                      # Build scripts
└── product.json                # Product configuration
```

---

## AI Agent Integration

HexCore includes an AI skill definition for integration with AI agents. The skill provides:

- Documentation for all HexCore commands
- Typical analysis workflow guides
- Output interpretation guidelines
- Command usage examples

See [.agent/skills/hexcore/SKILL.md](.agent/skills/hexcore/SKILL.md) for details.

---

## Usage

### Hex Viewer
- Right-click any file and select **"HexCore: Open Hex View"**
- Or use **"Open With..." > "HexCore Hex Editor"**

### PE Analyzer
- Right-click any `.exe`, `.dll`, `.sys`, or `.ocx` file
- Select **"HexCore: Analyze PE File"**

### Disassembler
- Right-click any executable file
- Select **"HexCore: Disassemble File"**

### Hash Calculator
- Right-click any file
- Select **"HexCore: Calculate File Hashes"**

### Strings Extractor
- Right-click any file
- Select **"HexCore: Extract Strings"**

### YARA Scanner
- Open the YARA Scanner view
- Load rules and scan files

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See the [LICENSE.txt](LICENSE.txt) file for details.

---

<p align="center">
  <strong>HikariSystem</strong> - Security Tools for Professionals
</p>

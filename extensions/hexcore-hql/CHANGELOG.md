# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-01
### Added
- **AST Type System (`src/types/ast.ts`)**: Implemented all 31 C-AST node interfaces based on the Helix MLIR/C++23 decompiler using Discriminated Unions for zero runtime overhead.
- **HQL Query DSL (`src/types/hql.ts`)**: JSON-like query structure for semantic pattern matching, supporting attributes (exact, glob, regex), operands, and recursive containment checks.
- **Matcher Engine (`src/engine/matcher.ts`)**: `HQLMatcher` class with a highly optimized, zero-reflection recursive Tree Walker for AST matching and DFS signature evaluation.
- **Public API (`src/index.ts`)**: Clean exports for HexCore IDE integration.
- **Test Suite (`test/smoke.ts`)**: Smoke tests covering matching features and signature evaluation.
- **Project Configuration**: Strict TypeScript setup (`tsconfig.json`) targeting ES2022 and Node16 module resolution.

### Security
- Designed without reliance on fragile byte-level pattern matching (e.g., YARA/FLIRT) to withstand compiler optimizations and basic obfuscation.

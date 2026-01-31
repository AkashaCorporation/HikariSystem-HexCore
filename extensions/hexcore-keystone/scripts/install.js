/**
 * HexCore Keystone - Installation Script
 * Automates the build process for Keystone engine
 * No manual steps required!
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const DEPS_DIR = path.join(ROOT, 'deps', 'keystone');
const CONFIG_DIR = path.join(DEPS_DIR, 'llvm', 'include', 'llvm', 'Config');
const BUILD_DIR = path.join(DEPS_DIR, 'build_new');
const LIB_DIR = path.join(BUILD_DIR, 'Release');

// Architecture definitions - automatically generated
const TARGETS_DEF = `#ifndef LLVM_TARGET
#  error Please define the macro LLVM_TARGET(TargetName)
#endif
LLVM_TARGET(AArch64)
LLVM_TARGET(ARM)
LLVM_TARGET(Hexagon)
LLVM_TARGET(Mips)
LLVM_TARGET(PowerPC)
LLVM_TARGET(Sparc)
LLVM_TARGET(SystemZ)
LLVM_TARGET(X86)
#undef LLVM_TARGET
`;

const ASMPARSERS_DEF = `#ifndef LLVM_ASM_PARSER
#  error Please define the macro LLVM_ASM_PARSER(TargetName)
#endif
LLVM_ASM_PARSER(AArch64)
LLVM_ASM_PARSER(ARM)
LLVM_ASM_PARSER(Hexagon)
LLVM_ASM_PARSER(Mips)
LLVM_ASM_PARSER(PowerPC)
LLVM_ASM_PARSER(Sparc)
LLVM_ASM_PARSER(SystemZ)
LLVM_ASM_PARSER(X86)
#undef LLVM_ASM_PARSER
`;

function log(msg) {
	console.log('[HexCore Keystone]', msg);
}

function ensureDefs() {
	log('Checking architecture definitions...');
	
	const targetsPath = path.join(CONFIG_DIR, 'Targets.def');
	const asmParsersPath = path.join(CONFIG_DIR, 'AsmParsers.def');
	
	if (!fs.existsSync(targetsPath)) {
		log('Creating Targets.def...');
		fs.writeFileSync(targetsPath, TARGETS_DEF);
	}
	
	if (!fs.existsSync(asmParsersPath)) {
		log('Creating AsmParsers.def...');
		fs.writeFileSync(asmParsersPath, ASMPARSERS_DEF);
	}
	
	log('Architecture definitions ready ✓');
}

function hasPrebuilt() {
	const libName = process.platform === 'win32' ? 'keystone.lib' : 'libkeystone.a';
	const libPath = path.join(LIB_DIR, libName);
	
	// Check in build_new/Release (Windows) or lib/ (Unix)
	if (process.platform === 'win32') {
		return fs.existsSync(libPath);
	} else {
		const unixLib = path.join(DEPS_DIR, 'lib', libName);
		return fs.existsSync(unixLib) || fs.existsSync(libPath);
	}
}

function buildKeystone() {
	log('Building Keystone library (this may take a few minutes)...');
	
	try {
		// Create build directory
		if (!fs.existsSync(BUILD_DIR)) {
			fs.mkdirSync(BUILD_DIR, { recursive: true });
		}
		
		// Run CMake
		log('Running CMake...');
		const cmakeCmd = `cmake -S "${DEPS_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release`;
		execSync(cmakeCmd, { stdio: 'inherit', cwd: ROOT });
		
		// Build
		log('Compiling...');
		const buildCmd = `cmake --build "${BUILD_DIR}" --config Release --parallel`;
		execSync(buildCmd, { stdio: 'inherit', cwd: ROOT });
		
		log('Keystone library built successfully ✓');
	} catch (err) {
		log('ERROR: Failed to build Keystone library');
		log(err.message);
		process.exit(1);
	}
}

function main() {
	log('Setting up HexCore Keystone...');
	
	// Step 1: Ensure .def files exist
	ensureDefs();
	
	// Step 2: Check for prebuilt library
	if (hasPrebuilt()) {
		log('Prebuilt library found ✓');
		log('Skipping build, using existing library');
	} else {
		log('No prebuilt library found');
		buildKeystone();
	}
	
	log('Setup complete! You can now run: npm run build');
}

main();

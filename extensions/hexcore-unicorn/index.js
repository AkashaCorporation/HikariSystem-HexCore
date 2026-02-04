/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
'use strict';

const path = require('path');
const fs = require('fs');

if (process.platform === 'win32') {
	const unicornDir = path.join(__dirname, 'deps', 'unicorn');
	const unicornDll = path.join(unicornDir, 'unicorn.dll');
	if (fs.existsSync(unicornDll)) {
		const pathEntries = (process.env.PATH || '').split(';');
		if (!pathEntries.includes(unicornDir)) {
			process.env.PATH = `${unicornDir};${process.env.PATH || ''}`;
		}
	}
}

/**
 * Load the native addon with fallback paths
 */
function loadNativeAddon() {
	const addonName = 'hexcore_unicorn';
	const possiblePaths = [
		// Prebuilt binaries (prebuildify)
		() => {
			try {
				const prebuildPath = path.join(__dirname, 'prebuilds',
					`${process.platform}-${process.arch}`,
					`${addonName}.node`);
				if (fs.existsSync(prebuildPath)) {
					return require(prebuildPath);
				}
			} catch (e) {}
			return null;
		},
		// Release build
		() => {
			try {
				const releasePath = path.join(__dirname, 'build', 'Release', `${addonName}.node`);
				if (fs.existsSync(releasePath)) {
					return require(releasePath);
				}
			} catch (e) {}
			return null;
		},
		// Debug build
		() => {
			try {
				const debugPath = path.join(__dirname, 'build', 'Debug', `${addonName}.node`);
				if (fs.existsSync(debugPath)) {
					return require(debugPath);
				}
			} catch (e) {}
			return null;
		}
	];

	for (const tryLoad of possiblePaths) {
		const addon = tryLoad();
		if (addon) {
			return addon;
		}
	}

	throw new Error(
		'Failed to load hexcore-unicorn native addon. ' +
		'Please ensure the package is properly built. ' +
		'Run: npm run build'
	);
}

const native = loadNativeAddon();

// Export the Unicorn class
const Unicorn = native.Unicorn;

// Export the UnicornContext class
const UnicornContext = native.UnicornContext;

// Export constants
const ARCH = Object.freeze(native.ARCH);
const MODE = Object.freeze(native.MODE);
const PROT = Object.freeze(native.PROT);
const HOOK = Object.freeze(native.HOOK);
const MEM = Object.freeze(native.MEM);
const QUERY = Object.freeze(native.QUERY);
const ERR = Object.freeze(native.ERR);

// Export register constants
const X86_REG = Object.freeze(native.X86_REG);
const ARM_REG = Object.freeze(native.ARM_REG);
const ARM64_REG = Object.freeze(native.ARM64_REG);
const MIPS_REG = Object.freeze(native.MIPS_REG);

// Export utility functions
const version = native.version;
const archSupported = native.archSupported;
const strerror = native.strerror;

// CommonJS exports
module.exports = {
	// Classes
	Unicorn,
	UnicornContext,

	// Architecture constants
	ARCH,

	// Mode constants
	MODE,

	// Memory protection constants
	PROT,

	// Hook type constants
	HOOK,

	// Memory access type constants
	MEM,

	// Query type constants
	QUERY,

	// Error constants
	ERR,

	// Register constants by architecture
	X86_REG,
	ARM_REG,
	ARM64_REG,
	MIPS_REG,

	// Utility functions
	version,
	archSupported,
	strerror,

	// Default export for convenient destructuring
	default: {
		Unicorn,
		UnicornContext,
		ARCH,
		MODE,
		PROT,
		HOOK,
		MEM,
		QUERY,
		ERR,
		X86_REG,
		ARM_REG,
		ARM64_REG,
		MIPS_REG,
		version,
		archSupported,
		strerror
	}
};


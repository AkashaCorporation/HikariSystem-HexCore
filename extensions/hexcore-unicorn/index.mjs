/**
 * HexCore Unicorn - ESM wrapper
 *
 * HikariSystem HexCore - CPU Emulator
 * ES Module exports for the Unicorn emulation framework bindings
 *
 * @module hexcore-unicorn
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const native = require('./index.js');

// Export classes
export const Unicorn = native.Unicorn;
export const UnicornContext = native.UnicornContext;

// Export constants
export const ARCH = native.ARCH;
export const MODE = native.MODE;
export const PROT = native.PROT;
export const HOOK = native.HOOK;
export const MEM = native.MEM;
export const QUERY = native.QUERY;
export const ERR = native.ERR;

// Export register constants
export const X86_REG = native.X86_REG;
export const ARM_REG = native.ARM_REG;
export const ARM64_REG = native.ARM64_REG;
export const MIPS_REG = native.MIPS_REG;

// Export utility functions
export const version = native.version;
export const archSupported = native.archSupported;
export const strerror = native.strerror;

// Default export
export default native;

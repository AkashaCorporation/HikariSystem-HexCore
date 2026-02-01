// ESM wrapper for hexcore-llvm-mc
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const binding = require('./index.js');

// Export the main class
export const LlvmMc = binding.LlvmMc;

// Export constants
export const TRIPLE = binding.TRIPLE;
export const SYNTAX = binding.SYNTAX;
export const OPTION = binding.OPTION;
export const ERR = binding.ERR;
export const CPU = binding.CPU;
export const FEATURES = binding.FEATURES;

// Export functions
export const version = binding.version;
export const getTargets = binding.getTargets;

// Default export
export default binding;

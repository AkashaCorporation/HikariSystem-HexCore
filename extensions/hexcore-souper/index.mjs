import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const binding = require('./index.js');

export const { SouperOptimizer, version } = binding;
export default binding;

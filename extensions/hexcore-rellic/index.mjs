/**
 * HexCore Rellic - ESM Wrapper
 * ECMAScript Module support for modern Node.js
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const rellic = require('./index.js');

export const { RellicDecompiler, version } = rellic;

export default RellicDecompiler;

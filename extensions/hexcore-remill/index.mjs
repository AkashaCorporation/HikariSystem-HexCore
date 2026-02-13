/**
 * HexCore Remill - ESM Wrapper
 * ECMAScript Module support for modern Node.js
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const remill = require('./index.js');

export const { RemillLifter, ARCH, OS, version } = remill;

export default RemillLifter;

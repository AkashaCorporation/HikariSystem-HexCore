/**
 * HexCore Capstone - ESM Wrapper
 * ECMAScript Module support for modern Node.js
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const capstone = require('./index.js');

export const {
	Capstone,
	ARCH,
	MODE,
	OPT,
	OPT_VALUE,
	ERR,
	version,
	support
} = capstone;

export default Capstone;

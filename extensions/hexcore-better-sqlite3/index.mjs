/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const binding = require('./index.js');

export const Database = binding.Database;
export const openDatabase = binding.openDatabase;
export const resolveNativeBinaryPath = binding.resolveNativeBinaryPath;

export default binding;


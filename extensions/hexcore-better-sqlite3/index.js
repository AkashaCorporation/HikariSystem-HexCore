/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
'use strict';

const fs = require('fs');
const path = require('path');

const BetterSqlite3 = require('better-sqlite3');

function resolvePackageRoot() {
	const packageJsonPath = require.resolve('better-sqlite3/package.json');
	return path.dirname(packageJsonPath);
}

function resolveNativeBinaryPath() {
	const packageRoot = resolvePackageRoot();
	const candidates = [
		path.join(packageRoot, 'build', 'Release', 'better_sqlite3.node'),
		path.join(packageRoot, 'build', 'Debug', 'better_sqlite3.node'),
		path.join(packageRoot, 'prebuilds', `${process.platform}-${process.arch}`, 'node.napi.node'),
		path.join(packageRoot, 'prebuilds', `${process.platform}-${process.arch}`, 'better_sqlite3.node')
	];

	for (const candidate of candidates) {
		if (fs.existsSync(candidate)) {
			return candidate;
		}
	}

	return undefined;
}

function openDatabase(filename, options) {
	return new BetterSqlite3(filename, options);
}

module.exports = BetterSqlite3;
module.exports.default = BetterSqlite3;
module.exports.Database = BetterSqlite3;
module.exports.openDatabase = openDatabase;
module.exports.resolveNativeBinaryPath = resolveNativeBinaryPath;


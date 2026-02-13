/**
 * HexCore Better-SQLite3 - Native Node.js Bindings
 * N-API wrapper for SQLite via better-sqlite3 binding layer
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

'use strict';

const path = require('path');

// ---------------------------------------------------------------------------
// 1. Load the native addon using the standard HexCore fallback chain
// ---------------------------------------------------------------------------
let nativeAddon;
try {
	nativeAddon = require('./prebuilds/' + process.platform + '-' + process.arch + '/node.napi.node');
} catch (e1) {
	try {
		nativeAddon = require('./build/Release/hexcore_sqlite3.node');
	} catch (e2) {
		try {
			nativeAddon = require('./build/Debug/hexcore_sqlite3.node');
		} catch (e3) {
			throw new Error(
				'Failed to load hexcore-better-sqlite3 native module. ' +
				'Errors:\n' +
				`  Prebuild: ${e1.message}\n` +
				`  Release: ${e2.message}\n` +
				`  Debug: ${e3.message}`
			);
		}
	}
}

// ---------------------------------------------------------------------------
// 2. Wire up the JS layer with the loaded addon
// ---------------------------------------------------------------------------
const SqliteError = require('./lib/sqlite-error');

if (!nativeAddon.isInitialized) {
	nativeAddon.setErrorConstructor(SqliteError);
	nativeAddon.isInitialized = true;
}

// Inject the loaded addon into Database so lib/database.js never calls
// node-gyp-build or bindings at runtime.
const Database = require('./lib/database');
Database._nativeAddon = nativeAddon;

// ---------------------------------------------------------------------------
// 3. Public API
// ---------------------------------------------------------------------------

function openDatabase(filename, options) {
	return new Database(filename, options);
}

function resolveNativeBinaryPath() {
	const fs = require('fs');
	const candidates = [
		path.join(__dirname, 'prebuilds', `${process.platform}-${process.arch}`, 'node.napi.node'),
		path.join(__dirname, 'build', 'Release', 'hexcore_sqlite3.node'),
		path.join(__dirname, 'build', 'Debug', 'hexcore_sqlite3.node'),
	];
	return candidates.find(p => fs.existsSync(p));
}

module.exports = Database;
module.exports.default = Database;
module.exports.Database = Database;
module.exports.SqliteError = SqliteError;
module.exports.openDatabase = openDatabase;
module.exports.resolveNativeBinaryPath = resolveNativeBinaryPath;

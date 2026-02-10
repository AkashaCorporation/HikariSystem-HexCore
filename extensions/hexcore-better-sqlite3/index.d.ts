/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import BetterSqlite3 = require('better-sqlite3');
type BetterSqlite3Constructor = typeof import('better-sqlite3');

declare function openDatabase(
	filename: string,
	options?: BetterSqlite3.Options
): BetterSqlite3.Database;

declare function resolveNativeBinaryPath(): string | undefined;

declare const Database: BetterSqlite3Constructor & {
	default: BetterSqlite3Constructor;
	Database: BetterSqlite3Constructor;
	openDatabase: typeof openDatabase;
	resolveNativeBinaryPath: typeof resolveNativeBinaryPath;
};

export = Database;

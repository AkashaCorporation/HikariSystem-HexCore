/*---------------------------------------------------------------------------------------------
 *  HexCore Better-SQLite3 - TypeScript Definitions
 *  Inline types following the HexCore native wrapper standard.
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License.
 *--------------------------------------------------------------------------------------------*/

/**
 * Options for opening a database.
 */
export interface DatabaseOptions {
	/** Open the database in read-only mode. Default: false. */
	readonly readonly?: boolean;
	/** Throw if the database file does not exist. Default: false. */
	readonly fileMustExist?: boolean;
	/** Busy timeout in milliseconds. Default: 5000. */
	readonly timeout?: number;
	/** Called with every SQL string executed. */
	readonly verbose?: (message: string, ...args: unknown[]) => void;
	/**
	 * Path to a custom native binding (.node file) or a pre-loaded addon object.
	 * When omitted the standard HexCore fallback loading is used.
	 */
	readonly nativeBinding?: string | object;
}

/** Result of a statement that modifies data. */
export interface RunResult {
	/** Number of rows changed by the last INSERT, UPDATE, or DELETE. */
	readonly changes: number;
	/** Row ID of the last inserted row. */
	readonly lastInsertRowid: number | bigint;
}

/** Column metadata returned by `.columns()`. */
export interface ColumnDefinition {
	readonly name: string;
	readonly column: string | null;
	readonly table: string | null;
	readonly database: string | null;
	readonly type: string | null;
}

/** A prepared SQL statement. */
export interface Statement<BindParameters extends unknown[] = unknown[]> {
	/** Execute the statement and return run result (for INSERT/UPDATE/DELETE). */
	run(...params: BindParameters): RunResult;
	/** Execute the statement and return the first matching row. */
	get(...params: BindParameters): unknown;
	/** Execute the statement and return all matching rows. */
	all(...params: BindParameters): unknown[];
	/** Iterate over result rows. */
	iterate(...params: BindParameters): IterableIterator<unknown>;
	/** Return column metadata for the prepared statement. */
	columns(): ColumnDefinition[];
	/** Bind parameters permanently to the statement. */
	bind(...params: BindParameters): this;
	/** Enable or disable safe integer mode for this statement. */
	safeIntegers(toggle?: boolean): this;
	/** Enable or disable raw array mode (rows as arrays instead of objects). */
	raw(toggle?: boolean): this;
	/** Enable or disable expand mode (rows grouped by table). */
	expand(toggle?: boolean): this;
	/** The source SQL string. */
	readonly source: string;
	/** Whether the statement is read-only. */
	readonly reader: boolean;
	/** Whether the statement is bound to parameters. */
	readonly busy: boolean;
}

/** A SQLite database connection. */
export interface Database {
	/**
	 * Prepare a SQL statement.
	 * @param sql - The SQL string to prepare.
	 */
	prepare<P extends unknown[] = unknown[]>(sql: string): Statement<P>;
	/**
	 * Execute one or more SQL statements (no parameter binding).
	 * @param sql - The SQL string(s) to execute.
	 */
	exec(sql: string): this;
	/** Close the database connection. */
	close(): this;
	/**
	 * Create a transaction function.
	 * @param fn - The function to wrap in a transaction.
	 */
	transaction<F extends (...args: unknown[]) => unknown>(fn: F): F & {
		deferred: F;
		immediate: F;
		exclusive: F;
	};
	/** Execute a PRAGMA statement. */
	pragma(sql: string, options?: { simple?: boolean }): unknown;
	/** Register a custom SQL function. */
	function(name: string, fn: (...args: unknown[]) => unknown): this;
	function(name: string, options: { deterministic?: boolean; varargs?: boolean; directOnly?: boolean; safeIntegers?: boolean }, fn: (...args: unknown[]) => unknown): this;
	/** Register a custom aggregate function. */
	aggregate(name: string, options: {
		start: unknown;
		step: (total: unknown, next: unknown) => unknown;
		result?: (total: unknown) => unknown;
		inverse?: (total: unknown, dropped: unknown) => unknown;
		deterministic?: boolean;
		directOnly?: boolean;
		safeIntegers?: boolean;
	}): this;
	/** Load a SQLite extension. */
	loadExtension(path: string, entryPoint?: string): this;
	/** Enable or disable safe integer mode globally. */
	defaultSafeIntegers(toggle?: boolean): this;
	/** Enable or disable unsafe mode. */
	unsafeMode(toggle?: boolean): this;
	/** Serialize the database to a Buffer. */
	serialize(attachedName?: string): Buffer;
	/** Back up the database to a file. */
	backup(destinationFile: string, options?: { attached?: string; progress?: (info: { totalPages: number; remainingPages: number }) => number }): Promise<void>;
	/** The filename of the database. */
	readonly name: string;
	/** Whether the database connection is open. */
	readonly open: boolean;
	/** Whether the database is in a transaction. */
	readonly inTransaction: boolean;
	/** Whether the database was opened in read-only mode. */
	readonly readonly: boolean;
	/** Whether the database is an in-memory database. */
	readonly memory: boolean;
}

/** Custom SQLite error class. */
export interface SqliteError extends Error {
	readonly code: string;
}

/** Database constructor type. */
export interface DatabaseConstructor {
	new(filename: string, options?: DatabaseOptions): Database;
	(filename: string, options?: DatabaseOptions): Database;
}

/**
 * Open a SQLite database.
 *
 * @example
 * ```js
 * const { openDatabase } = require('hexcore-better-sqlite3');
 * const db = openDatabase(':memory:');
 * db.exec('CREATE TABLE kv (id INTEGER PRIMARY KEY, value TEXT)');
 * db.prepare('INSERT INTO kv(value) VALUES (?)').run('hello');
 * const row = db.prepare('SELECT value FROM kv WHERE id = 1').get();
 * db.close();
 * ```
 */
export declare function openDatabase(filename: string, options?: DatabaseOptions): Database;

/** Resolve the path to the loaded native binary. */
export declare function resolveNativeBinaryPath(): string | undefined;

declare const _default: DatabaseConstructor & {
	default: DatabaseConstructor;
	Database: DatabaseConstructor;
	SqliteError: SqliteError;
	openDatabase: typeof openDatabase;
	resolveNativeBinaryPath: typeof resolveNativeBinaryPath;
};

export = _default;

/*---------------------------------------------------------------------------------------------
 *  HexCore Session Store v1.0.0
 *  Persistent session database for binary analysis (renames, retypes, comments, bookmarks)
 *  Uses hexcore-better-sqlite3 with WAL mode for concurrent read access (HQL).
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { loadNativeModule } from 'hexcore-common';

// ── SQLite type interfaces (matches hexcore-better-sqlite3 API) ─────────────

interface SqliteRunResult {
	changes: number;
	lastInsertRowid: number | bigint;
}

interface SqlitePreparedStatement {
	run(...params: unknown[]): SqliteRunResult;
	get(...params: unknown[]): unknown;
	all(...params: unknown[]): unknown[];
}

interface SqliteDatabase {
	exec(sql: string): void;
	prepare(sql: string): SqlitePreparedStatement;
	close(): void;
	readonly open: boolean;
}

interface HexcoreBetterSqlite3Module {
	openDatabase(filename: string, options?: { readonly?: boolean; fileMustExist?: boolean }): SqliteDatabase;
}

// ── Public types ────────────────────────────────────────────────────────────

export interface FunctionEntry {
	address: string;
	name: string | null;
	return_type: string | null;
	calling_convention: string | null;
	updated_at: string;
}

export interface VariableEntry {
	func_address: string;
	original_name: string;
	new_name: string | null;
	new_type: string | null;
	updated_at: string;
}

export interface FieldEntry {
	struct_type: string;
	offset: number;
	name: string | null;
	type: string | null;
	updated_at: string;
}

export interface CommentEntry {
	address: string;
	comment: string;
	updated_at: string;
}

export interface BookmarkEntry {
	address: string;
	label: string;
	updated_at: string;
}

export interface CachedFunction {
	address: string;
	name: string;
	size: number;
	end_address: number;
}

// ── SessionStore ────────────────────────────────────────────────────────────

const SESSION_DB_FILENAME = '.hexcore_session.db';
const GITIGNORE_ENTRIES = ['.hexcore_session.db', '.hexcore_session.db-shm', '.hexcore_session.db-wal'];

export class SessionStore {
	private readonly db: SqliteDatabase;
	private readonly dbPath: string;
	private readonly binarySha256: string;

	// Prepared statements — functions
	private readonly insertFunc;
	private readonly selectFunc;
	private readonly selectAllFuncs;

	// Prepared statements — variables
	private readonly upsertVar;
	private readonly selectVarsByFunc;

	// Prepared statements — fields
	private readonly upsertField;
	private readonly selectFieldsByStruct;

	// Prepared statements — comments
	private readonly upsertComment;
	private readonly selectComment;
	private readonly selectAllComments;
	private readonly deleteComment;

	// Prepared statements — bookmarks
	private readonly upsertBookmark;
	private readonly selectAllBookmarks;
	private readonly deleteBookmark;

	// Prepared statements — analyze cache
	private readonly insertCachedFunc;
	private readonly selectAllCachedFuncs;
	private readonly clearCacheStmt;

	// Prepared statements — session meta
	private readonly upsertMeta;
	private readonly selectMeta;

	constructor(binaryPath: string) {
		// Compute SHA-256
		const fileBuffer = fs.readFileSync(binaryPath);
		this.binarySha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

		// DB lives next to the binary
		const dir = path.dirname(binaryPath);
		this.dbPath = path.join(dir, SESSION_DB_FILENAME);

		// Open/create database
		this.db = loadSqliteModule().openDatabase(this.dbPath);

		// Performance PRAGMAs (same as hexcore-ioc)
		this.db.exec(`
			PRAGMA journal_mode = WAL;
			PRAGMA synchronous = NORMAL;
			PRAGMA temp_store = MEMORY;
			PRAGMA cache_size = -32000;
		`);

		// Create schema
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS session_meta (
				key TEXT PRIMARY KEY,
				value TEXT
			);

			CREATE TABLE IF NOT EXISTS functions (
				address TEXT PRIMARY KEY,
				name TEXT,
				return_type TEXT,
				calling_convention TEXT,
				updated_at TEXT
			);

			CREATE TABLE IF NOT EXISTS variables (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				func_address TEXT NOT NULL,
				original_name TEXT NOT NULL,
				new_name TEXT,
				new_type TEXT,
				updated_at TEXT,
				UNIQUE(func_address, original_name)
			);

			CREATE TABLE IF NOT EXISTS fields (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				struct_type TEXT NOT NULL,
				offset INTEGER NOT NULL,
				name TEXT,
				type TEXT,
				updated_at TEXT,
				UNIQUE(struct_type, offset)
			);

			CREATE TABLE IF NOT EXISTS comments (
				address TEXT PRIMARY KEY,
				comment TEXT,
				updated_at TEXT
			);

			CREATE TABLE IF NOT EXISTS bookmarks (
				address TEXT PRIMARY KEY,
				label TEXT,
				updated_at TEXT
			);

			CREATE TABLE IF NOT EXISTS analyze_cache (
				address TEXT PRIMARY KEY,
				name TEXT,
				size INTEGER,
				end_address INTEGER
			);
		`);

		// Validate session ownership
		this.validateSession(binaryPath);

		// Prepare all statements
		this.upsertMeta = this.db.prepare(
			`INSERT OR REPLACE INTO session_meta (key, value) VALUES (?, ?)`
		);
		this.selectMeta = this.db.prepare(
			`SELECT value FROM session_meta WHERE key = ?`
		);

		this.insertFunc = this.db.prepare(
			`INSERT OR REPLACE INTO functions (address, name, return_type, calling_convention, updated_at) VALUES (?, ?, ?, ?, ?)`
		);
		this.selectFunc = this.db.prepare(
			`SELECT address, name, return_type, calling_convention, updated_at FROM functions WHERE address = ?`
		);
		this.selectAllFuncs = this.db.prepare(
			`SELECT address, name, return_type, calling_convention, updated_at FROM functions ORDER BY address`
		);

		this.upsertVar = this.db.prepare(
			`INSERT INTO variables (func_address, original_name, new_name, new_type, updated_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(func_address, original_name) DO UPDATE
			 SET new_name = excluded.new_name, new_type = excluded.new_type, updated_at = excluded.updated_at`
		);
		this.selectVarsByFunc = this.db.prepare(
			`SELECT func_address, original_name, new_name, new_type, updated_at FROM variables WHERE func_address = ?`
		);

		this.upsertField = this.db.prepare(
			`INSERT INTO fields (struct_type, offset, name, type, updated_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(struct_type, offset) DO UPDATE
			 SET name = excluded.name, type = excluded.type, updated_at = excluded.updated_at`
		);
		this.selectFieldsByStruct = this.db.prepare(
			`SELECT struct_type, offset, name, type, updated_at FROM fields WHERE struct_type = ? ORDER BY offset`
		);

		this.upsertComment = this.db.prepare(
			`INSERT OR REPLACE INTO comments (address, comment, updated_at) VALUES (?, ?, ?)`
		);
		this.selectComment = this.db.prepare(
			`SELECT address, comment, updated_at FROM comments WHERE address = ?`
		);
		this.selectAllComments = this.db.prepare(
			`SELECT address, comment, updated_at FROM comments ORDER BY address`
		);
		this.deleteComment = this.db.prepare(
			`DELETE FROM comments WHERE address = ?`
		);

		this.upsertBookmark = this.db.prepare(
			`INSERT OR REPLACE INTO bookmarks (address, label, updated_at) VALUES (?, ?, ?)`
		);
		this.selectAllBookmarks = this.db.prepare(
			`SELECT address, label, updated_at FROM bookmarks ORDER BY address`
		);
		this.deleteBookmark = this.db.prepare(
			`DELETE FROM bookmarks WHERE address = ?`
		);

		this.insertCachedFunc = this.db.prepare(
			`INSERT OR REPLACE INTO analyze_cache (address, name, size, end_address) VALUES (?, ?, ?, ?)`
		);
		this.selectAllCachedFuncs = this.db.prepare(
			`SELECT address, name, size, end_address FROM analyze_cache ORDER BY address`
		);
		this.clearCacheStmt = this.db.prepare(
			`DELETE FROM analyze_cache`
		);

		// Ensure gitignore
		this.ensureGitignore(dir);
	}

	// ── Session validation ──────────────────────────────────────────────────

	private validateSession(binaryPath: string): void {
		const row = this.db.prepare(`SELECT value FROM session_meta WHERE key = 'binary_sha256'`).get() as { value: string } | undefined;

		if (!row) {
			// Fresh DB — write meta
			const now = new Date().toISOString();
			this.db.exec(`DELETE FROM session_meta`);
			const insert = this.db.prepare(`INSERT INTO session_meta (key, value) VALUES (?, ?)`);
			insert.run('binary_sha256', this.binarySha256);
			insert.run('binary_path', binaryPath);
			insert.run('created_at', now);
			insert.run('hexcore_version', '3.7.4');
		} else if (row.value !== this.binarySha256) {
			// Binary changed — clear all analysis data but keep user annotations
			this.db.exec(`DELETE FROM analyze_cache`);
			// Update meta
			this.db.prepare(`UPDATE session_meta SET value = ? WHERE key = 'binary_sha256'`).run(this.binarySha256);
			this.db.prepare(`UPDATE session_meta SET value = ? WHERE key = 'binary_path'`).run(binaryPath);
		}
	}

	// ── Functions ────────────────────────────────────────────────────────────

	renameFunction(address: string, name: string): void {
		const now = new Date().toISOString();
		const existing = this.selectFunc.get(address) as FunctionEntry | undefined;
		this.insertFunc.run(
			address,
			name,
			existing?.return_type ?? null,
			existing?.calling_convention ?? null,
			now
		);
	}

	retypeFunction(address: string, returnType: string): void {
		const now = new Date().toISOString();
		const existing = this.selectFunc.get(address) as FunctionEntry | undefined;
		this.insertFunc.run(
			address,
			existing?.name ?? null,
			returnType,
			existing?.calling_convention ?? null,
			now
		);
	}

	setFunctionCallingConvention(address: string, cc: string): void {
		const now = new Date().toISOString();
		const existing = this.selectFunc.get(address) as FunctionEntry | undefined;
		this.insertFunc.run(
			address,
			existing?.name ?? null,
			existing?.return_type ?? null,
			cc,
			now
		);
	}

	getFunction(address: string): FunctionEntry | undefined {
		return this.selectFunc.get(address) as FunctionEntry | undefined;
	}

	getAllFunctions(): FunctionEntry[] {
		return this.selectAllFuncs.all() as FunctionEntry[];
	}

	// ── Variables ────────────────────────────────────────────────────────────

	renameVariable(funcAddress: string, originalName: string, newName: string): void {
		const now = new Date().toISOString();
		const existing = this.selectVarsByFunc.all(funcAddress) as VariableEntry[];
		const prev = existing.find(v => v.original_name === originalName);
		this.upsertVar.run(funcAddress, originalName, newName, prev?.new_type ?? null, now);
	}

	retypeVariable(funcAddress: string, originalName: string, newType: string): void {
		const now = new Date().toISOString();
		const existing = this.selectVarsByFunc.all(funcAddress) as VariableEntry[];
		const prev = existing.find(v => v.original_name === originalName);
		this.upsertVar.run(funcAddress, originalName, prev?.new_name ?? null, newType, now);
	}

	getVariables(funcAddress: string): VariableEntry[] {
		return this.selectVarsByFunc.all(funcAddress) as VariableEntry[];
	}

	// ── Fields ──────────────────────────────────────────────────────────────

	setField(structType: string, offset: number, name: string, type: string): void {
		const now = new Date().toISOString();
		this.upsertField.run(structType, offset, name, type, now);
	}

	getFields(structType: string): FieldEntry[] {
		return this.selectFieldsByStruct.all(structType) as FieldEntry[];
	}

	// ── Comments ─────────────────────────────────────────────────────────────

	setComment(address: string, comment: string): void {
		const now = new Date().toISOString();
		this.upsertComment.run(address, comment, now);
	}

	getComment(address: string): string | undefined {
		const row = this.selectComment.get(address) as CommentEntry | undefined;
		return row?.comment;
	}

	getAllComments(): CommentEntry[] {
		return this.selectAllComments.all() as CommentEntry[];
	}

	removeComment(address: string): void {
		this.deleteComment.run(address);
	}

	// ── Bookmarks ────────────────────────────────────────────────────────────

	setBookmark(address: string, label: string): void {
		const now = new Date().toISOString();
		this.upsertBookmark.run(address, label, now);
	}

	removeBookmark(address: string): void {
		this.deleteBookmark.run(address);
	}

	getAllBookmarks(): BookmarkEntry[] {
		return this.selectAllBookmarks.all() as BookmarkEntry[];
	}

	// ── Analyze cache ────────────────────────────────────────────────────────

	cacheFunction(address: string, name: string, size: number, endAddress: number): void {
		this.insertCachedFunc.run(address, name, size, endAddress);
	}

	getCachedFunctions(): CachedFunction[] {
		return this.selectAllCachedFuncs.all() as CachedFunction[];
	}

	clearCache(): void {
		this.clearCacheStmt.run();
	}

	// ── Import from AnnotationStore ──────────────────────────────────────────

	importAnnotations(annotationsJsonPath: string): number {
		try {
			if (!fs.existsSync(annotationsJsonPath)) {
				return 0;
			}
			const raw = fs.readFileSync(annotationsJsonPath, 'utf-8');
			const parsed = JSON.parse(raw);
			if (!parsed || parsed.version !== 1 || !parsed.annotations) {
				return 0;
			}

			let count = 0;
			for (const entry of Object.values(parsed.annotations) as Array<{ address: string; comment: string }>) {
				if (entry.address && entry.comment) {
					// Only import if we don't already have a comment at this address
					const existing = this.selectComment.get(entry.address);
					if (!existing) {
						this.setComment(entry.address, entry.comment);
						count++;
					}
				}
			}
			return count;
		} catch {
			return 0;
		}
	}

	// ── Meta / Accessors ─────────────────────────────────────────────────────

	getDbPath(): string {
		return this.dbPath;
	}

	getBinarySha256(): string {
		return this.binarySha256;
	}

	getMeta(key: string): string | undefined {
		const row = this.selectMeta.get(key) as { value: string } | undefined;
		return row?.value;
	}

	setMeta(key: string, value: string): void {
		this.upsertMeta.run(key, value);
	}

	dispose(): void {
		try {
			if (this.db.open) {
				this.db.close();
			}
		} catch {
			// best-effort cleanup
		}
	}

	// ── Gitignore ────────────────────────────────────────────────────────────

	private ensureGitignore(dir: string): void {
		try {
			const gitignorePath = this.findNearestGitignore(dir) ?? path.join(dir, '.gitignore');
			let content = '';
			if (fs.existsSync(gitignorePath)) {
				content = fs.readFileSync(gitignorePath, 'utf-8');
			}

			const lines = content.split(/\r?\n/);
			const toAdd: string[] = [];
			for (const entry of GITIGNORE_ENTRIES) {
				if (!lines.some(line => line.trim() === entry)) {
					toAdd.push(entry);
				}
			}

			if (toAdd.length > 0) {
				const needsNewline = content.length > 0 && !content.endsWith('\n');
				const addition = (needsNewline ? '\n' : '') +
					'# HexCore session files\n' +
					toAdd.join('\n') + '\n';
				fs.writeFileSync(gitignorePath, content + addition, 'utf-8');
			}
		} catch {
			// Silently ignore gitignore errors
		}
	}

	private findNearestGitignore(startDir: string): string | undefined {
		let current = path.resolve(startDir);
		const root = path.parse(current).root;
		while (current !== root) {
			const candidate = path.join(current, '.gitignore');
			if (fs.existsSync(candidate)) {
				return candidate;
			}
			const parent = path.dirname(current);
			if (parent === current) {
				break;
			}
			current = parent;
		}
		return undefined;
	}
}

// ── Module loader ────────────────────────────────────────────────────────────

function loadSqliteModule(): HexcoreBetterSqlite3Module {
	// Use loadNativeModule with candidate paths (same pattern as capstone/remill/helix wrappers)
	const result = loadNativeModule<HexcoreBetterSqlite3Module>({
		moduleName: 'hexcore-better-sqlite3',
		candidatePaths: [
			path.join(__dirname, '..', '..', 'hexcore-better-sqlite3'),
			path.join(__dirname, '..', '..', '..', 'hexcore-better-sqlite3'),
		],
	});
	if (!result.module) {
		throw new Error(`hexcore-better-sqlite3 not available: ${result.errorMessage}`);
	}
	return result.module;
}

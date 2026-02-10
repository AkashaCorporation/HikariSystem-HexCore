/*---------------------------------------------------------------------------------------------
 *  HexCore IOC Extractor v1.1.0
 *  Match storage backends (memory/sqlite)
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { IOCCategory, IOCMatch, IOCStorageBackend } from './types';

interface SqliteRunResult {
	changes: number;
}

interface SqlitePreparedStatement {
	run(...params: unknown[]): SqliteRunResult;
	all(...params: unknown[]): unknown[];
}

interface SqliteDatabase {
	exec(sql: string): void;
	prepare(sql: string): SqlitePreparedStatement;
	close(): void;
}

interface HexcoreBetterSqlite3Module {
	openDatabase(filename: string, options?: unknown): SqliteDatabase;
}

export interface IOCMatchStoreSnapshot {
	indicators: Record<IOCCategory, IOCMatch[]>;
	categoryCounts: Record<IOCCategory, number>;
	totalUniqueCount: number;
}

export interface IOCMatchStore {
	readonly backend: IOCStorageBackend;
	addMatch(match: IOCMatch): boolean;
	snapshot(categories: readonly IOCCategory[]): IOCMatchStoreSnapshot;
	dispose(): void;
}

export interface IOCMatchStoreOptions {
	backend: IOCStorageBackend;
	categories: readonly IOCCategory[];
	sqlitePath?: string;
}

export function createIOCMatchStore(options: IOCMatchStoreOptions): IOCMatchStore {
	if (options.backend === 'sqlite') {
		return new SqliteIOCMatchStore(options.sqlitePath);
	}
	return new InMemoryIOCMatchStore(options.categories);
}

class InMemoryIOCMatchStore implements IOCMatchStore {
	readonly backend: IOCStorageBackend = 'memory';
	private readonly seen = new Set<string>();
	private readonly indicators: Record<IOCCategory, IOCMatch[]>;

	constructor(categories: readonly IOCCategory[]) {
		const record = Object.create(null) as Record<IOCCategory, IOCMatch[]>;
		for (const category of categories) {
			record[category] = [];
		}
		this.indicators = record;
	}

	addMatch(match: IOCMatch): boolean {
		const dedupKey = `${match.category}:${match.value.toLowerCase()}`;
		if (this.seen.has(dedupKey)) {
			return false;
		}
		this.seen.add(dedupKey);
		this.indicators[match.category]?.push(match);
		return true;
	}

	snapshot(categories: readonly IOCCategory[]): IOCMatchStoreSnapshot {
		const categoryCounts = Object.create(null) as Record<IOCCategory, number>;
		let totalUniqueCount = 0;

		for (const category of categories) {
			const matches = this.indicators[category] ?? [];
			categoryCounts[category] = matches.length;
			totalUniqueCount += matches.length;
		}

		return {
			indicators: this.indicators,
			categoryCounts,
			totalUniqueCount,
		};
	}

	dispose(): void {
		// no-op for in-memory backend
	}
}

class SqliteIOCMatchStore implements IOCMatchStore {
	readonly backend: IOCStorageBackend = 'sqlite';
	private readonly db: SqliteDatabase;
	private readonly dbPath: string;
	private readonly temporaryDb: boolean;
	private readonly insertStatement;
	private readonly selectByCategoryStatement;

	constructor(sqlitePath?: string) {
		const resolvedPath = sqlitePath && sqlitePath.length > 0
			? path.resolve(sqlitePath)
			: createTemporarySqlitePath();

		this.dbPath = resolvedPath;
		this.temporaryDb = !sqlitePath;

		fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
		this.db = loadSqliteModule().openDatabase(this.dbPath);

		this.db.exec(`
			PRAGMA journal_mode = WAL;
			PRAGMA synchronous = NORMAL;
			PRAGMA temp_store = MEMORY;
			PRAGMA cache_size = -32000;
		`);

		this.db.exec(`
			CREATE TABLE IF NOT EXISTS ioc_matches (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				category TEXT NOT NULL,
				value TEXT NOT NULL,
				value_lower TEXT NOT NULL,
				offset INTEGER NOT NULL,
				encoding TEXT NOT NULL,
				context TEXT NOT NULL,
				UNIQUE(category, value_lower)
			);
			CREATE INDEX IF NOT EXISTS idx_ioc_matches_category_offset
				ON ioc_matches(category, offset);
		`);

		this.insertStatement = this.db.prepare(`
			INSERT OR IGNORE INTO ioc_matches (
				category,
				value,
				value_lower,
				offset,
				encoding,
				context
			) VALUES (?, ?, ?, ?, ?, ?)
		`);

		this.selectByCategoryStatement = this.db.prepare(`
			SELECT
				value,
				offset,
				encoding,
				context
			FROM ioc_matches
			WHERE category = ?
			ORDER BY offset ASC
		`);
	}

	addMatch(match: IOCMatch): boolean {
		const result = this.insertStatement.run(
			match.category,
			match.value,
			match.value.toLowerCase(),
			match.offset,
			match.encoding,
			match.context,
		) as { changes: number };
		return result.changes > 0;
	}

	snapshot(categories: readonly IOCCategory[]): IOCMatchStoreSnapshot {
		const indicators = Object.create(null) as Record<IOCCategory, IOCMatch[]>;
		const categoryCounts = Object.create(null) as Record<IOCCategory, number>;
		let totalUniqueCount = 0;

		for (const category of categories) {
			const rows = this.selectByCategoryStatement.all(category) as Array<{
				value: string;
				offset: number;
				encoding: 'ASCII' | 'UTF-16LE';
				context: string;
			}>;

			const matches = rows.map(row => ({
				category,
				value: row.value,
				offset: row.offset,
				encoding: row.encoding,
				context: row.context,
			}));

			indicators[category] = matches;
			categoryCounts[category] = matches.length;
			totalUniqueCount += matches.length;
		}

		return {
			indicators,
			categoryCounts,
			totalUniqueCount,
		};
	}

	dispose(): void {
		try {
			this.db.close();
		} finally {
			if (this.temporaryDb) {
				safeDeleteFile(this.dbPath);
				safeDeleteFile(`${this.dbPath}-shm`);
				safeDeleteFile(`${this.dbPath}-wal`);
			}
		}
	}
}

function createTemporarySqlitePath(): string {
	const tempRoot = path.join(os.tmpdir(), 'hexcore-ioc');
	fs.mkdirSync(tempRoot, { recursive: true });
	const fileName = `ioc-${process.pid}-${Date.now()}-${crypto.randomUUID()}.db`;
	return path.join(tempRoot, fileName);
}

function safeDeleteFile(filePath: string): void {
	try {
		fs.unlinkSync(filePath);
	} catch {
		// best effort cleanup only
	}
}

function loadSqliteModule(): HexcoreBetterSqlite3Module {
	return require('hexcore-better-sqlite3') as HexcoreBetterSqlite3Module;
}

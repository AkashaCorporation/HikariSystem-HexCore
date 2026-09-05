/*---------------------------------------------------------------------------------------------
 *  HexCore Session Store v1.0.0
 *  Persistent session database for binary analysis (renames, retypes, comments, bookmarks)
 *  Uses hexcore-better-sqlite3 with WAL mode for concurrent read access (HQL).
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
	ANALYSIS_CONTRACT_VERSION,
	createAnalysisSession,
	createAnalysisTarget,
	loadNativeModule,
	type AnalysisEngineIdentity,
	type AnalysisSession,
	type AnalysisTarget,
	type AnalysisTargetInput,
} from 'hexcore-common';
import { SemanticStore } from './semanticStore';
import type { WholeProgramPropagationStore } from './wholeProgramPropagation';
import {
	SemanticTypeCatalog,
	type CallingConventionId,
	type SemanticEvidence,
} from './semanticModel';

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

export interface InvestigationEntry {
	id: string;
	title: string;
	kind: string;
	query: string;
	status: string;
	result_count: number;
	created_at: string;
	updated_at: string;
}

export interface InvestigationFindingEntry {
	id: string;
	investigation_id: string;
	kind: string;
	query: string;
	label: string;
	string_address: string;
	reference_address: string | null;
	function_address: string | null;
	function_name: string | null;
	encoding: string | null;
	evidence_json: string;
	saved: number;
	created_at: string;
	updated_at: string;
}

export interface InvestigationFindingInput {
	id: string;
	investigationId: string;
	kind: string;
	query: string;
	label: string;
	stringAddress: string;
	referenceAddress: string | null;
	functionAddress: string | null;
	functionName: string | null;
	encoding: string | null;
	evidenceJson: string;
	saved: boolean;
}

export interface EngineManifestRecord {
	engines: AnalysisEngineIdentity[];
	settings?: Record<string, unknown>;
	recordedAt: string;
}

export interface FunctionInvalidationResult {
	removedCachedFunctions: number;
	removedFindings: number;
	invalidatedReferenceEdges: number;
}

export interface PersistedMaterializedFunction {
	address: string;
	endExclusive: string;
	bodySha256: string;
	bodyCompleteness?: {
		state: 'complete';
		authoritativeStart: number;
		authoritativeEndExclusive: number;
		decodedEndExclusive: number;
		semanticEndExclusive: number;
		boundaryReached: true;
		stopReason: 'function-end';
		byteCoverage: number;
	};
}

export interface AnalysisUniverseManifest {
	schemaVersion: 1;
	binarySha256: string;
	materializedFunctions: PersistedMaterializedFunction[];
	universeSha256: string;
	updatedAt: string;
}

// ── SessionStore ────────────────────────────────────────────────────────────

const SESSION_DB_FILENAME = '.hexcore_session.db';
export const SESSION_SCHEMA_VERSION = 2;
const GITIGNORE_ENTRIES = [
	'.hexcore_session.db',
	'.hexcore_session.db-shm',
	'.hexcore_session.db-wal',
	'.hexcore_session.db.migration-backup-*',
	'.hexcore_session.db.target-mismatch-*',
];

export class SessionStore {
	private db!: SqliteDatabase;
	private readonly dbPath: string;
	private readonly binarySha256: string;
	private analysisTarget?: AnalysisTarget;
	private analysisSession?: AnalysisSession;
	private semanticStore!: SemanticStore;

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

	// Prepared statements — investigations
	private readonly upsertInvestigation;
	private readonly selectRecentInvestigations;
	private readonly deleteInvestigationFindings;
	private readonly insertInvestigationFinding;
	private readonly selectInvestigationFindings;
	private readonly selectSavedInvestigationFindings;
	private readonly selectInvestigationFinding;
	private readonly updateInvestigationFindingSaved;
	private readonly updateInvestigationFindingFunction;

	constructor(binaryPath: string) {
		// Compute SHA-256
		const fileBuffer = fs.readFileSync(binaryPath);
		this.binarySha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

		// DB lives next to the binary
		const dir = path.dirname(binaryPath);
		this.dbPath = path.join(dir, SESSION_DB_FILENAME);

		let recoveredMigration = false;
		let recoveredTargetMismatch = false;
		while (true) {
			this.db = loadSqliteModule().openDatabase(this.dbPath);
			this.configureDatabase(this.db);
			const existingBinarySha256 = this.readExistingBinarySha256(this.db);
			if (existingBinarySha256 && existingBinarySha256 !== this.binarySha256) {
				this.db.close();
				if (recoveredTargetMismatch) {
					throw new Error(`Unable to isolate session owned by binary ${existingBinarySha256}`);
				}
				this.archiveTargetMismatch(existingBinarySha256);
				recoveredTargetMismatch = true;
				continue;
			}
			const schemaVersion = this.readSchemaVersion(this.db);
			if (schemaVersion > SESSION_SCHEMA_VERSION) {
				this.db.close();
				throw new Error(
					`Session database schema ${schemaVersion} is newer than supported schema ${SESSION_SCHEMA_VERSION}`
				);
			}

			const migrating = schemaVersion < SESSION_SCHEMA_VERSION;
			if (migrating && schemaVersion > 0) this.backupBeforeMigration(schemaVersion);
			try {
				if (migrating) {
					this.db.exec('BEGIN IMMEDIATE;');
				}

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

			CREATE TABLE IF NOT EXISTS investigations (
				id TEXT PRIMARY KEY,
				title TEXT NOT NULL,
				kind TEXT NOT NULL,
				query TEXT NOT NULL,
				status TEXT NOT NULL,
				result_count INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS investigation_findings (
				id TEXT PRIMARY KEY,
				investigation_id TEXT NOT NULL,
				kind TEXT NOT NULL,
				query TEXT NOT NULL,
				label TEXT NOT NULL,
				string_address TEXT NOT NULL,
				reference_address TEXT,
				function_address TEXT,
				function_name TEXT,
				encoding TEXT,
				evidence_json TEXT NOT NULL,
				saved INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
			);

			CREATE INDEX IF NOT EXISTS investigation_findings_investigation_idx
				ON investigation_findings(investigation_id);
			CREATE INDEX IF NOT EXISTS investigation_findings_saved_idx
				ON investigation_findings(saved, updated_at DESC);
				`);
				this.validateSchemaV1(this.db);
				this.semanticStore = new SemanticStore(this.db, this.semanticTargetIdentity());
				if (migrating) {
					this.migrateLegacySemanticFacts();
				}

				if (migrating) {
					this.db.exec(`PRAGMA user_version = ${SESSION_SCHEMA_VERSION}; COMMIT;`);
				}
				break;
			} catch (error) {
				if (migrating) {
					try {
						this.db.exec('ROLLBACK;');
					} catch {
						// The failing SQLite statement may already have aborted the transaction.
					}
				}
				try {
					this.db.close();
				} catch {
					// Continue to the recovery decision with the original migration error.
				}
				if (!migrating || recoveredMigration) {
					throw error;
				}
				this.backupFailedMigration();
				recoveredMigration = true;
			}
		}

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

		this.upsertInvestigation = this.db.prepare(
			`INSERT OR REPLACE INTO investigations
			 (id, title, kind, query, status, result_count, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		);
		this.selectRecentInvestigations = this.db.prepare(
			`SELECT id, title, kind, query, status, result_count, created_at, updated_at
			 FROM investigations ORDER BY updated_at DESC LIMIT ?`
		);
		this.deleteInvestigationFindings = this.db.prepare(
			`DELETE FROM investigation_findings WHERE investigation_id = ?`
		);
		this.insertInvestigationFinding = this.db.prepare(
			`INSERT OR REPLACE INTO investigation_findings
			 (id, investigation_id, kind, query, label, string_address, reference_address,
			  function_address, function_name, encoding, evidence_json, saved, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		);
		this.selectInvestigationFindings = this.db.prepare(
			`SELECT id, investigation_id, kind, query, label, string_address, reference_address,
			 function_address, function_name, encoding, evidence_json, saved, created_at, updated_at
			 FROM investigation_findings WHERE investigation_id = ? ORDER BY function_address, reference_address`
		);
		this.selectSavedInvestigationFindings = this.db.prepare(
			`SELECT id, investigation_id, kind, query, label, string_address, reference_address,
			 function_address, function_name, encoding, evidence_json, saved, created_at, updated_at
			 FROM investigation_findings WHERE saved = 1 ORDER BY updated_at DESC LIMIT ?`
		);
		this.selectInvestigationFinding = this.db.prepare(
			`SELECT id, investigation_id, kind, query, label, string_address, reference_address,
			 function_address, function_name, encoding, evidence_json, saved, created_at, updated_at
			 FROM investigation_findings WHERE id = ?`
		);
		this.updateInvestigationFindingSaved = this.db.prepare(
			`UPDATE investigation_findings SET saved = ?, updated_at = ? WHERE id = ?`
		);
		this.updateInvestigationFindingFunction = this.db.prepare(
			`UPDATE investigation_findings
			 SET function_address = ?, function_name = ?, updated_at = ? WHERE id = ?`
		);

		// Ensure gitignore
		this.ensureGitignore(dir);
	}

	private configureDatabase(db: SqliteDatabase): void {
		db.exec(`
			PRAGMA journal_mode = WAL;
			PRAGMA synchronous = NORMAL;
			PRAGMA temp_store = MEMORY;
			PRAGMA cache_size = -32000;
		`);
	}

	private semanticTargetIdentity(): string {
		return `target:sha256:${this.binarySha256}`;
	}

	private propagationFunctionIdentity(value: string): string {
		const normalized = value.trim();
		return /^0x[0-9a-f]+$/i.test(normalized) ? `function:${normalized.toLowerCase()}` : normalized;
	}

	private readExistingBinarySha256(db: SqliteDatabase): string | undefined {
		try {
			const table = db.prepare(`SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'session_meta'`).get() as { present?: number } | undefined;
			if (table?.present !== 1) return undefined;
			const row = db.prepare(`SELECT value FROM session_meta WHERE key = 'binary_sha256'`).get() as { value?: unknown } | undefined;
			return typeof row?.value === 'string' && /^[a-f0-9]{64}$/i.test(row.value) ? row.value.toLowerCase() : undefined;
		} catch {
			return undefined;
		}
	}

	private archiveTargetMismatch(previousSha256: string): void {
		if (!fs.existsSync(this.dbPath)) return;
		const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
		const archivePath = `${this.dbPath}.target-mismatch-${previousSha256.slice(0, 12)}-${timestamp}`;
		fs.renameSync(this.dbPath, archivePath);
		for (const suffix of ['-wal', '-shm']) {
			const sidecar = `${this.dbPath}${suffix}`;
			if (fs.existsSync(sidecar)) fs.renameSync(sidecar, `${archivePath}${suffix}`);
		}
	}

	private backupBeforeMigration(fromVersion: number): void {
		if (!fs.existsSync(this.dbPath)) return;
		this.db.exec('PRAGMA wal_checkpoint(FULL);');
		const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
		const backupPath = `${this.dbPath}.migration-backup-v${fromVersion}-to-v${SESSION_SCHEMA_VERSION}-${timestamp}`;
		fs.copyFileSync(this.dbPath, backupPath);
		for (const suffix of ['-wal', '-shm']) {
			const sidecar = `${this.dbPath}${suffix}`;
			if (fs.existsSync(sidecar)) fs.copyFileSync(sidecar, `${backupPath}${suffix}`);
		}
	}

	private migrateLegacySemanticFacts(): void {
		const functions = this.db.prepare(
			`SELECT address, name, return_type, calling_convention FROM functions ORDER BY address`,
		).all() as Array<{ address: string; name: string | null; return_type: string | null; calling_convention: string | null }>;
		const variables = this.db.prepare(
			`SELECT func_address, original_name, new_name, new_type FROM variables ORDER BY func_address, original_name`,
		).all() as Array<{ func_address: string; original_name: string; new_name: string | null; new_type: string | null }>;
		const fields = this.db.prepare(
			`SELECT struct_type, offset, name, type FROM fields ORDER BY struct_type, offset`,
		).all() as Array<{ struct_type: string; offset: number; name: string | null; type: string | null }>;
		const comments = this.db.prepare(`SELECT address, comment FROM comments ORDER BY address`).all();
		const bookmarks = this.db.prepare(`SELECT address, label FROM bookmarks ORDER BY address`).all();
		this.semanticStore.migrateLegacyV1({
			functions,
			variables,
			fields,
			additionalFacts: [
				...comments.map((value, index) => ({ kind: 'comment', key: String((value as { address?: unknown }).address ?? index), value })),
				...bookmarks.map((value, index) => ({ kind: 'bookmark', key: String((value as { address?: unknown }).address ?? index), value })),
			],
		});
	}

	private readSchemaVersion(db: SqliteDatabase): number {
		const row = db.prepare('PRAGMA user_version').get() as { user_version?: unknown } | undefined;
		const value = row?.user_version;
		return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0;
	}

	private validateSchemaV1(db: SqliteDatabase): void {
		const probes = [
			'SELECT key, value FROM session_meta LIMIT 1',
			'SELECT address, name, return_type, calling_convention, updated_at FROM functions LIMIT 1',
			'SELECT func_address, original_name, new_name, new_type, updated_at FROM variables LIMIT 1',
			'SELECT struct_type, offset, name, type, updated_at FROM fields LIMIT 1',
			'SELECT address, comment, updated_at FROM comments LIMIT 1',
			'SELECT address, label, updated_at FROM bookmarks LIMIT 1',
			'SELECT address, name, size, end_address FROM analyze_cache LIMIT 1',
			'SELECT id, title, kind, query, status, result_count, created_at, updated_at FROM investigations LIMIT 1',
			`SELECT id, investigation_id, kind, query, label, string_address, reference_address,
			 function_address, function_name, encoding, evidence_json, saved, created_at, updated_at
			 FROM investigation_findings LIMIT 1`,
		];
		for (const probe of probes) {
			db.prepare(probe).get();
		}
	}

	private backupFailedMigration(): void {
		if (!fs.existsSync(this.dbPath)) {
			return;
		}
		const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
		const backupPath = `${this.dbPath}.migration-backup-${timestamp}`;
		fs.copyFileSync(this.dbPath, backupPath);
		for (const suffix of ['-wal', '-shm']) {
			const sidecar = `${this.dbPath}${suffix}`;
			if (fs.existsSync(sidecar)) {
				fs.copyFileSync(sidecar, `${backupPath}${suffix}`);
				fs.rmSync(sidecar, { force: true });
			}
		}
		fs.rmSync(this.dbPath, { force: true });
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
			insert.run('hexcore_version', readProductVersion());
		} else if (row.value !== this.binarySha256) {
			// Constructor-level quarantine should make this unreachable; fail closed.
			throw new Error(`Session ownership mismatch: expected ${this.binarySha256}, found ${row.value}`);
		}
	}

	// ── Functions ────────────────────────────────────────────────────────────

	private analystEvidence(existing: readonly SemanticEvidence[] = []): SemanticEvidence {
		const generation = Math.max(
			this.analysisTarget ? (this.analysisSession?.generation ?? -1) + 1 : (this.analysisSession?.generation ?? 0),
			...existing.map(evidence => evidence.generation + 1),
		);
		return {
			strength: 'definitive', source: 'analyst', producer: 'session-store:analyst-override',
			generation,
			userDefined: true,
		};
	}

	private normalizeCallingConvention(value: string | null | undefined): CallingConventionId {
		const normalized = (value ?? '').trim().toLowerCase().replace(/^__/, '');
		const aliases: Record<string, CallingConventionId> = {
			cdecl: 'cdecl', stdcall: 'stdcall', fastcall: 'fastcall', thiscall: 'thiscall', vectorcall: 'vectorcall',
			usercall: 'usercall', win64: 'win64', msvc_x64: 'win64', sysv64: 'sysv64', sysv_amd64: 'sysv64',
			aapcs32: 'aapcs32', aapcs64: 'aapcs64',
		};
		return aliases[normalized] ?? 'win64';
	}

	private updateSemanticPrototype(address: string, returnType?: string, callingConvention?: string): void {
		const functionIdentity = address.trim().toLowerCase();
		const targetIdentity = this.semanticTargetIdentity();
		const current = this.semanticStore.getPrototype(functionIdentity);
		const evidence = this.analystEvidence(current?.evidenceSet);
		const catalog = new SemanticTypeCatalog(targetIdentity, 'analyst-overrides');
		let returnTypeId = current?.returnTypeId;
		if (returnType !== undefined) {
			const parsed = catalog.parseLegacyCType(returnType, evidence, { targetIdentity, nominalScope: 'analyst-overrides' });
			this.semanticStore.writeBatch({ types: parsed.types });
			returnTypeId = parsed.rootTypeId;
		}
		if (!returnTypeId) {
			const unknown = catalog.intern({ kind: 'unknown', name: `return:${functionIdentity}` }, evidence);
			this.semanticStore.putType(unknown);
			returnTypeId = unknown.typeId;
		}
		const legacy = this.selectFunc.get(address) as FunctionEntry | undefined;
		const result = this.semanticStore.putPrototype({
			targetIdentity,
			functionIdentity,
			functionAddress: functionIdentity,
			returnTypeId,
			callingConventionId: this.normalizeCallingConvention(callingConvention ?? current?.callingConventionId ?? legacy?.calling_convention),
			parameters: current?.parameters ?? [],
			variadic: current?.variadic ?? false,
			noreturn: current?.noreturn ?? false,
			method: current?.method ?? false,
			staticMethod: current?.staticMethod ?? false,
			...(current?.hiddenReturn ? { hiddenReturn: current.hiddenReturn } : {}),
			...(current?.hiddenStorage ? { hiddenStorage: current.hiddenStorage } : {}),
			evidence,
		});
		const changed = current === undefined || current.prototypeHash !== result.accepted.prototypeHash;
		if (changed && this.analysisTarget) {
			this.invalidateFunction(functionIdentity);
			this.advanceAnalysisGeneration(
				'semantic prototype override changed',
				functionIdentity,
				this.getAnalysisUniverseManifest()?.universeSha256,
			);
		}
	}

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
		this.updateSemanticPrototype(address, returnType);
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
		this.updateSemanticPrototype(address, undefined, cc);
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

	replaceCachedFunctions(entries: Iterable<CachedFunction>): void {
		this.db.exec('BEGIN IMMEDIATE');
		try {
			this.clearCacheStmt.run();
			for (const entry of entries) {
				this.insertCachedFunc.run(entry.address, entry.name, entry.size, entry.end_address);
			}
			this.db.exec('COMMIT');
		} catch (error) {
			try {
				this.db.exec('ROLLBACK');
			} catch {
				// Preserve the original database error.
			}
			throw error;
		}
	}

	getCachedFunctions(): CachedFunction[] {
		return this.selectAllCachedFuncs.all() as CachedFunction[];
	}

	// ── Investigations ───────────────────────────────────────────────────────

	recordInvestigation(
		entry: Omit<InvestigationEntry, 'result_count' | 'created_at' | 'updated_at'>,
		findings: readonly InvestigationFindingInput[]
	): void {
		const now = new Date().toISOString();
		// Findings are target-scoped evidence: when a stable finding ID reappears
		// (same finding rediscovered by a re-run or another investigation), retain
		// the analyst's saved mark and the original discovery timestamp instead of
		// resetting both on every re-record.
		const priorRows = this.db.prepare(
			`SELECT id, saved, created_at FROM investigation_findings`
		).all() as Array<{ id: string; saved: number; created_at: string }>;
		const priorById = new Map(priorRows.map(row => [row.id, row]));
		this.db.exec('BEGIN IMMEDIATE');
		try {
			this.upsertInvestigation.run(
				entry.id, entry.title, entry.kind, entry.query, entry.status,
				findings.length, now, now
			);
			this.deleteInvestigationFindings.run(entry.id);
			for (const finding of findings) {
				const prior = priorById.get(finding.id);
				const saved = finding.saved || prior?.saved === 1 ? 1 : 0;
				const createdAt = prior?.created_at ?? now;
				this.insertInvestigationFinding.run(
					finding.id, finding.investigationId, finding.kind, finding.query,
					finding.label, finding.stringAddress, finding.referenceAddress,
					finding.functionAddress, finding.functionName, finding.encoding,
					finding.evidenceJson, saved, createdAt, now
				);
			}
			this.db.exec('COMMIT');
		} catch (error) {
			try {
				this.db.exec('ROLLBACK');
			} catch {
				// Preserve the original database error.
			}
			throw error;
		}
	}

	getRecentInvestigations(limit = 20): InvestigationEntry[] {
		return this.selectRecentInvestigations.all(Math.max(1, Math.min(100, limit))) as InvestigationEntry[];
	}

	getInvestigationFindings(investigationId: string): InvestigationFindingEntry[] {
		return this.selectInvestigationFindings.all(investigationId) as InvestigationFindingEntry[];
	}

	getSavedInvestigationFindings(limit = 250): InvestigationFindingEntry[] {
		return this.selectSavedInvestigationFindings.all(Math.max(1, Math.min(1000, limit))) as InvestigationFindingEntry[];
	}

	getInvestigationFinding(id: string): InvestigationFindingEntry | undefined {
		return this.selectInvestigationFinding.get(id) as InvestigationFindingEntry | undefined;
	}

	setInvestigationFindingSaved(id: string, saved: boolean): boolean {
		return this.updateInvestigationFindingSaved.run(saved ? 1 : 0, new Date().toISOString(), id).changes > 0;
	}

	setInvestigationFindingFunction(id: string, functionAddress: string, functionName: string | null): boolean {
		return this.updateInvestigationFindingFunction.run(
			functionAddress, functionName, new Date().toISOString(), id
		).changes > 0;
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

	getSemanticStore(): SemanticStore {
		return this.semanticStore;
	}

	getWholeProgramPropagationStore(): WholeProgramPropagationStore {
		return this.semanticStore.getWholeProgramPropagationStore();
	}

	getMeta(key: string): string | undefined {
		const row = this.selectMeta.get(key) as { value: string } | undefined;
		return row?.value;
	}

	getSchemaVersion(): number {
		return this.readSchemaVersion(this.db);
	}

	setMeta(key: string, value: string): void {
		this.upsertMeta.run(key, value);
	}

	/**
	 * Bind the persistent database to the canonical target after format parsing.
	 * Existing databases are migrated through session_meta only; user annotations
	 * and derived tables keep their current schema and ownership rules.
	 */
	bindAnalysisTarget(input: Omit<AnalysisTargetInput, 'binarySha256'>): AnalysisTarget {
		const target = createAnalysisTarget({
			...input,
			binarySha256: this.binarySha256,
		});
		const persistedSession = this.restoreAnalysisSession(target.id);
		const session = persistedSession ?? createAnalysisSession({
			id: `session:${crypto.randomUUID()}`,
			targetId: target.id,
			generation: 0,
		});

		this.analysisTarget = target;
		this.analysisSession = session;
		this.setMeta('analysis_contract_version', String(ANALYSIS_CONTRACT_VERSION));
		this.setMeta('analysis_target_json', JSON.stringify(target));
		this.setMeta('analysis_session_json', JSON.stringify(session));
		// The database must not lie about which product wrote it: refresh the
		// stored version on every bind instead of freezing it at creation time.
		this.setMeta('hexcore_version', readProductVersion());
		if (this.getMeta('analysis_generation_counter') === undefined) {
			this.setMeta('analysis_generation_counter', String(session.generation));
		}
		return target;
	}

	getAnalysisTarget(): AnalysisTarget | undefined {
		return this.analysisTarget;
	}

	getAnalysisSession(): AnalysisSession | undefined {
		return this.analysisSession;
	}

	getAnalysisUniverseManifest(): AnalysisUniverseManifest | undefined {
		const serialized = this.getMeta('analysis_universe_manifest_json');
		if (!serialized) { return undefined; }
		try {
			const manifest = JSON.parse(serialized) as Partial<AnalysisUniverseManifest>;
			if (manifest.schemaVersion !== 1 || manifest.binarySha256 !== this.binarySha256 ||
				!Array.isArray(manifest.materializedFunctions) || typeof manifest.universeSha256 !== 'string' ||
				typeof manifest.updatedAt !== 'string') {
				return undefined;
			}
			const materializedFunctions = manifest.materializedFunctions.filter(entry => {
				const completeness = entry?.bodyCompleteness;
				const validCompleteness = completeness === undefined || (
					completeness.state === 'complete' && completeness.boundaryReached === true &&
					completeness.stopReason === 'function-end' && completeness.byteCoverage === 1 &&
					Number.isSafeInteger(completeness.authoritativeStart) &&
					Number.isSafeInteger(completeness.authoritativeEndExclusive) &&
					Number.isSafeInteger(completeness.decodedEndExclusive) &&
					Number.isSafeInteger(completeness.semanticEndExclusive)
				);
				return typeof entry?.address === 'string' && typeof entry?.endExclusive === 'string' &&
					typeof entry?.bodySha256 === 'string' && /^[a-f0-9]{64}$/i.test(entry.bodySha256) &&
					validCompleteness;
			});
			if (materializedFunctions.length !== manifest.materializedFunctions.length) { return undefined; }
			return { ...manifest as AnalysisUniverseManifest, materializedFunctions };
		} catch {
			return undefined;
		}
	}

	recordMaterializedFunction(entry: PersistedMaterializedFunction): AnalysisUniverseManifest {
		const previous = this.getAnalysisUniverseManifest();
		const byAddress = new Map((previous?.materializedFunctions ?? []).map(item => [item.address.toLowerCase(), item]));
		byAddress.set(entry.address.toLowerCase(), entry);
		return this.replaceAnalysisUniverseManifest([...byAddress.values()]);
	}

	replaceAnalysisUniverseManifest(entries: readonly PersistedMaterializedFunction[]): AnalysisUniverseManifest {
		const materializedFunctions = [...entries].sort((left, right) =>
			left.address.toLowerCase().localeCompare(right.address.toLowerCase()));
		const identityPayload = {
			schemaVersion: 1,
			binarySha256: this.binarySha256,
			materializedFunctions,
		};
		const universeSha256 = crypto.createHash('sha256').update(JSON.stringify(identityPayload)).digest('hex');
		const manifest: AnalysisUniverseManifest = {
			...identityPayload,
			schemaVersion: 1,
			universeSha256,
			updatedAt: new Date().toISOString(),
		};
		this.setMeta('analysis_universe_manifest_json', JSON.stringify(manifest));
		return manifest;
	}

	resetAnalysisUniverseManifest(): AnalysisUniverseManifest {
		const identityPayload = {
			schemaVersion: 1 as const,
			binarySha256: this.binarySha256,
			materializedFunctions: [] as PersistedMaterializedFunction[],
		};
		const manifest: AnalysisUniverseManifest = {
			...identityPayload,
			universeSha256: crypto.createHash('sha256').update(JSON.stringify(identityPayload)).digest('hex'),
			updatedAt: new Date().toISOString(),
		};
		this.setMeta('analysis_universe_manifest_json', JSON.stringify(manifest));
		return manifest;
	}

	/**
	 * Advance the persisted analysis generation after a bounded incremental
	 * refinement. Unlike startReanalysis(), this preserves the current derived
	 * corpus because only one already-known function body was added to it.
	 */
	advanceAnalysisGeneration(reason: string, functionAddress?: string, universeSha256?: string): AnalysisSession {
		const target = this.requireBoundTarget();
		const current = this.analysisSession ?? createAnalysisSession({
			id: `session:${crypto.randomUUID()}`,
			targetId: target.id,
			generation: 0,
		});
		const next = createAnalysisSession({
			id: current.id,
			targetId: target.id,
			generation: current.generation + 1,
			parentGeneration: current.generation,
			createdAt: current.createdAt,
			engines: current.engines,
		});
		this.analysisSession = next;
		this.setMeta('analysis_session_json', JSON.stringify(next));
		this.setMeta('analysis_generation_counter', String(next.generation));
		this.setMeta('analysis_last_incremental_update_json', JSON.stringify({
			reason,
			...(functionAddress ? { functionAddress } : {}),
			generation: next.generation,
			...(universeSha256 ? { universeSha256 } : {}),
			updatedAt: new Date().toISOString(),
		}));
		if (universeSha256) {
			this.setMeta('analysis_generation_universe_json', JSON.stringify({
				generation: next.generation,
				universeSha256,
			}));
		}
		if (functionAddress) {
			this.semanticStore.getWholeProgramPropagationStore().markDirty(
				[this.propagationFunctionIdentity(functionAddress)],
				next.generation,
				`analysis-generation:${reason}`,
			);
		}
		return next;
	}

	/**
	 * Begin a whole-binary reanalysis: the session advances to generation N+1
	 * with parentGeneration N, the counter is persisted, and every derived
	 * (non-user) fact is invalidated. User annotations (renames, retypes,
	 * comments, bookmarks) are owned by the analyst and survive.
	 */
	startReanalysis(): AnalysisSession {
		const target = this.requireBoundTarget();
		const current = this.analysisSession;
		const next = createAnalysisSession({
			id: current?.id ?? `session:${crypto.randomUUID()}`,
			targetId: target.id,
			generation: (current?.generation ?? -1) + 1,
			parentGeneration: current?.generation,
			createdAt: current?.createdAt,
			engines: current?.engines ?? [],
		});
		this.db.exec('BEGIN IMMEDIATE');
		try {
			this.semanticStore.getReferenceGraph().invalidateAllDerived(
				next.generation,
				`whole-binary-reanalysis:generation:${next.generation}`,
			);
			this.semanticStore.getWholeProgramPropagationStore().markAllDirty(
				next.generation,
				`whole-binary-reanalysis:generation:${next.generation}`,
			);
			this.setMeta('analysis_session_json', JSON.stringify(next));
			this.setMeta('analysis_generation_counter', String(next.generation));
			this.db.exec(`
				DELETE FROM analyze_cache;
				DELETE FROM investigation_findings;
				DELETE FROM investigations;
			`);
			this.db.exec('COMMIT');
		} catch (error) {
			try { this.db.exec('ROLLBACK'); } catch { /* preserve the original failure */ }
			throw error;
		}
		this.analysisSession = next;
		return next;
	}

	/**
	 * Selective invalidation for a single-function reanalysis: only facts that
	 * depend on the function are removed (its analyze-cache row and unsaved
	 * findings bound to it). Saved findings, annotations, and every other
	 * function's facts survive.
	 * `functionAddress` must use the same canonical string form the engine
	 * writes into analyze_cache/function_address.
	 */
	invalidateFunction(functionAddress: string): FunctionInvalidationResult {
		const address = functionAddress.trim();
		if (!address) {
			throw new Error('invalidateFunction requires a function address');
		}
		this.db.exec('BEGIN IMMEDIATE');
		try {
			const invalidatedReferenceEdges = this.semanticStore.getReferenceGraph().invalidateFunction(
				address,
				this.analysisSession?.generation ?? 0,
				`function-reanalysis:${address}`,
			);
			this.semanticStore.getWholeProgramPropagationStore().markDirty(
				[this.propagationFunctionIdentity(address)],
				this.analysisSession?.generation ?? 0,
				`function-reanalysis:${address}`,
			);
			const removedCachedFunctions = this.db.prepare(
				`DELETE FROM analyze_cache WHERE address = ?`
			).run(address).changes;
			const removedFindings = this.db.prepare(
				`DELETE FROM investigation_findings WHERE function_address = ? AND saved = 0`
			).run(address).changes;
			// Keep recorded investigation counts honest after selective removal.
			this.db.exec(`
				UPDATE investigations SET result_count = (
					SELECT COUNT(*) FROM investigation_findings
					WHERE investigation_findings.investigation_id = investigations.id
				)
			`);
			this.db.exec('COMMIT');
			return { removedCachedFunctions, removedFindings, invalidatedReferenceEdges };
		} catch (error) {
			try { this.db.exec('ROLLBACK'); } catch { /* preserve the original failure */ }
			throw error;
		}
	}

	/**
	 * Record the engine manifest and settings that produced this session.
	 * The manifest is also reflected into the persisted AnalysisSession so
	 * provenance consumers can resolve producer identities against it.
	 */
	recordEngineManifest(
		engines: readonly AnalysisEngineIdentity[],
		settings?: Record<string, unknown>,
	): EngineManifestRecord {
		const target = this.requireBoundTarget();
		const current = this.analysisSession ?? createAnalysisSession({
			id: `session:${crypto.randomUUID()}`,
			targetId: target.id,
			generation: 0,
		});
		const record: EngineManifestRecord = {
			engines: engines.map(engine => ({ ...engine })),
			...(settings ? { settings: { ...settings } } : {}),
			recordedAt: new Date().toISOString(),
		};
		this.setMeta('analysis_engines_json', JSON.stringify(record));
		this.analysisSession = createAnalysisSession({
			id: current.id,
			targetId: target.id,
			generation: current.generation,
			createdAt: current.createdAt,
			parentGeneration: current.parentGeneration,
			engines: record.engines,
		});
		this.setMeta('analysis_session_json', JSON.stringify(this.analysisSession));
		return record;
	}

	getEngineManifest(): EngineManifestRecord | undefined {
		const serialized = this.getMeta('analysis_engines_json');
		if (!serialized) {
			return undefined;
		}
		try {
			const candidate = JSON.parse(serialized) as Partial<EngineManifestRecord>;
			if (!Array.isArray(candidate.engines) || typeof candidate.recordedAt !== 'string') {
				return undefined;
			}
			return {
				engines: candidate.engines as AnalysisEngineIdentity[],
				...(candidate.settings ? { settings: candidate.settings } : {}),
				recordedAt: candidate.recordedAt,
			};
		} catch {
			return undefined;
		}
	}

	/**
	 * Compare the currently installed engines against the recorded manifest.
	 * Drift is reported as diagnostics, never as a restore failure: old
	 * results remain valid evidence of what those engine versions produced.
	 */
	diffEngineManifest(current: readonly AnalysisEngineIdentity[]): string[] {
		const recorded = this.getEngineManifest();
		if (!recorded) {
			return ['no engine manifest recorded for this session'];
		}
		const recordedById = new Map(recorded.engines.map(engine => [engine.id, engine]));
		const currentById = new Map(current.map(engine => [engine.id, engine]));
		const drift: string[] = [];
		for (const [id, recordedEngine] of recordedById) {
			const currentEngine = currentById.get(id);
			if (!currentEngine) {
				drift.push(`${id}: recorded ${recordedEngine.version} is no longer installed`);
				continue;
			}
			if (currentEngine.version !== recordedEngine.version) {
				drift.push(`${id}: recorded ${recordedEngine.version}, installed ${currentEngine.version}`);
			}
			if (recordedEngine.buildSha256 && currentEngine.buildSha256 &&
				recordedEngine.buildSha256 !== currentEngine.buildSha256) {
				drift.push(`${id}: build hash changed for version ${currentEngine.version}`);
			}
		}
		for (const id of currentById.keys()) {
			if (!recordedById.has(id)) {
				drift.push(`${id}: installed after the session manifest was recorded`);
			}
		}
		return drift;
	}

	private requireBoundTarget(): AnalysisTarget {
		if (!this.analysisTarget) {
			throw new Error('No analysis target is bound to this session store');
		}
		return this.analysisTarget;
	}

	private restoreAnalysisSession(targetId: string): AnalysisSession | undefined {
		const serialized = this.getMeta('analysis_session_json');
		if (!serialized) {
			return undefined;
		}
		try {
			const candidate = JSON.parse(serialized) as Partial<AnalysisSession>;
			if (candidate.contractVersion !== ANALYSIS_CONTRACT_VERSION ||
				candidate.targetId !== targetId ||
				typeof candidate.id !== 'string' ||
				typeof candidate.generation !== 'number' ||
				typeof candidate.createdAt !== 'string' ||
				!Array.isArray(candidate.engines)) {
				return undefined;
			}
			return createAnalysisSession({
				id: candidate.id,
				targetId,
				generation: candidate.generation,
				createdAt: candidate.createdAt,
				parentGeneration: candidate.parentGeneration,
				engines: candidate.engines,
			});
		} catch {
			return undefined;
		}
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

export interface PersistedContractState {
	target: AnalysisTarget;
	session: AnalysisSession;
	manifest?: EngineManifestRecord;
	universe?: AnalysisUniverseManifest;
}

/**
 * Read-only peek at the contract state persisted for a binary, without
 * constructing a SessionStore (no hashing, no schema writes, no gitignore).
 * Used by the pipeline runner to adopt the target's real session identity
 * into run provenance instead of synthesizing a parallel one.
 * Returns undefined when no readable, self-consistent state exists.
 */
export function peekAnalysisContractState(binaryPath: string): PersistedContractState | undefined {
	const dbPath = path.join(path.dirname(binaryPath), SESSION_DB_FILENAME);
	if (!fs.existsSync(dbPath)) {
		return undefined;
	}
	let db: SqliteDatabase | undefined;
	try {
		db = loadSqliteModule().openDatabase(dbPath, { readonly: true, fileMustExist: true });
		const readMeta = (key: string): string | undefined => {
			const row = db!.prepare(`SELECT value FROM session_meta WHERE key = ?`).get(key) as { value: string } | undefined;
			return row?.value;
		};
		const targetJson = readMeta('analysis_target_json');
		const sessionJson = readMeta('analysis_session_json');
		if (!targetJson || !sessionJson) {
			return undefined;
		}
		const target = JSON.parse(targetJson) as Partial<AnalysisTarget>;
		const session = JSON.parse(sessionJson) as Partial<AnalysisSession>;
		if (typeof target.id !== 'string' ||
			typeof session.id !== 'string' ||
			session.targetId !== target.id ||
			typeof session.generation !== 'number' ||
			!Array.isArray(session.engines)) {
			return undefined;
		}
		let manifest: EngineManifestRecord | undefined;
		const manifestJson = readMeta('analysis_engines_json');
		if (manifestJson) {
			try {
				const parsed = JSON.parse(manifestJson) as Partial<EngineManifestRecord>;
				if (Array.isArray(parsed.engines) && typeof parsed.recordedAt === 'string') {
					manifest = {
						engines: parsed.engines as AnalysisEngineIdentity[],
						...(parsed.settings ? { settings: parsed.settings } : {}),
						recordedAt: parsed.recordedAt,
					};
				}
			} catch {
				manifest = undefined;
			}
		}
		let universe: AnalysisUniverseManifest | undefined;
		const universeJson = readMeta('analysis_universe_manifest_json');
		const universeBindingJson = readMeta('analysis_generation_universe_json');
		if (universeJson && universeBindingJson) {
			try {
				const parsed = JSON.parse(universeJson) as AnalysisUniverseManifest;
				const binding = JSON.parse(universeBindingJson) as { generation?: unknown; universeSha256?: unknown };
				if (parsed.schemaVersion === 1 && parsed.binarySha256 === target.binarySha256 &&
					Array.isArray(parsed.materializedFunctions) && typeof parsed.universeSha256 === 'string' &&
					binding.generation === session.generation && binding.universeSha256 === parsed.universeSha256) {
					universe = parsed;
				}
			} catch {
				universe = undefined;
			}
		}
		return {
			target: target as AnalysisTarget,
			session: session as AnalysisSession,
			...(manifest ? { manifest } : {}),
			...(universe ? { universe } : {}),
		};
	} catch {
		return undefined;
	} finally {
		try {
			db?.close();
		} catch {
			// best-effort cleanup
		}
	}
}

/**
 * Product version recorded in session_meta. Read from the extension manifest
 * instead of a hardcoded string so the database never lies about who wrote it.
 */
function readProductVersion(): string {
	try {
		const manifestPath = path.join(__dirname, '..', 'package.json');
		const parsed = JSON.parse(fs.readFileSync(manifestPath, 'utf-8')) as { version?: unknown };
		return typeof parsed.version === 'string' && parsed.version.length > 0 ? parsed.version : 'unknown';
	} catch {
		return 'unknown';
	}
}

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

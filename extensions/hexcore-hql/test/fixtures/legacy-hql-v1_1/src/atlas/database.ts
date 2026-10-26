import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { canonicalJson, sha256Hex } from './canonical.js';
import { loadAtlasCanonicalSource, validateAtlasRecord } from './source.js';
import { loadHqlPackageAtlasSource } from './gitSource.js';
import {
  ATLAS_BUILDER_VERSION,
  ATLAS_SCHEMA_VERSION,
  type AtlasBenchmarkRecord,
  type AtlasBuildManifest,
  type AtlasBuildOptions,
  type AtlasCanonicalRecord,
  type AtlasCanonicalSource,
  type AtlasFixtureRecord,
  type AtlasLogicalSnapshot,
  type AtlasMetaRecord,
  type AtlasRowCounts,
  type AtlasRuleRecord,
  type AtlasSqliteDatabase,
  type AtlasSqliteModule,
  type AtlasSourcedRecord,
  type AtlasSupersessionRecord,
  type AtlasTableHashes,
  type AtlasVerificationReport,
} from './types.js';

const SCHEMA_SQL = `
  CREATE TABLE source_files (
    path TEXT PRIMARY KEY,
    raw_sha256 TEXT NOT NULL,
    canonical_sha256 TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    record_count INTEGER NOT NULL CHECK(record_count > 0)
  ) WITHOUT ROWID;

  CREATE TABLE rules (
    rule_id TEXT NOT NULL,
    version TEXT NOT NULL,
    namespace TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_level TEXT NOT NULL,
    severity TEXT NOT NULL,
    name TEXT NOT NULL,
    license TEXT NOT NULL,
    source_path TEXT NOT NULL,
    source_index INTEGER NOT NULL,
    canonical_sha256 TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    PRIMARY KEY(rule_id, version),
    UNIQUE(source_path, source_index),
    FOREIGN KEY(source_path) REFERENCES source_files(path)
  ) WITHOUT ROWID;

  CREATE TABLE fixtures (
    fixture_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    branch TEXT,
    source_path TEXT NOT NULL,
    source_index INTEGER NOT NULL,
    canonical_sha256 TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    UNIQUE(rule_id, rule_version, kind, branch, source_sha256),
    UNIQUE(source_path, source_index),
    FOREIGN KEY(rule_id, rule_version) REFERENCES rules(rule_id, version),
    FOREIGN KEY(source_path) REFERENCES source_files(path)
  ) WITHOUT ROWID;

  CREATE TABLE benchmarks (
    benchmark_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    corpus TEXT NOT NULL,
    corpus_sha256 TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    signature_set_sha256 TEXT NOT NULL,
    precision REAL NOT NULL,
    recall REAL NOT NULL,
    runtime_ms REAL NOT NULL,
    source_path TEXT NOT NULL,
    source_index INTEGER NOT NULL,
    canonical_sha256 TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    UNIQUE(rule_id, rule_version, corpus_sha256, engine_version, signature_set_sha256),
    UNIQUE(source_path, source_index),
    FOREIGN KEY(rule_id, rule_version) REFERENCES rules(rule_id, version),
    FOREIGN KEY(source_path) REFERENCES source_files(path)
  ) WITHOUT ROWID;

  CREATE TABLE supersession (
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    supersedes_rule_id TEXT NOT NULL,
    supersedes_rule_version TEXT NOT NULL,
    reason TEXT NOT NULL,
    source_path TEXT NOT NULL,
    source_index INTEGER NOT NULL,
    canonical_sha256 TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    PRIMARY KEY(rule_id, rule_version, supersedes_rule_id, supersedes_rule_version),
    UNIQUE(source_path, source_index),
    FOREIGN KEY(rule_id, rule_version) REFERENCES rules(rule_id, version),
    FOREIGN KEY(supersedes_rule_id, supersedes_rule_version) REFERENCES rules(rule_id, version),
    FOREIGN KEY(source_path) REFERENCES source_files(path)
  ) WITHOUT ROWID;

  CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    origin TEXT NOT NULL CHECK(origin IN ('canonical', 'derived')),
    source_path TEXT,
    source_index INTEGER,
    canonical_sha256 TEXT,
    canonical_json TEXT,
    CHECK(
      (origin = 'canonical' AND source_path IS NOT NULL AND source_index IS NOT NULL AND canonical_sha256 IS NOT NULL AND canonical_json IS NOT NULL)
      OR
      (origin = 'derived' AND source_path IS NULL AND source_index IS NULL AND canonical_sha256 IS NULL AND canonical_json IS NULL)
    ),
    UNIQUE(source_path, source_index),
    FOREIGN KEY(source_path) REFERENCES source_files(path)
  ) WITHOUT ROWID;

  CREATE INDEX idx_rules_namespace_status ON rules(namespace, status, rule_id, version);
  CREATE INDEX idx_fixtures_rule_kind ON fixtures(rule_id, rule_version, kind, fixture_id);
  CREATE INDEX idx_benchmarks_rule_corpus ON benchmarks(rule_id, rule_version, corpus, benchmark_id);
  CREATE INDEX idx_supersession_old ON supersession(supersedes_rule_id, supersedes_rule_version);
`;

interface CanonicalRow {
  [key: string]: unknown;
  source_path: string;
  source_index: number;
  canonical_sha256: string;
  canonical_json: string;
}

interface SourceRow {
  path: string;
  raw_sha256: string;
  canonical_sha256: string;
  canonical_json: string;
  record_count: number;
}

interface MetaValueRow {
  value_json: string;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function recordSortKey(record: AtlasCanonicalRecord): string {
  switch (record.recordType) {
    case 'rule': return `${record.id}\u0000${record.version}`;
    case 'fixture': return record.id;
    case 'benchmark': return record.id;
    case 'supersession': return [record.ruleId, record.ruleVersion, record.supersedesRuleId, record.supersedesRuleVersion].join('\u0000');
    case 'meta': return record.key;
  }
}

function sortedRecords<T extends AtlasCanonicalRecord>(source: AtlasCanonicalSource, recordType: T['recordType']): AtlasSourcedRecord<T>[] {
  return source.records
    .filter((entry): entry is AtlasSourcedRecord<T> => entry.record.recordType === recordType)
    .sort((left, right) => compareStrings(recordSortKey(left.record), recordSortKey(right.record)));
}

export function createAtlasLogicalSnapshot(source: AtlasCanonicalSource, builderVersion = ATLAS_BUILDER_VERSION): AtlasLogicalSnapshot {
  const project = <T extends AtlasCanonicalRecord>(entry: AtlasSourcedRecord<T>) => ({
    sourcePath: entry.sourcePath,
    sourceIndex: entry.sourceIndex,
    record: entry.record,
  });
  return {
    schemaVersion: ATLAS_SCHEMA_VERSION,
    builderVersion,
    sourceTreeSha256: source.sourceTreeSha256,
    sources: source.files
      .map(file => ({
        path: file.path,
        canonicalSha256: file.canonicalSha256,
        canonicalJson: file.canonicalJson,
        recordCount: file.recordCount,
      }))
      .sort((left, right) => compareStrings(left.path, right.path)),
    rules: sortedRecords<AtlasRuleRecord>(source, 'rule').map(project),
    fixtures: sortedRecords<AtlasFixtureRecord>(source, 'fixture').map(project),
    benchmarks: sortedRecords<AtlasBenchmarkRecord>(source, 'benchmark').map(project),
    supersession: sortedRecords<AtlasSupersessionRecord>(source, 'supersession').map(project),
    meta: sortedRecords<AtlasMetaRecord>(source, 'meta').map(project),
  };
}

function rowCounts(snapshot: AtlasLogicalSnapshot): AtlasRowCounts {
  return {
    rules: snapshot.rules.length,
    fixtures: snapshot.fixtures.length,
    benchmarks: snapshot.benchmarks.length,
    supersession: snapshot.supersession.length,
    meta: snapshot.meta.length,
    sourceFiles: snapshot.sources.length,
  };
}

function tableHashes(snapshot: AtlasLogicalSnapshot): AtlasTableHashes {
  return {
    rules: sha256Hex(canonicalJson(snapshot.rules)),
    fixtures: sha256Hex(canonicalJson(snapshot.fixtures)),
    benchmarks: sha256Hex(canonicalJson(snapshot.benchmarks)),
    supersession: sha256Hex(canonicalJson(snapshot.supersession)),
    meta: sha256Hex(canonicalJson(snapshot.meta)),
    sourceFiles: sha256Hex(canonicalJson(snapshot.sources)),
  };
}

function createManifest(snapshot: AtlasLogicalSnapshot): AtlasBuildManifest {
  return {
    schemaVersion: snapshot.schemaVersion,
    builderVersion: snapshot.builderVersion,
    sourceTreeSha256: snapshot.sourceTreeSha256,
    logicalSha256: sha256Hex(canonicalJson(snapshot)),
    rowCounts: rowCounts(snapshot),
    tableSha256: tableHashes(snapshot),
  };
}

function insertSource(db: AtlasSqliteDatabase, source: AtlasCanonicalSource, manifest: AtlasBuildManifest): void {
  const sourceInsert = db.prepare(
    'INSERT INTO source_files(path, raw_sha256, canonical_sha256, canonical_json, record_count) VALUES (?, ?, ?, ?, ?)',
  );
  for (const file of source.files.sort((left, right) => compareStrings(left.path, right.path))) {
    sourceInsert.run(file.path, file.rawSha256, file.canonicalSha256, file.canonicalJson, file.recordCount);
  }

  const ruleInsert = db.prepare(`
    INSERT INTO rules(
      rule_id, version, namespace, status, evidence_level, severity, name, license,
      source_path, source_index, canonical_sha256, canonical_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const fixtureInsert = db.prepare(`
    INSERT INTO fixtures(
      fixture_id, rule_id, rule_version, kind, source_sha256, branch,
      source_path, source_index, canonical_sha256, canonical_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const benchmarkInsert = db.prepare(`
    INSERT INTO benchmarks(
      benchmark_id, rule_id, rule_version, corpus, corpus_sha256, engine_version,
      signature_set_sha256, precision, recall, runtime_ms, source_path, source_index,
      canonical_sha256, canonical_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const supersessionInsert = db.prepare(`
    INSERT INTO supersession(
      rule_id, rule_version, supersedes_rule_id, supersedes_rule_version, reason,
      source_path, source_index, canonical_sha256, canonical_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const canonicalMetaInsert = db.prepare(`
    INSERT INTO meta(key, value_json, origin, source_path, source_index, canonical_sha256, canonical_json)
    VALUES (?, ?, 'canonical', ?, ?, ?, ?)
  `);

  for (const sourced of source.records) {
    const record = sourced.record;
    switch (record.recordType) {
      case 'rule':
        ruleInsert.run(
          record.id, record.version, record.namespace, record.status, record.evidenceLevel, record.severity,
          record.name, record.license, sourced.sourcePath, sourced.sourceIndex, sourced.canonicalSha256, sourced.canonicalJson,
        );
        break;
      case 'fixture':
        fixtureInsert.run(
          record.id, record.ruleId, record.ruleVersion, record.kind, record.sourceSha256, record.branch ?? null,
          sourced.sourcePath, sourced.sourceIndex, sourced.canonicalSha256, sourced.canonicalJson,
        );
        break;
      case 'benchmark':
        benchmarkInsert.run(
          record.id, record.ruleId, record.ruleVersion, record.corpus, record.corpusSha256, record.engineVersion,
          record.signatureSetSha256, record.precision, record.recall, record.runtimeMs, sourced.sourcePath,
          sourced.sourceIndex, sourced.canonicalSha256, sourced.canonicalJson,
        );
        break;
      case 'supersession':
        supersessionInsert.run(
          record.ruleId, record.ruleVersion, record.supersedesRuleId, record.supersedesRuleVersion, record.reason,
          sourced.sourcePath, sourced.sourceIndex, sourced.canonicalSha256, sourced.canonicalJson,
        );
        break;
      case 'meta':
        canonicalMetaInsert.run(
          record.key, canonicalJson(record.value), sourced.sourcePath, sourced.sourceIndex,
          sourced.canonicalSha256, sourced.canonicalJson,
        );
        break;
    }
  }

  const derivedMetaInsert = db.prepare(
    "INSERT INTO meta(key, value_json, origin) VALUES (?, ?, 'derived')",
  );
  derivedMetaInsert.run('atlas.schemaVersion', canonicalJson(manifest.schemaVersion));
  derivedMetaInsert.run('atlas.builderVersion', canonicalJson(manifest.builderVersion));
  derivedMetaInsert.run('atlas.sourceTreeSha256', canonicalJson(manifest.sourceTreeSha256));
  derivedMetaInsert.run('atlas.logicalSha256', canonicalJson(manifest.logicalSha256));
  derivedMetaInsert.run('atlas.rowCounts', canonicalJson(manifest.rowCounts));
  derivedMetaInsert.run('atlas.tableSha256', canonicalJson(manifest.tableSha256));
}

function safeDeleteDatabaseFiles(databasePath: string): void {
  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    try {
      fs.unlinkSync(`${databasePath}${suffix}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
}

function promoteDatabase(tempPath: string, outputPath: string, replaceExisting: boolean): void {
  if (!fs.existsSync(outputPath)) {
    fs.renameSync(tempPath, outputPath);
    return;
  }
  if (!replaceExisting) {
    throw new Error(`Atlas output already exists: ${outputPath}`);
  }

  const backupPath = `${outputPath}.replace-${process.pid}-${randomUUID()}.bak`;
  fs.renameSync(outputPath, backupPath);
  try {
    fs.renameSync(tempPath, outputPath);
    safeDeleteDatabaseFiles(backupPath);
  } catch (error) {
    if (!fs.existsSync(outputPath) && fs.existsSync(backupPath)) {
      fs.renameSync(backupPath, outputPath);
    }
    throw error;
  }
}

/** Build into a temporary database, verify it, then promote it to the requested path. */
export function buildAtlasDatabase(options: AtlasBuildOptions): AtlasBuildManifest {
  const source = options.sourceLayout === 'records'
    ? loadAtlasCanonicalSource(options.sourceRoot)
    : loadHqlPackageAtlasSource(options.sourceRoot);
  const builderVersion = options.builderVersion ?? ATLAS_BUILDER_VERSION;
  const snapshot = createAtlasLogicalSnapshot(source, builderVersion);
  const manifest = createManifest(snapshot);
  const outputPath = path.resolve(options.outputPath);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  const tempPath = path.join(
    path.dirname(outputPath),
    `.${path.basename(outputPath)}.${process.pid}.${randomUUID()}.tmp`,
  );

  let db: AtlasSqliteDatabase | undefined;
  try {
    db = options.sqliteModule.openDatabase(tempPath, { timeout: 5000 });
    db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL;');
    db.exec('BEGIN IMMEDIATE;');
    try {
      db.exec(SCHEMA_SQL);
      insertSource(db, source, manifest);
      db.exec(`PRAGMA user_version = ${ATLAS_SCHEMA_VERSION};`);
      const foreignKeyFailures = db.prepare('PRAGMA foreign_key_check').all();
      if (foreignKeyFailures.length !== 0) {
        throw new Error(`Atlas foreign-key verification failed: ${canonicalJson(foreignKeyFailures)}`);
      }
      db.exec('COMMIT;');
    } catch (error) {
      try { db.exec('ROLLBACK;'); } catch { /* preserve the original error */ }
      throw error;
    }
    db.close();
    db = undefined;

    const verification = verifyAtlasDatabase(tempPath, options.sqliteModule);
    if (!verification.valid || verification.logicalSha256 !== manifest.logicalSha256) {
      throw new Error(`Atlas temporary build failed verification: ${verification.problems.join('; ')}`);
    }
    promoteDatabase(tempPath, outputPath, options.replaceExisting ?? false);
    return manifest;
  } finally {
    try { if (db?.open !== false) db?.close(); } catch { /* best effort */ }
    if (fs.existsSync(tempPath)) safeDeleteDatabaseFiles(tempPath);
  }
}

function parseCanonicalRecordRows(
  db: AtlasSqliteDatabase,
  table: 'rules' | 'fixtures' | 'benchmarks' | 'supersession',
  recordType: AtlasCanonicalRecord['recordType'],
  problems: string[],
): Array<{ sourcePath: string; sourceIndex: number; record: AtlasCanonicalRecord }> {
  const rows = db.prepare(`SELECT * FROM ${table}`).all() as CanonicalRow[];
  return rows.map(row => {
    if (sha256Hex(row.canonical_json) !== row.canonical_sha256) {
      problems.push(`${table} ${row.source_path}[${row.source_index}] canonical SHA-256 mismatch`);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(row.canonical_json) as unknown;
      if (canonicalJson(parsed) !== row.canonical_json) {
        problems.push(`${table} ${row.source_path}[${row.source_index}] stores non-canonical JSON`);
      }
    } catch (error) {
      throw new Error(`${table} ${row.source_path}[${row.source_index}] contains invalid canonical JSON: ${String(error)}`);
    }
    const record = validateAtlasRecord(parsed, `${table}:${row.source_path}[${row.source_index}]`);
    if (record.recordType !== recordType) {
      throw new Error(`${table} contains ${record.recordType} record`);
    }
    verifyIndexedColumns(table, row, record, problems);
    return { sourcePath: row.source_path, sourceIndex: row.source_index, record };
  }).sort((left, right) => compareStrings(recordSortKey(left.record), recordSortKey(right.record)));
}

function verifyIndexedColumns(
  table: 'rules' | 'fixtures' | 'benchmarks' | 'supersession',
  row: CanonicalRow,
  record: AtlasCanonicalRecord,
  problems: string[],
): void {
  const expected: Record<string, unknown> = {};
  if (table === 'rules' && record.recordType === 'rule') {
    Object.assign(expected, {
      rule_id: record.id,
      version: record.version,
      namespace: record.namespace,
      status: record.status,
      evidence_level: record.evidenceLevel,
      severity: record.severity,
      name: record.name,
      license: record.license,
    });
  } else if (table === 'fixtures' && record.recordType === 'fixture') {
    Object.assign(expected, {
      fixture_id: record.id,
      rule_id: record.ruleId,
      rule_version: record.ruleVersion,
      kind: record.kind,
      source_sha256: record.sourceSha256,
      branch: record.branch ?? null,
    });
  } else if (table === 'benchmarks' && record.recordType === 'benchmark') {
    Object.assign(expected, {
      benchmark_id: record.id,
      rule_id: record.ruleId,
      rule_version: record.ruleVersion,
      corpus: record.corpus,
      corpus_sha256: record.corpusSha256,
      engine_version: record.engineVersion,
      signature_set_sha256: record.signatureSetSha256,
      precision: record.precision,
      recall: record.recall,
      runtime_ms: record.runtimeMs,
    });
  } else if (table === 'supersession' && record.recordType === 'supersession') {
    Object.assign(expected, {
      rule_id: record.ruleId,
      rule_version: record.ruleVersion,
      supersedes_rule_id: record.supersedesRuleId,
      supersedes_rule_version: record.supersedesRuleVersion,
      reason: record.reason,
    });
  } else {
    problems.push(`${table} index contains incompatible ${record.recordType} record`);
    return;
  }
  for (const [column, value] of Object.entries(expected)) {
    if (row[column] !== value) {
      problems.push(`${table} ${row.source_path}[${row.source_index}] column ${column} disagrees with canonical JSON`);
    }
  }
}

function readMetaValue(db: AtlasSqliteDatabase, key: string): unknown {
  const row = db.prepare("SELECT value_json FROM meta WHERE key = ? AND origin = 'derived'").get(key) as MetaValueRow | undefined;
  if (!row) throw new Error(`Missing derived meta key ${key}`);
  return JSON.parse(row.value_json) as unknown;
}

function readLogicalSnapshot(db: AtlasSqliteDatabase, problems: string[]): AtlasLogicalSnapshot {
  const sourceRows = db.prepare(
    'SELECT path, raw_sha256, canonical_sha256, canonical_json, record_count FROM source_files ORDER BY path',
  ).all() as SourceRow[];
  const sources = sourceRows.map(row => ({
    path: row.path,
    canonicalSha256: row.canonical_sha256,
    canonicalJson: row.canonical_json,
    recordCount: row.record_count,
  }));
  for (const row of sourceRows) {
    if (!/^[a-f0-9]{64}$/.test(row.raw_sha256)) problems.push(`source ${row.path} has invalid raw SHA-256`);
    if (!/^[a-f0-9]{64}$/.test(row.canonical_sha256)) problems.push(`source ${row.path} has invalid canonical SHA-256`);
    try {
      const parsed = JSON.parse(row.canonical_json) as unknown;
      if (canonicalJson(parsed) !== row.canonical_json) problems.push(`source ${row.path} stores non-canonical JSON`);
      if (sha256Hex(row.canonical_json) !== row.canonical_sha256) problems.push(`source ${row.path} canonical SHA-256 mismatch`);
    } catch (error) {
      problems.push(`source ${row.path} has invalid canonical JSON: ${String(error)}`);
    }
  }

  const canonicalMetaRows = db.prepare(
    "SELECT key, value_json, source_path, source_index, canonical_sha256, canonical_json FROM meta WHERE origin = 'canonical'",
  ).all() as CanonicalRow[];
  const meta = canonicalMetaRows.map(row => {
    if (sha256Hex(row.canonical_json) !== row.canonical_sha256) {
      problems.push(`meta ${row.source_path}[${row.source_index}] canonical SHA-256 mismatch`);
    }
    const parsed = JSON.parse(row.canonical_json) as unknown;
    if (canonicalJson(parsed) !== row.canonical_json) {
      problems.push(`meta ${row.source_path}[${row.source_index}] stores non-canonical JSON`);
    }
    const record = validateAtlasRecord(parsed, `meta:${row.source_path}[${row.source_index}]`);
    if (record.recordType !== 'meta') throw new Error('meta table contains non-meta canonical record');
    const fullRow = row as CanonicalRow & { key?: unknown; value_json?: unknown };
    if (fullRow.key !== record.key) problems.push(`meta ${row.source_path}[${row.source_index}] key disagrees with canonical JSON`);
    if (fullRow.value_json !== canonicalJson(record.value)) problems.push(`meta ${row.source_path}[${row.source_index}] value disagrees with canonical JSON`);
    return { sourcePath: row.source_path, sourceIndex: row.source_index, record };
  }).sort((left, right) => compareStrings(left.record.key, right.record.key));

  const rules = parseCanonicalRecordRows(db, 'rules', 'rule', problems) as AtlasLogicalSnapshot['rules'];
  const fixtures = parseCanonicalRecordRows(db, 'fixtures', 'fixture', problems) as AtlasLogicalSnapshot['fixtures'];
  const benchmarks = parseCanonicalRecordRows(db, 'benchmarks', 'benchmark', problems) as AtlasLogicalSnapshot['benchmarks'];
  const supersession = parseCanonicalRecordRows(db, 'supersession', 'supersession', problems) as AtlasLogicalSnapshot['supersession'];

  const fileRecords = new Map<string, Array<{ sourceIndex: number; record: AtlasCanonicalRecord }>>();
  for (const entry of [...rules, ...fixtures, ...benchmarks, ...supersession, ...meta]) {
    const entries = fileRecords.get(entry.sourcePath) ?? [];
    entries.push({ sourceIndex: entry.sourceIndex, record: entry.record });
    fileRecords.set(entry.sourcePath, entries);
  }
  for (const source of sources) {
    const entries = (fileRecords.get(source.path) ?? []).sort((left, right) => left.sourceIndex - right.sourceIndex);
    if (entries.length !== source.recordCount) {
      problems.push(`source ${source.path} record count mismatch: indexed=${entries.length} declared=${source.recordCount}`);
    }
    entries.forEach((entry, index) => {
      if (entry.sourceIndex !== index) problems.push(`source ${source.path} has non-contiguous or duplicate record indexes`);
    });
    fileRecords.delete(source.path);
  }
  for (const orphanPath of fileRecords.keys()) {
    problems.push(`canonical records reference missing source file ${orphanPath}`);
  }

  const computedTreeHash = sha256Hex(canonicalJson(sources));
  const storedTreeHash = readMetaValue(db, 'atlas.sourceTreeSha256');
  if (computedTreeHash !== storedTreeHash) {
    problems.push(`source tree SHA-256 mismatch: stored=${String(storedTreeHash)} computed=${computedTreeHash}`);
  }

  return {
    schemaVersion: readMetaValue(db, 'atlas.schemaVersion') as number,
    builderVersion: readMetaValue(db, 'atlas.builderVersion') as string,
    sourceTreeSha256: computedTreeHash,
    sources,
    rules,
    fixtures,
    benchmarks,
    supersession,
    meta,
  };
}

/** Export logical content. The result is stable even if SQLite page layout changes. */
export function exportAtlasDatabase(databasePath: string, sqliteModule: AtlasSqliteModule): AtlasLogicalSnapshot {
  const db = sqliteModule.openDatabase(path.resolve(databasePath), { readonly: true, fileMustExist: true });
  try {
    return readLogicalSnapshot(db, []);
  } finally {
    db.close();
  }
}

export function exportAtlasDatabaseJson(databasePath: string, sqliteModule: AtlasSqliteModule): string {
  return canonicalJson(exportAtlasDatabase(databasePath, sqliteModule));
}

/** Verify schema metadata, foreign keys, per-record hashes, row counts, and the logical digest. */
export function verifyAtlasDatabase(databasePath: string, sqliteModule: AtlasSqliteModule): AtlasVerificationReport {
  const problems: string[] = [];
  let snapshot: AtlasLogicalSnapshot | undefined;
  let storedLogicalSha256 = '';
  let storedCounts: AtlasRowCounts | undefined;
  let storedTableHashes: AtlasTableHashes | undefined;
  const db = sqliteModule.openDatabase(path.resolve(databasePath), { readonly: true, fileMustExist: true });
  try {
    const foreignKeyFailures = db.prepare('PRAGMA foreign_key_check').all();
    if (foreignKeyFailures.length !== 0) {
      problems.push(`foreign-key violations: ${canonicalJson(foreignKeyFailures)}`);
    }
    snapshot = readLogicalSnapshot(db, problems);
    storedLogicalSha256 = readMetaValue(db, 'atlas.logicalSha256') as string;
    storedCounts = readMetaValue(db, 'atlas.rowCounts') as AtlasRowCounts;
    storedTableHashes = readMetaValue(db, 'atlas.tableSha256') as AtlasTableHashes;
  } catch (error) {
    problems.push(error instanceof Error ? error.message : String(error));
  } finally {
    db.close();
  }

  const fallbackCounts: AtlasRowCounts = {
    rules: 0, fixtures: 0, benchmarks: 0, supersession: 0, meta: 0, sourceFiles: 0,
  };
  if (!snapshot) {
    return {
      valid: false,
      problems,
      schemaVersion: 0,
      builderVersion: '',
      sourceTreeSha256: '',
      logicalSha256: '',
      rowCounts: fallbackCounts,
      tableSha256: {
        rules: '', fixtures: '', benchmarks: '', supersession: '', meta: '', sourceFiles: '',
      },
    };
  }

  const computedManifest = createManifest(snapshot);
  if (snapshot.schemaVersion !== ATLAS_SCHEMA_VERSION) {
    problems.push(`unsupported schema version ${snapshot.schemaVersion}`);
  }
  if (computedManifest.logicalSha256 !== storedLogicalSha256) {
    problems.push(`logical SHA-256 mismatch: stored=${storedLogicalSha256} computed=${computedManifest.logicalSha256}`);
  }
  if (canonicalJson(computedManifest.rowCounts) !== canonicalJson(storedCounts)) {
    problems.push('row counts do not match derived metadata');
  }
  if (canonicalJson(computedManifest.tableSha256) !== canonicalJson(storedTableHashes)) {
    problems.push('table SHA-256 values do not match derived metadata');
  }
  return { ...computedManifest, valid: problems.length === 0, problems };
}

export function assertAtlasDatabase(databasePath: string, sqliteModule: AtlasSqliteModule): AtlasVerificationReport {
  const report = verifyAtlasDatabase(databasePath, sqliteModule);
  if (!report.valid) {
    throw new Error(`Invalid HQL Atlas database: ${report.problems.join('; ')}`);
  }
  return report;
}

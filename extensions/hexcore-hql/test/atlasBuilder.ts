import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createRequire } from 'module';
import {
  assertAtlasDatabase,
  buildAtlasDatabase,
  exportAtlasDatabaseJson,
  loadReleasedAtlasSignatures,
  verifyAtlasDatabase,
} from '../src/atlas/index.js';
import type { AtlasCanonicalRecord, AtlasSqliteDatabase, AtlasSqliteModule } from '../src/atlas/types.js';

const require = createRequire(import.meta.url);
const nativeSqlite = require('hexcore-better-sqlite3') as AtlasSqliteModule;
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);

let openCount = 0;
const injectedSqlite: AtlasSqliteModule = {
  openDatabase(filename, options) {
    openCount++;
    return nativeSqlite.openDatabase(filename, options);
  },
};

const ruleV1: AtlasCanonicalRecord = {
  recordType: 'rule',
  id: 'anti-analysis.timer-loop',
  version: '1.0.0',
  namespace: 'anti-analysis',
  status: 'retired',
  name: 'Timer loop',
  description: 'Structural timer loop signal.',
  author: 'HikariSystem',
  license: 'MIT',
  provenance: { kind: 'internal', source: 'git:rules/anti-analysis.timer-loop.json', path: 'fixture-v1' },
  compatibility: { hql: '>=0.2.0 <1.0.0', helix: '>=0.9.3', hastSchema: 1 },
  architectures: ['x64'],
  formats: ['PE'],
  scopes: ['function'],
  evidenceLevel: 'signal',
  severity: 'low',
  signature: {
    id: 'anti-analysis.timer-loop',
    name: 'Timer loop',
    description: 'Structural timer loop signal.',
    severity: 'low',
    evidenceLevel: 'signal',
    condition: { query: { target: 'CForStmt' } },
  },
  roles: ['source'],
  limitations: ['Does not prove anti-debugging intent.'],
  knownFalsePositives: ['Performance instrumentation.'],
  tags: ['timer'],
};

const ruleV2: AtlasCanonicalRecord = {
  ...ruleV1,
  version: '2.0.0',
  status: 'released',
  provenance: { kind: 'internal', source: 'git:rules/anti-analysis.timer-loop.json', path: 'fixture-v2' },
};

const records: AtlasCanonicalRecord[] = [
  ruleV1,
  ruleV2,
  {
    recordType: 'fixture',
    id: 'timer-loop-positive-for',
    ruleId: 'anti-analysis.timer-loop',
    ruleVersion: '2.0.0',
    kind: 'positive',
    sourceSha256: HASH_A,
    expectedLocations: ['function:timer_probe'],
    branch: 'for-loop',
    architecture: 'x64',
    format: 'PE',
    adapterCoverage: 1,
  },
  {
    recordType: 'fixture',
    id: 'timer-loop-negative-plain',
    ruleId: 'anti-analysis.timer-loop',
    ruleVersion: '2.0.0',
    kind: 'negative',
    sourceSha256: HASH_B,
    expectedLocations: [],
    branch: 'for-loop',
  },
  {
    recordType: 'benchmark',
    id: 'timer-loop-corpus-v1',
    ruleId: 'anti-analysis.timer-loop',
    ruleVersion: '2.0.0',
    corpus: 'atlas-unit-corpus',
    corpusSha256: HASH_C,
    truePositive: 3,
    falsePositive: 1,
    trueNegative: 4,
    falseNegative: 2,
    precision: 0.75,
    recall: 0.6,
    runtimeMs: 12.5,
    engineVersion: '0.2.0',
    signatureSetSha256: HASH_A,
  },
  {
    recordType: 'supersession',
    ruleId: 'anti-analysis.timer-loop',
    ruleVersion: '2.0.0',
    supersedesRuleId: 'anti-analysis.timer-loop',
    supersedesRuleVersion: '1.0.0',
    reason: 'Replaced conjunction-only semantics with a recursive condition.',
  },
  {
    recordType: 'meta',
    key: 'release.channel',
    value: { name: 'test', stable: false },
  },
];

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hql-atlas-test-'));
try {
  const sourceRoot = path.join(root, 'canonical');
  const sourceFile = path.join(sourceRoot, 'records', 'atlas.json');
  fs.mkdirSync(path.dirname(sourceFile), { recursive: true });
  fs.writeFileSync(sourceFile, JSON.stringify(records, null, 2));

  const firstDb = path.join(root, 'atlas-first.db');
  const first = buildAtlasDatabase({
    sourceRoot,
    outputPath: firstDb,
    sqliteModule: injectedSqlite,
    sourceLayout: 'records',
  });
  assert.strictEqual(first.rowCounts.rules, 2);
  assert.strictEqual(first.rowCounts.fixtures, 2);
  assert.strictEqual(first.rowCounts.benchmarks, 1);
  assert.strictEqual(first.rowCounts.supersession, 1);
  assert.strictEqual(first.rowCounts.meta, 1);
  assert.strictEqual(first.rowCounts.sourceFiles, 1);
  assertAtlasDatabase(firstDb, injectedSqlite);
  const firstExport = exportAtlasDatabaseJson(firstDb, injectedSqlite);

  // Formatting is not semantic input: compact JSON must produce the same tree and logical hashes.
  fs.writeFileSync(sourceFile, JSON.stringify(records));
  const secondDb = path.join(root, 'atlas-second.db');
  const second = buildAtlasDatabase({
    sourceRoot,
    outputPath: secondDb,
    sqliteModule: injectedSqlite,
    sourceLayout: 'records',
  });
  assert.strictEqual(second.sourceTreeSha256, first.sourceTreeSha256);
  assert.strictEqual(second.logicalSha256, first.logicalSha256);
  assert.strictEqual(exportAtlasDatabaseJson(secondDb, injectedSqlite), firstExport);

  // The schema contains semantic knowledge only, not per-target analysis state.
  const schemaDb = nativeSqlite.openDatabase(secondDb, { readonly: true, fileMustExist: true });
  const tableRows = schemaDb.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all() as Array<{ name: string }>;
  schemaDb.close();
  assert.deepStrictEqual(tableRows.map(row => row.name), [
    'benchmarks', 'fixtures', 'meta', 'rules', 'source_files', 'supersession',
  ]);

  // Duplicate canonical identity must fail before replacing an accepted database.
  const duplicate = [...records, { ...ruleV2 }];
  fs.writeFileSync(sourceFile, JSON.stringify(duplicate));
  assert.throws(
    () => buildAtlasDatabase({
      sourceRoot,
      outputPath: secondDb,
      sqliteModule: injectedSqlite,
      replaceExisting: true,
      sourceLayout: 'records',
    }),
    /duplicate rule version/,
  );
  assert.strictEqual(assertAtlasDatabase(secondDb, injectedSqlite).logicalSha256, second.logicalSha256);

  // A failure after BEGIN never reaches promotion and leaves no temporary database behind.
  fs.writeFileSync(sourceFile, JSON.stringify(records));
  const failingSqlite: AtlasSqliteModule = {
    openDatabase(filename, options) {
      const db = nativeSqlite.openDatabase(filename, options);
      const wrapper: AtlasSqliteDatabase = {
        exec: sql => db.exec(sql),
        prepare(sql) {
          const statement = db.prepare(sql);
          if (/INSERT INTO fixtures/.test(sql)) {
            return {
              ...statement,
              run() { throw new Error('injected transactional failure'); },
              get: (...params) => statement.get(...params),
              all: (...params) => statement.all(...params),
            };
          }
          return statement;
        },
        close: () => db.close(),
        get open() { return db.open; },
      };
      return wrapper;
    },
  };
  assert.throws(
    () => buildAtlasDatabase({
      sourceRoot,
      outputPath: secondDb,
      sqliteModule: failingSqlite,
      replaceExisting: true,
      sourceLayout: 'records',
    }),
    /injected transactional failure/,
  );
  assert.strictEqual(assertAtlasDatabase(secondDb, injectedSqlite).logicalSha256, second.logicalSha256);
  assert.deepStrictEqual(
    fs.readdirSync(root).filter(name => name.includes('.tmp')),
    [],
    'failed builds must not leave temporary databases',
  );

  // Indexed columns are verified against their canonical record, not trusted independently.
  const indexCorruptDb = nativeSqlite.openDatabase(secondDb);
  indexCorruptDb.prepare('UPDATE rules SET namespace = ? WHERE rule_id = ? AND version = ?')
    .run('wrong-namespace', 'anti-analysis.timer-loop', '2.0.0');
  indexCorruptDb.close();
  const indexCorrupted = verifyAtlasDatabase(secondDb, injectedSqlite);
  assert.strictEqual(indexCorrupted.valid, false);
  assert.ok(indexCorrupted.problems.some(problem => /column namespace disagrees/.test(problem)));

  // A mutated canonical row is observable even when the SQLite file remains readable.
  const corruptDb = nativeSqlite.openDatabase(firstDb);
  corruptDb.prepare('UPDATE rules SET canonical_json = ? WHERE rule_id = ? AND version = ?')
    .run('{"recordType":"rule"}', 'anti-analysis.timer-loop', '2.0.0');
  corruptDb.close();
  const corrupted = verifyAtlasDatabase(firstDb, injectedSqlite);
  assert.strictEqual(corrupted.valid, false);
  assert.ok(corrupted.problems.some(problem => /canonical SHA-256 mismatch|must be a non-empty string/.test(problem)));

  // Production path: derive directly from rules, fixture manifest/cases, and benchmark lock.
  const packageRoot = path.resolve(__dirname, '..');
  const canonicalDb = path.join(root, 'atlas-canonical.db');
  const canonicalBuild = buildAtlasDatabase({
    sourceRoot: packageRoot,
    outputPath: canonicalDb,
    sqliteModule: injectedSqlite,
  });
	assert.deepStrictEqual(canonicalBuild.rowCounts, {
		rules: 12,
		fixtures: 60,
		benchmarks: 8,
		supersession: 0,
		meta: 2,
		sourceFiles: 27,
	});
  assert.strictEqual(assertAtlasDatabase(canonicalDb, injectedSqlite).logicalSha256, canonicalBuild.logicalSha256);
  const runtimeRules = loadReleasedAtlasSignatures(canonicalDb, injectedSqlite);
  assert.strictEqual(runtimeRules.length, 12);
  assert.strictEqual(new Set(runtimeRules.map(rule => rule.id)).size, 12);
  const canonicalExport = exportAtlasDatabaseJson(canonicalDb, injectedSqlite);

  const canonicalRebuildDb = path.join(root, 'atlas-canonical-rebuild.db');
  const canonicalRebuild = buildAtlasDatabase({
    sourceRoot: packageRoot,
    outputPath: canonicalRebuildDb,
    sqliteModule: injectedSqlite,
  });
  assert.strictEqual(canonicalRebuild.sourceTreeSha256, canonicalBuild.sourceTreeSha256);
  assert.strictEqual(canonicalRebuild.logicalSha256, canonicalBuild.logicalSha256);
  assert.strictEqual(exportAtlasDatabaseJson(canonicalRebuildDb, injectedSqlite), canonicalExport);

  assert.ok(openCount >= 17, 'all builder/read paths must use the injected SQLite module');
  console.log(
    `HQL Atlas builder: PASS (${openCount} injected opens, ` +
    `unit=${second.logicalSha256.slice(0, 16)}..., canonical=${canonicalBuild.logicalSha256.slice(0, 16)}...)`,
  );
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

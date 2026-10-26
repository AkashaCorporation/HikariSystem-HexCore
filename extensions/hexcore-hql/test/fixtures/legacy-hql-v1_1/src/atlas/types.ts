export const ATLAS_SCHEMA_VERSION = 1;
export const ATLAS_BUILDER_VERSION = '1.0.0';

export type AtlasRuleStatus = 'nursery' | 'released' | 'retired';
export type AtlasEvidenceLevel = 'signal' | 'candidate' | 'proven';
export type AtlasFixtureKind = 'positive' | 'negative';

export interface AtlasCompatibility {
  hql: string;
  helix?: string;
  hastSchema: number;
}

export interface AtlasProvenance {
  kind: 'internal' | 'derived' | 'external';
  source: string;
  url?: string;
  commit?: string;
  path?: string;
  modified?: boolean;
}

export interface AtlasRuleRecord {
  recordType: 'rule';
  id: string;
  version: string;
  namespace: string;
  status: AtlasRuleStatus;
  name: string;
  description: string;
  author: string;
  license: string;
  provenance: AtlasProvenance;
  compatibility: AtlasCompatibility;
  architectures: string[];
  formats: string[];
  scopes: string[];
  evidenceLevel: AtlasEvidenceLevel;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  signature: unknown;
  roles?: Array<'source' | 'transform' | 'sink' | 'barrier' | 'sanitizer'>;
  limitations?: string[];
  knownFalsePositives?: string[];
  tags?: string[];
}

export interface AtlasFixtureRecord {
  recordType: 'fixture';
  id: string;
  ruleId: string;
  ruleVersion: string;
  kind: AtlasFixtureKind;
  sourceSha256: string;
  expectedLocations: string[];
  branch?: string;
  branchIndex?: number;
  architecture?: string;
  format?: string;
  adapterCoverage?: number;
  notes?: string;
  ast?: unknown;
}

export interface AtlasBenchmarkRecord {
  recordType: 'benchmark';
  id: string;
  ruleId: string;
  ruleVersion: string;
  corpus: string;
  corpusSha256: string;
  truePositive: number;
  falsePositive: number;
  trueNegative: number;
  falseNegative: number;
  precision: number;
  recall: number;
  runtimeMs: number;
  engineVersion: string;
  signatureSetSha256: string;
  notes?: string;
}

export interface AtlasSupersessionRecord {
  recordType: 'supersession';
  ruleId: string;
  ruleVersion: string;
  supersedesRuleId: string;
  supersedesRuleVersion: string;
  reason: string;
}

export interface AtlasMetaRecord {
  recordType: 'meta';
  key: string;
  value: unknown;
}

export type AtlasCanonicalRecord =
  | AtlasRuleRecord
  | AtlasFixtureRecord
  | AtlasBenchmarkRecord
  | AtlasSupersessionRecord
  | AtlasMetaRecord;

export interface AtlasSourceFile {
  path: string;
  rawSha256: string;
  canonicalSha256: string;
  canonicalJson: string;
  recordCount: number;
}

export interface AtlasSourcedRecord<T extends AtlasCanonicalRecord = AtlasCanonicalRecord> {
  record: T;
  sourcePath: string;
  sourceIndex: number;
  canonicalJson: string;
  canonicalSha256: string;
}

export interface AtlasCanonicalSource {
  root: string;
  sourceTreeSha256: string;
  files: AtlasSourceFile[];
  records: AtlasSourcedRecord[];
}

export interface AtlasRowCounts {
  rules: number;
  fixtures: number;
  benchmarks: number;
  supersession: number;
  meta: number;
  sourceFiles: number;
}

export interface AtlasTableHashes {
  rules: string;
  fixtures: string;
  benchmarks: string;
  supersession: string;
  meta: string;
  sourceFiles: string;
}

export interface AtlasLogicalSnapshot {
  schemaVersion: number;
  builderVersion: string;
  sourceTreeSha256: string;
  sources: Array<{ path: string; canonicalSha256: string; canonicalJson: string; recordCount: number }>;
  rules: Array<{ sourcePath: string; sourceIndex: number; record: AtlasRuleRecord }>;
  fixtures: Array<{ sourcePath: string; sourceIndex: number; record: AtlasFixtureRecord }>;
  benchmarks: Array<{ sourcePath: string; sourceIndex: number; record: AtlasBenchmarkRecord }>;
  supersession: Array<{ sourcePath: string; sourceIndex: number; record: AtlasSupersessionRecord }>;
  meta: Array<{ sourcePath: string; sourceIndex: number; record: AtlasMetaRecord }>;
}

export interface AtlasBuildManifest {
  schemaVersion: number;
  builderVersion: string;
  sourceTreeSha256: string;
  logicalSha256: string;
  rowCounts: AtlasRowCounts;
  tableSha256: AtlasTableHashes;
}

export interface AtlasVerificationReport extends AtlasBuildManifest {
  valid: boolean;
  problems: string[];
}

export interface AtlasRunResult {
  changes: number;
  lastInsertRowid?: number | bigint;
}

export interface AtlasSqliteStatement {
  run(...params: unknown[]): AtlasRunResult;
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}

export interface AtlasSqliteDatabase {
  exec(sql: string): unknown;
  prepare(sql: string): AtlasSqliteStatement;
  close(): unknown;
  readonly open?: boolean;
}

export interface AtlasSqliteModule {
  openDatabase(
    filename: string,
    options?: { readonly?: boolean; fileMustExist?: boolean; timeout?: number },
  ): AtlasSqliteDatabase;
}

export interface AtlasBuildOptions {
  sourceRoot: string;
  outputPath: string;
  sqliteModule: AtlasSqliteModule;
  replaceExisting?: boolean;
  builderVersion?: string;
  /** Canonical package layout is the production default; records exists for isolated builder tests/tools. */
  sourceLayout?: 'hql-package' | 'records';
}

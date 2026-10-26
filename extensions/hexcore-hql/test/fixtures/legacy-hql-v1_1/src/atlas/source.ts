import * as fs from 'fs';
import * as path from 'path';
import { canonicalJson, sha256Hex } from './canonical.js';
import { assertValidSignature } from '../signatures/schema.js';
import type {
  AtlasBenchmarkRecord,
  AtlasCanonicalRecord,
  AtlasCanonicalSource,
  AtlasFixtureRecord,
  AtlasMetaRecord,
  AtlasRuleRecord,
  AtlasSourcedRecord,
  AtlasSourceFile,
  AtlasSupersessionRecord,
} from './types.js';

const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const IDENTIFIER = /^[a-z0-9][a-z0-9._-]*$/;
const CASE_IDENTIFIER = /^[a-z0-9][a-z0-9:._-]*$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function fail(source: string, message: string): never {
  throw new Error(`${source}: ${message}`);
}

function exactFields(record: Record<string, unknown>, allowed: readonly string[], source: string): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(record)) {
    if (!allowedSet.has(key)) {
      fail(source, `unknown field ${JSON.stringify(key)}`);
    }
  }
}

function requiredString(record: Record<string, unknown>, key: string, source: string): string {
  const value = record[key];
  if (typeof value !== 'string' || value.trim().length === 0) {
    fail(source, `${key} must be a non-empty string`);
  }
  return value;
}

function optionalString(record: Record<string, unknown>, key: string, source: string): void {
  const value = record[key];
  if (value !== undefined && (typeof value !== 'string' || value.trim().length === 0)) {
    fail(source, `${key} must be a non-empty string when present`);
  }
}

function stringArray(record: Record<string, unknown>, key: string, source: string): string[] {
  const value = record[key];
  if (!Array.isArray(value) || value.some(item => typeof item !== 'string' || item.trim().length === 0)) {
    fail(source, `${key} must be an array of non-empty strings`);
  }
  if (new Set(value).size !== value.length) {
    fail(source, `${key} contains duplicate values`);
  }
  return value as string[];
}

function optionalStringArray(record: Record<string, unknown>, key: string, source: string): void {
  if (record[key] === undefined) {
    return;
  }
  stringArray(record, key, source);
}

function enumValue(record: Record<string, unknown>, key: string, values: readonly string[], source: string): string {
  const value = requiredString(record, key, source);
  if (!values.includes(value)) {
    fail(source, `${key} must be one of ${values.join(', ')}`);
  }
  return value;
}

function boundedNumber(record: Record<string, unknown>, key: string, min: number, max: number, source: string): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) {
    fail(source, `${key} must be a finite number in [${min}, ${max}]`);
  }
  return value;
}

function nonNegativeInteger(record: Record<string, unknown>, key: string, source: string): number {
  const value = record[key];
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    fail(source, `${key} must be a non-negative safe integer`);
  }
  return value as number;
}

function validateIdentifier(value: string, field: string, source: string): void {
  if (!IDENTIFIER.test(value)) {
    fail(source, `${field} must match ${IDENTIFIER.source}`);
  }
}

function validateVersion(value: string, field: string, source: string): void {
  if (!VERSION.test(value)) {
    fail(source, `${field} must be a semantic version`);
  }
}

function validateSha256(value: string, field: string, source: string): void {
  if (!SHA256.test(value)) {
    fail(source, `${field} must be a lowercase SHA-256`);
  }
}

function validateRule(record: Record<string, unknown>, source: string): AtlasRuleRecord {
  exactFields(record, [
    'recordType', 'id', 'version', 'namespace', 'status', 'name', 'description', 'author', 'license',
    'provenance', 'compatibility', 'architectures', 'formats', 'scopes', 'evidenceLevel', 'severity',
    'signature', 'roles', 'limitations', 'knownFalsePositives', 'tags',
  ], source);

  const id = requiredString(record, 'id', source);
  const version = requiredString(record, 'version', source);
  const namespace = requiredString(record, 'namespace', source);
  validateIdentifier(id, 'id', source);
  validateIdentifier(namespace, 'namespace', source);
  validateVersion(version, 'version', source);
  enumValue(record, 'status', ['nursery', 'released', 'retired'], source);
  requiredString(record, 'name', source);
  requiredString(record, 'description', source);
  requiredString(record, 'author', source);
  requiredString(record, 'license', source);
  enumValue(record, 'evidenceLevel', ['signal', 'candidate', 'proven'], source);
  enumValue(record, 'severity', ['info', 'low', 'medium', 'high', 'critical'], source);
  stringArray(record, 'architectures', source);
  stringArray(record, 'formats', source);
  stringArray(record, 'scopes', source);
  optionalStringArray(record, 'roles', source);
  optionalStringArray(record, 'limitations', source);
  optionalStringArray(record, 'knownFalsePositives', source);
  optionalStringArray(record, 'tags', source);

  if (Array.isArray(record.roles)) {
    const validRoles = new Set(['source', 'transform', 'sink', 'barrier', 'sanitizer']);
    if (record.roles.some(role => !validRoles.has(role as string))) {
      fail(source, 'roles contains an unsupported semantic role');
    }
  }

  if (!isObject(record.provenance)) {
    fail(source, 'provenance must be an object');
  }
  exactFields(record.provenance, ['kind', 'source', 'url', 'commit', 'path', 'modified'], `${source}.provenance`);
  enumValue(record.provenance, 'kind', ['internal', 'derived', 'external'], `${source}.provenance`);
  requiredString(record.provenance, 'source', `${source}.provenance`);
  optionalString(record.provenance, 'url', `${source}.provenance`);
  optionalString(record.provenance, 'commit', `${source}.provenance`);
  optionalString(record.provenance, 'path', `${source}.provenance`);
  if (record.provenance.modified !== undefined && typeof record.provenance.modified !== 'boolean') {
    fail(`${source}.provenance`, 'modified must be boolean when present');
  }

  if (!isObject(record.compatibility)) {
    fail(source, 'compatibility must be an object');
  }
  exactFields(record.compatibility, ['hql', 'helix', 'hastSchema'], `${source}.compatibility`);
  requiredString(record.compatibility, 'hql', `${source}.compatibility`);
  optionalString(record.compatibility, 'helix', `${source}.compatibility`);
  nonNegativeInteger(record.compatibility, 'hastSchema', `${source}.compatibility`);
  if (record.compatibility.hastSchema === 0) fail(`${source}.compatibility`, 'hastSchema must be positive');

  if (!isObject(record.signature)) {
    fail(source, 'signature must be a JSON object');
  }
  assertValidSignature(record.signature, `${source}.signature`);
  if (typeof record.signature.id === 'string' && record.signature.id !== id) {
    fail(source, `signature.id ${record.signature.id} does not match rule id ${id}`);
  }

  return record as unknown as AtlasRuleRecord;
}

function validateFixture(record: Record<string, unknown>, source: string): AtlasFixtureRecord {
  exactFields(record, [
    'recordType', 'id', 'ruleId', 'ruleVersion', 'kind', 'sourceSha256', 'expectedLocations',
    'branch', 'branchIndex', 'architecture', 'format', 'adapterCoverage', 'notes', 'ast',
  ], source);
  const id = requiredString(record, 'id', source);
  const ruleId = requiredString(record, 'ruleId', source);
  const ruleVersion = requiredString(record, 'ruleVersion', source);
  if (!CASE_IDENTIFIER.test(id)) fail(source, `id must match ${CASE_IDENTIFIER.source}`);
  validateIdentifier(ruleId, 'ruleId', source);
  validateVersion(ruleVersion, 'ruleVersion', source);
  const kind = enumValue(record, 'kind', ['positive', 'negative'], source);
  const hash = requiredString(record, 'sourceSha256', source);
  validateSha256(hash, 'sourceSha256', source);
  const locations = stringArray(record, 'expectedLocations', source);
  if (kind === 'positive' && locations.length === 0) {
    fail(source, 'positive fixture requires at least one expected location');
  }
  if (kind === 'negative' && locations.length !== 0) {
    fail(source, 'negative fixture cannot declare expected match locations');
  }
  optionalString(record, 'branch', source);
  if (record.branchIndex !== undefined) nonNegativeInteger(record, 'branchIndex', source);
  optionalString(record, 'architecture', source);
  optionalString(record, 'format', source);
  optionalString(record, 'notes', source);
  if (record.adapterCoverage !== undefined) {
    boundedNumber(record, 'adapterCoverage', 0, 1, source);
  }
  if (record.ast !== undefined) canonicalJson(record.ast);
  return record as unknown as AtlasFixtureRecord;
}

function validateBenchmark(record: Record<string, unknown>, source: string): AtlasBenchmarkRecord {
  exactFields(record, [
    'recordType', 'id', 'ruleId', 'ruleVersion', 'corpus', 'corpusSha256', 'truePositive',
    'falsePositive', 'trueNegative', 'falseNegative', 'precision', 'recall', 'runtimeMs',
    'engineVersion', 'signatureSetSha256', 'notes',
  ], source);
  const id = requiredString(record, 'id', source);
  const ruleId = requiredString(record, 'ruleId', source);
  const ruleVersion = requiredString(record, 'ruleVersion', source);
  validateIdentifier(id, 'id', source);
  validateIdentifier(ruleId, 'ruleId', source);
  validateVersion(ruleVersion, 'ruleVersion', source);
  requiredString(record, 'corpus', source);
  validateSha256(requiredString(record, 'corpusSha256', source), 'corpusSha256', source);
  const tp = nonNegativeInteger(record, 'truePositive', source);
  const fp = nonNegativeInteger(record, 'falsePositive', source);
  nonNegativeInteger(record, 'trueNegative', source);
  const fn = nonNegativeInteger(record, 'falseNegative', source);
  const precision = boundedNumber(record, 'precision', 0, 1, source);
  const recall = boundedNumber(record, 'recall', 0, 1, source);
  boundedNumber(record, 'runtimeMs', 0, Number.MAX_SAFE_INTEGER, source);
  requiredString(record, 'engineVersion', source);
  validateSha256(requiredString(record, 'signatureSetSha256', source), 'signatureSetSha256', source);
  optionalString(record, 'notes', source);

  const expectedPrecision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const expectedRecall = tp + fn === 0 ? 0 : tp / (tp + fn);
  if (Math.abs(precision - expectedPrecision) > 1e-9) {
    fail(source, `precision does not match TP/(TP+FP): expected ${expectedPrecision}`);
  }
  if (Math.abs(recall - expectedRecall) > 1e-9) {
    fail(source, `recall does not match TP/(TP+FN): expected ${expectedRecall}`);
  }
  return record as unknown as AtlasBenchmarkRecord;
}

function validateSupersession(record: Record<string, unknown>, source: string): AtlasSupersessionRecord {
  exactFields(record, [
    'recordType', 'ruleId', 'ruleVersion', 'supersedesRuleId', 'supersedesRuleVersion', 'reason',
  ], source);
  const ruleId = requiredString(record, 'ruleId', source);
  const ruleVersion = requiredString(record, 'ruleVersion', source);
  const oldRuleId = requiredString(record, 'supersedesRuleId', source);
  const oldRuleVersion = requiredString(record, 'supersedesRuleVersion', source);
  validateIdentifier(ruleId, 'ruleId', source);
  validateIdentifier(oldRuleId, 'supersedesRuleId', source);
  validateVersion(ruleVersion, 'ruleVersion', source);
  validateVersion(oldRuleVersion, 'supersedesRuleVersion', source);
  requiredString(record, 'reason', source);
  if (ruleId === oldRuleId && ruleVersion === oldRuleVersion) {
    fail(source, 'a rule version cannot supersede itself');
  }
  return record as unknown as AtlasSupersessionRecord;
}

function validateMeta(record: Record<string, unknown>, source: string): AtlasMetaRecord {
  exactFields(record, ['recordType', 'key', 'value'], source);
  const key = requiredString(record, 'key', source);
  if (key.startsWith('atlas.')) {
    fail(source, 'meta keys beginning with "atlas." are reserved for the derived database');
  }
  canonicalJson(record.value);
  return record as unknown as AtlasMetaRecord;
}

export function validateAtlasRecord(value: unknown, source: string): AtlasCanonicalRecord {
  if (!isObject(value)) {
    fail(source, 'record must be a JSON object');
  }
  switch (value.recordType) {
    case 'rule': return validateRule(value, source);
    case 'fixture': return validateFixture(value, source);
    case 'benchmark': return validateBenchmark(value, source);
    case 'supersession': return validateSupersession(value, source);
    case 'meta': return validateMeta(value, source);
    default: fail(source, 'recordType must be rule, fixture, benchmark, supersession, or meta');
  }
}

function collectJsonFiles(root: string): string[] {
  const files: string[] = [];
  const visit = (directory: string): void => {
    const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        fail(absolute, 'symbolic links are not permitted in canonical Atlas inputs');
      }
      if (entry.isDirectory()) {
        visit(absolute);
      } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.json')) {
        files.push(absolute);
      }
    }
  };
  visit(root);
  return files;
}

function ruleKey(ruleId: string, ruleVersion: string): string {
  return `${ruleId}\u0000${ruleVersion}`;
}

function validateCrossReferences(records: AtlasSourcedRecord[]): void {
  const rules = new Map<string, AtlasSourcedRecord<AtlasRuleRecord>>();
  const fixtures = new Map<string, AtlasSourcedRecord<AtlasFixtureRecord>>();
  const fixtureNaturalKeys = new Set<string>();
  const benchmarks = new Map<string, AtlasSourcedRecord<AtlasBenchmarkRecord>>();
  const benchmarkNaturalKeys = new Set<string>();
  const supersessionEdges = new Set<string>();
  const meta = new Set<string>();

  const duplicate = (kind: string, key: string, first: AtlasSourcedRecord, second: AtlasSourcedRecord): never => {
    fail(`${second.sourcePath}[${second.sourceIndex}]`, `duplicate ${kind} ${JSON.stringify(key)}; first defined at ${first.sourcePath}[${first.sourceIndex}]`);
  };

  for (const sourced of records) {
    const record = sourced.record;
    if (record.recordType === 'rule') {
      const key = ruleKey(record.id, record.version);
      const first = rules.get(key);
      if (first) duplicate('rule version', `${record.id}@${record.version}`, first, sourced);
      rules.set(key, sourced as AtlasSourcedRecord<AtlasRuleRecord>);
    } else if (record.recordType === 'fixture') {
      const first = fixtures.get(record.id);
      if (first) duplicate('fixture id', record.id, first, sourced);
      fixtures.set(record.id, sourced as AtlasSourcedRecord<AtlasFixtureRecord>);
      const natural = [record.ruleId, record.ruleVersion, record.kind, record.branch ?? '', record.sourceSha256].join('\u0000');
      if (fixtureNaturalKeys.has(natural)) fail(`${sourced.sourcePath}[${sourced.sourceIndex}]`, 'duplicate fixture content key');
      fixtureNaturalKeys.add(natural);
    } else if (record.recordType === 'benchmark') {
      const first = benchmarks.get(record.id);
      if (first) duplicate('benchmark id', record.id, first, sourced);
      benchmarks.set(record.id, sourced as AtlasSourcedRecord<AtlasBenchmarkRecord>);
      const natural = [record.ruleId, record.ruleVersion, record.corpusSha256, record.engineVersion, record.signatureSetSha256].join('\u0000');
      if (benchmarkNaturalKeys.has(natural)) fail(`${sourced.sourcePath}[${sourced.sourceIndex}]`, 'duplicate benchmark content key');
      benchmarkNaturalKeys.add(natural);
    } else if (record.recordType === 'supersession') {
      const edge = [record.ruleId, record.ruleVersion, record.supersedesRuleId, record.supersedesRuleVersion].join('\u0000');
      if (supersessionEdges.has(edge)) fail(`${sourced.sourcePath}[${sourced.sourceIndex}]`, 'duplicate supersession edge');
      supersessionEdges.add(edge);
    } else {
      if (meta.has(record.key)) fail(`${sourced.sourcePath}[${sourced.sourceIndex}]`, `duplicate meta key ${record.key}`);
      meta.add(record.key);
    }
  }

  for (const sourced of records) {
    const record = sourced.record;
    if (record.recordType === 'fixture' || record.recordType === 'benchmark') {
      if (!rules.has(ruleKey(record.ruleId, record.ruleVersion))) {
        fail(`${sourced.sourcePath}[${sourced.sourceIndex}]`, `references missing rule ${record.ruleId}@${record.ruleVersion}`);
      }
    } else if (record.recordType === 'supersession') {
      const newer = ruleKey(record.ruleId, record.ruleVersion);
      const older = ruleKey(record.supersedesRuleId, record.supersedesRuleVersion);
      if (!rules.has(newer)) fail(`${sourced.sourcePath}[${sourced.sourceIndex}]`, `references missing rule ${record.ruleId}@${record.ruleVersion}`);
      if (!rules.has(older)) fail(`${sourced.sourcePath}[${sourced.sourceIndex}]`, `references missing superseded rule ${record.supersedesRuleId}@${record.supersedesRuleVersion}`);
    }
  }

  const graph = new Map<string, string[]>();
  for (const sourced of records) {
    if (sourced.record.recordType !== 'supersession') continue;
    const record = sourced.record;
    const newer = ruleKey(record.ruleId, record.ruleVersion);
    const older = ruleKey(record.supersedesRuleId, record.supersedesRuleVersion);
    graph.set(newer, [...(graph.get(newer) ?? []), older]);
  }
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (key: string): void => {
    if (visiting.has(key)) fail('supersession', 'supersession graph contains a cycle');
    if (visited.has(key)) return;
    visiting.add(key);
    for (const target of graph.get(key) ?? []) visit(target);
    visiting.delete(key);
    visited.add(key);
  };
  for (const key of graph.keys()) visit(key);
}

export function assertAtlasRecordSet(records: AtlasSourcedRecord[]): void {
  validateCrossReferences(records);
}

/** Load reviewable JSON records from a Git tree and derive its format-insensitive semantic hash. */
export function loadAtlasCanonicalSource(sourceRoot: string): AtlasCanonicalSource {
  const root = path.resolve(sourceRoot);
  if (!fs.statSync(root).isDirectory()) {
    fail(root, 'sourceRoot must be a directory');
  }

  const files: AtlasSourceFile[] = [];
  const records: AtlasSourcedRecord[] = [];
  for (const absolutePath of collectJsonFiles(root)) {
    const relativePath = path.relative(root, absolutePath).split(path.sep).join('/');
    const bytes = fs.readFileSync(absolutePath);
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytes.toString('utf8')) as unknown;
    } catch (error) {
      fail(relativePath, `invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
    const values = Array.isArray(parsed) ? parsed : [parsed];
    if (values.length === 0) {
      fail(relativePath, 'record file cannot be an empty array');
    }
    values.forEach((value, sourceIndex) => {
      const record = validateAtlasRecord(value, `${relativePath}[${sourceIndex}]`);
      const recordJson = canonicalJson(record);
      records.push({
        record,
        sourcePath: relativePath,
        sourceIndex,
        canonicalJson: recordJson,
        canonicalSha256: sha256Hex(recordJson),
      });
    });
    files.push({
      path: relativePath,
      rawSha256: sha256Hex(bytes),
      canonicalSha256: sha256Hex(canonicalJson(values)),
      canonicalJson: canonicalJson(values),
      recordCount: values.length,
    });
  }
  if (records.length === 0) {
    fail(root, 'canonical Atlas tree contains no JSON records');
  }

  validateCrossReferences(records);
  const semanticManifest = files.map(file => ({
    path: file.path,
    canonicalSha256: file.canonicalSha256,
    canonicalJson: file.canonicalJson,
    recordCount: file.recordCount,
  }));
  return {
    root,
    files,
    records,
    sourceTreeSha256: sha256Hex(canonicalJson(semanticManifest)),
  };
}

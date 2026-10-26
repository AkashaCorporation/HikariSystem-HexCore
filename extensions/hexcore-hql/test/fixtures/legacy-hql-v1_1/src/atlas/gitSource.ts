import * as fs from 'fs';
import * as path from 'path';
import { assertValidSignature } from '../signatures/schema.js';
import type { HQLSignature } from '../types/hql.js';
import { canonicalJson, sha256Hex } from './canonical.js';
import { assertAtlasRecordSet, validateAtlasRecord } from './source.js';
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
const GIT_COMMIT = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/;
const CASE_ID = /^[a-z0-9][a-z0-9:._-]*$/;
const VERSIONED_RULE = /^([a-z0-9][a-z0-9._-]*)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/;

interface ManagedSignature extends HQLSignature {
  version: string;
  namespace: string;
  status: 'nursery' | 'released' | 'retired';
  author: string;
  license: string;
  provenance: NonNullable<HQLSignature['provenance']>;
  compatibility: NonNullable<HQLSignature['compatibility']>;
  fixtures?: { manifest: string };
}

interface FixtureManifest {
  schemaVersion: 1;
  corpusId: string;
  expectedSignatureCount: number;
  expectedCaseCount: number;
  fixtureFiles: Array<{ path: string; canonicalFileSha256: string }>;
}

interface FixtureCase {
  caseId: string;
  branchId: string;
  branchIndex?: number;
  expectMatch: boolean;
  expectedMatchLocations: string[];
  contentSha256: string;
  ast: unknown;
}

interface FixtureFile {
  schemaVersion: 1;
  signatureId: string;
  cases: FixtureCase[];
}

interface ThirdPartyLock {
  schemaVersion: 1;
  generatedAt: string;
  tools: Array<{
    id: string;
    version: string;
    ref: string;
    commit: string;
    repository: string;
    license: string;
  }>;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function fail(source: string, message: string): never {
  throw new Error(`${source}: ${message}`);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], source: string): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(source, `unknown field ${JSON.stringify(key)}`);
  }
}

function safeRelativePath(root: string, relativePath: string, source: string): string {
  if (path.isAbsolute(relativePath) || relativePath.split(/[\\/]/).includes('..')) {
    fail(source, `unsafe relative path ${JSON.stringify(relativePath)}`);
  }
  const absolute = path.resolve(root, relativePath);
  if (absolute !== root && !absolute.startsWith(`${root}${path.sep}`)) {
    fail(source, `path escapes canonical root: ${relativePath}`);
  }
  return absolute;
}

function slashPath(root: string, absolutePath: string): string {
  return path.relative(root, absolutePath).split(path.sep).join('/');
}

function collectFiles(directory: string, predicate: (name: string) => boolean): string[] {
  const files: string[] = [];
  const visit = (current: string): void => {
    const entries = fs.readdirSync(current, { withFileTypes: true })
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of entries) {
      const absolute = path.join(current, entry.name);
      if (entry.isSymbolicLink()) fail(absolute, 'symbolic links are not canonical Atlas inputs');
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && predicate(entry.name)) files.push(absolute);
    }
  };
  visit(directory);
  return files;
}

function readJson(absolutePath: string, source: string): { bytes: Buffer; parsed: unknown; canonical: string } {
  const bytes = fs.readFileSync(absolutePath);
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString('utf8')) as unknown;
  } catch (error) {
    fail(source, `invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  const canonical = canonicalJson(parsed);
  return { bytes, parsed, canonical };
}

function requireManagedSignature(value: unknown, source: string): ManagedSignature {
  assertValidSignature(value, source);
  const signature = value as HQLSignature;
  for (const field of ['version', 'namespace', 'status', 'author', 'license', 'provenance', 'compatibility'] as const) {
    if (signature[field] === undefined) fail(source, `${field} is required for an Atlas rule`);
  }
  return signature as ManagedSignature;
}

function createRuleRecord(signature: ManagedSignature): AtlasRuleRecord {
  return {
    recordType: 'rule',
    id: signature.id,
    version: signature.version,
    namespace: signature.namespace,
    status: signature.status,
    name: signature.name,
    description: signature.description,
    author: signature.author,
    license: signature.license,
    provenance: signature.provenance,
    compatibility: signature.compatibility,
    architectures: ['any'],
    formats: ['any'],
    scopes: ['function'],
    evidenceLevel: signature.evidenceLevel ?? 'signal',
    severity: signature.severity,
    signature,
    ...(signature.limitations ? { limitations: signature.limitations } : {}),
  };
}

function sourcedRecord<T extends AtlasCanonicalRecord>(record: T, sourcePath: string, sourceIndex: number): AtlasSourcedRecord<T> {
  const validated = validateAtlasRecord(record, `${sourcePath}[${sourceIndex}]`) as T;
  const json = canonicalJson(validated);
  return {
    record: validated,
    sourcePath,
    sourceIndex,
    canonicalJson: json,
    canonicalSha256: sha256Hex(json),
  };
}

function parseFixtureManifest(value: unknown, source: string): FixtureManifest {
  if (!isObject(value)) fail(source, 'fixture manifest must be an object');
  exactKeys(value, ['schemaVersion', 'corpusId', 'expectedSignatureCount', 'expectedCaseCount', 'fixtureFiles'], source);
  if (value.schemaVersion !== 1) fail(source, 'schemaVersion must be 1');
  if (typeof value.corpusId !== 'string' || value.corpusId.length === 0) fail(source, 'corpusId must be non-empty');
  if (!Number.isSafeInteger(value.expectedSignatureCount) || Number(value.expectedSignatureCount) < 0) fail(source, 'expectedSignatureCount must be non-negative');
  if (!Number.isSafeInteger(value.expectedCaseCount) || Number(value.expectedCaseCount) < 0) fail(source, 'expectedCaseCount must be non-negative');
  if (!Array.isArray(value.fixtureFiles)) fail(source, 'fixtureFiles must be an array');
  const seenPaths = new Set<string>();
  for (const [index, entry] of value.fixtureFiles.entries()) {
    if (!isObject(entry)) fail(`${source}.fixtureFiles[${index}]`, 'entry must be an object');
    exactKeys(entry, ['path', 'canonicalFileSha256'], `${source}.fixtureFiles[${index}]`);
    if (typeof entry.path !== 'string' || entry.path.length === 0 || path.isAbsolute(entry.path) || entry.path.split(/[\\/]/).includes('..')) {
      fail(`${source}.fixtureFiles[${index}]`, 'path must be a safe relative path');
    }
    if (typeof entry.canonicalFileSha256 !== 'string' || !SHA256.test(entry.canonicalFileSha256)) {
      fail(`${source}.fixtureFiles[${index}]`, 'canonicalFileSha256 must be lowercase SHA-256');
    }
    if (seenPaths.has(entry.path)) fail(source, `duplicate fixture path ${entry.path}`);
    seenPaths.add(entry.path);
  }
  return value as unknown as FixtureManifest;
}

function parseFixtureFile(value: unknown, source: string): FixtureFile {
  if (!isObject(value)) fail(source, 'fixture file must be an object');
  exactKeys(value, ['schemaVersion', 'signatureId', 'cases'], source);
  if (value.schemaVersion !== 1) fail(source, 'schemaVersion must be 1');
  if (typeof value.signatureId !== 'string' || value.signatureId.length === 0) fail(source, 'signatureId must be non-empty');
  if (!Array.isArray(value.cases) || value.cases.length === 0) fail(source, 'cases must be a non-empty array');
  const seenCases = new Set<string>();
  for (const [index, entry] of value.cases.entries()) {
    const caseSource = `${source}.cases[${index}]`;
    if (!isObject(entry)) fail(caseSource, 'case must be an object');
    exactKeys(entry, ['caseId', 'branchId', 'branchIndex', 'expectMatch', 'expectedMatchLocations', 'contentSha256', 'ast'], caseSource);
    if (typeof entry.caseId !== 'string' || !CASE_ID.test(entry.caseId)) fail(caseSource, 'invalid persistent caseId');
    if (seenCases.has(entry.caseId)) fail(caseSource, `duplicate caseId ${entry.caseId}`);
    seenCases.add(entry.caseId);
    if (typeof entry.branchId !== 'string' || entry.branchId.length === 0) fail(caseSource, 'branchId must be non-empty');
    if (entry.branchIndex !== undefined && (!Number.isSafeInteger(entry.branchIndex) || Number(entry.branchIndex) < 0)) fail(caseSource, 'branchIndex must be non-negative');
    if (typeof entry.expectMatch !== 'boolean') fail(caseSource, 'expectMatch must be boolean');
    if (!Array.isArray(entry.expectedMatchLocations) || entry.expectedMatchLocations.some(location => typeof location !== 'string' || location.length === 0)) {
      fail(caseSource, 'expectedMatchLocations must be an array of non-empty strings');
    }
    if (new Set(entry.expectedMatchLocations).size !== entry.expectedMatchLocations.length) fail(caseSource, 'expected match locations must be unique');
    if ((entry.expectedMatchLocations.length > 0) !== entry.expectMatch) fail(caseSource, 'positive cases require locations and negative cases require none');
    if (typeof entry.contentSha256 !== 'string' || !SHA256.test(entry.contentSha256)) fail(caseSource, 'contentSha256 must be lowercase SHA-256');
    if (sha256Hex(canonicalJson(entry.ast)) !== entry.contentSha256) fail(caseSource, 'AST canonical SHA-256 mismatch');
  }
  return value as unknown as FixtureFile;
}

function assertFixtureGate(signature: ManagedSignature, fixture: FixtureFile, source: string): void {
  if (fixture.signatureId !== signature.id) fail(source, `signatureId ${fixture.signatureId} does not match ${signature.id}`);
  const branches = signature.condition && 'any' in signature.condition ? signature.condition.any.length : undefined;
  if (branches !== undefined) {
    for (const fixtureCase of fixture.cases) {
      if (!Number.isSafeInteger(fixtureCase.branchIndex) || fixtureCase.branchIndex! < 0 || fixtureCase.branchIndex! >= branches) {
        fail(source, `${fixtureCase.caseId} has invalid branchIndex`);
      }
    }
    for (let index = 0; index < branches; index++) {
      const branchCases = fixture.cases.filter(entry => entry.branchIndex === index);
      if (!branchCases.some(entry => entry.expectMatch)) fail(source, `branch ${index} lacks a positive fixture`);
      if (branchCases.filter(entry => !entry.expectMatch).length < 2) fail(source, `branch ${index} requires two negative fixtures`);
      if (new Set(branchCases.map(entry => entry.branchId)).size !== 1) fail(source, `branch ${index} has unstable branchId`);
    }
    return;
  }
  if (fixture.cases.some(entry => entry.branchIndex !== undefined)) fail(source, 'non-any rule cannot declare branchIndex');
  if (fixture.cases.some(entry => entry.branchId !== 'rule')) fail(source, 'non-any rule branchId must be "rule"');
  if (!fixture.cases.some(entry => entry.expectMatch)) fail(source, 'rule lacks a positive fixture');
  if (fixture.cases.filter(entry => !entry.expectMatch).length < 2) fail(source, 'rule requires two negative fixtures');
}

function parseThirdPartyLock(value: unknown, source: string): ThirdPartyLock {
  if (!isObject(value)) fail(source, 'third-party lock must be an object');
  exactKeys(value, ['schemaVersion', 'generatedAt', 'tools'], source);
  if (value.schemaVersion !== 1) fail(source, 'schemaVersion must be 1');
  if (typeof value.generatedAt !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value.generatedAt)) fail(source, 'generatedAt must be YYYY-MM-DD');
  if (!Array.isArray(value.tools) || value.tools.length === 0) fail(source, 'tools must be a non-empty array');
  const ids = new Set<string>();
  for (const [index, tool] of value.tools.entries()) {
    const toolSource = `${source}.tools[${index}]`;
    if (!isObject(tool)) fail(toolSource, 'tool must be an object');
    exactKeys(tool, ['id', 'version', 'ref', 'commit', 'repository', 'license'], toolSource);
    for (const field of ['id', 'version', 'ref', 'repository', 'license'] as const) {
      if (typeof tool[field] !== 'string' || tool[field].length === 0) fail(toolSource, `${field} must be non-empty`);
    }
    if (ids.has(tool.id as string)) fail(source, `duplicate tool id ${tool.id}`);
    ids.add(tool.id as string);
    if (typeof tool.commit !== 'string' || !GIT_COMMIT.test(tool.commit)) fail(toolSource, 'commit must be a full Git object ID');
    if (!/^https:\/\/github\.com\//.test(tool.repository as string)) fail(toolSource, 'repository must be an HTTPS GitHub URL');
  }
  return value as unknown as ThirdPartyLock;
}

function addSourceFile(
  files: Map<string, AtlasSourceFile>,
  relativePath: string,
  bytes: Buffer,
  canonical: string,
  recordCount: number,
): void {
  if (files.has(relativePath)) fail(relativePath, 'canonical file registered twice');
  if (recordCount <= 0) fail(relativePath, 'canonical file must derive at least one record');
  files.set(relativePath, {
    path: relativePath,
    rawSha256: sha256Hex(bytes),
    canonicalSha256: sha256Hex(canonical),
    canonicalJson: canonical,
    recordCount,
  });
}

/**
 * Derive Atlas records directly from the reviewable HQL package tree.
 * No generated record tree is accepted or required.
 */
export function loadHqlPackageAtlasSource(packageRoot: string): AtlasCanonicalSource {
  const root = path.resolve(packageRoot);
  const signaturesRoot = path.join(root, 'signatures');
  const fixtureRoot = path.join(root, 'atlas', 'fixtures');
  const fixtureManifestPath = path.join(fixtureRoot, 'v1', 'manifest.json');
  const thirdPartyLockPath = path.join(root, 'benchmarks', 'third_party.lock.json');
  for (const required of [signaturesRoot, fixtureManifestPath, thirdPartyLockPath]) {
    if (!fs.existsSync(required)) fail(required, 'required canonical Atlas input is missing');
  }

  const files = new Map<string, AtlasSourceFile>();
  const records: AtlasSourcedRecord[] = [];
  const signatures = new Map<string, { signature: ManagedSignature; sourcePath: string }>();
  for (const absolutePath of collectFiles(signaturesRoot, name => name.endsWith('.hql.json'))) {
    const sourcePath = slashPath(root, absolutePath);
    const document = readJson(absolutePath, sourcePath);
    const signature = requireManagedSignature(document.parsed, sourcePath);
    if (signatures.has(signature.id)) fail(sourcePath, `duplicate signature id ${signature.id}`);
    signatures.set(signature.id, { signature, sourcePath });
    const rule = createRuleRecord(signature);
    records.push(sourcedRecord(rule, sourcePath, 0));

    let sourceIndex = 1;
    for (const superseded of signature.supersedes ?? []) {
      const match = VERSIONED_RULE.exec(superseded);
      if (!match) fail(sourcePath, `supersedes entry must use rule.id@semver: ${superseded}`);
      const edge: AtlasSupersessionRecord = {
        recordType: 'supersession',
        ruleId: signature.id,
        ruleVersion: signature.version,
        supersedesRuleId: match[1],
        supersedesRuleVersion: match[2],
        reason: `Declared by ${signature.id}@${signature.version}`,
      };
      records.push(sourcedRecord(edge, sourcePath, sourceIndex++));
    }
    addSourceFile(files, sourcePath, document.bytes, document.canonical, sourceIndex);
  }

  const manifestSource = slashPath(root, fixtureManifestPath);
  const manifestDocument = readJson(fixtureManifestPath, manifestSource);
  const manifest = parseFixtureManifest(manifestDocument.parsed, manifestSource);
  const manifestMeta: AtlasMetaRecord = { recordType: 'meta', key: 'fixtures.manifest', value: manifest };
  records.push(sourcedRecord(manifestMeta, manifestSource, 0));
  addSourceFile(files, manifestSource, manifestDocument.bytes, manifestDocument.canonical, 1);

  const released = [...signatures.values()].filter(entry => entry.signature.status === 'released');
  if (manifest.expectedSignatureCount !== released.length) {
    fail(manifestSource, `expectedSignatureCount=${manifest.expectedSignatureCount}, released rules=${released.length}`);
  }
  const manifestEntries = new Map(manifest.fixtureFiles.map(entry => [entry.path, entry]));
  if (manifestEntries.size !== manifest.fixtureFiles.length) fail(manifestSource, 'fixture file paths must be unique');
  const expectedFixturePaths = new Set<string>();
  let totalCases = 0;
  const allCaseIds = new Set<string>();

  for (const { signature, sourcePath: signatureSource } of released) {
    if (!signature.fixtures) fail(signatureSource, 'released rule requires fixtures.manifest');
    const fixtureRelative = signature.fixtures.manifest.split(path.sep).join('/');
    const fixtureParts = fixtureRelative.split('/');
    if (fixtureParts.length < 2 || fixtureParts[0] !== 'v1') fail(signatureSource, 'fixtures.manifest must point into atlas/fixtures/v1');
    const manifestEntryPath = fixtureParts.slice(1).join('/');
    const manifestEntry = manifestEntries.get(manifestEntryPath);
    if (!manifestEntry) fail(signatureSource, `fixture ${manifestEntryPath} is absent from the v1 manifest`);
    expectedFixturePaths.add(manifestEntryPath);
    const absoluteFixture = safeRelativePath(fixtureRoot, fixtureRelative, signatureSource);
    const fixtureSource = slashPath(root, absoluteFixture);
    const fixtureDocument = readJson(absoluteFixture, fixtureSource);
    if (sha256Hex(fixtureDocument.canonical) !== manifestEntry.canonicalFileSha256) {
      fail(fixtureSource, 'canonical file SHA-256 does not match manifest');
    }
    const fixture = parseFixtureFile(fixtureDocument.parsed, fixtureSource);
    assertFixtureGate(signature, fixture, fixtureSource);
    fixture.cases.forEach((fixtureCase, sourceIndex) => {
      if (allCaseIds.has(fixtureCase.caseId)) fail(fixtureSource, `duplicate global caseId ${fixtureCase.caseId}`);
      allCaseIds.add(fixtureCase.caseId);
      const record: AtlasFixtureRecord = {
        recordType: 'fixture',
        id: fixtureCase.caseId,
        ruleId: signature.id,
        ruleVersion: signature.version,
        kind: fixtureCase.expectMatch ? 'positive' : 'negative',
        sourceSha256: fixtureCase.contentSha256,
        expectedLocations: fixtureCase.expectedMatchLocations,
        branch: fixtureCase.branchId,
        ...(fixtureCase.branchIndex !== undefined ? { branchIndex: fixtureCase.branchIndex } : {}),
        ast: fixtureCase.ast,
      };
      records.push(sourcedRecord(record, fixtureSource, sourceIndex));
    });
    totalCases += fixture.cases.length;
    addSourceFile(files, fixtureSource, fixtureDocument.bytes, fixtureDocument.canonical, fixture.cases.length);
  }
  if (expectedFixturePaths.size !== manifestEntries.size) {
    const extras = [...manifestEntries.keys()].filter(entry => !expectedFixturePaths.has(entry));
    fail(manifestSource, `manifest contains fixtures for no released rule: ${extras.join(', ')}`);
  }
  if (totalCases !== manifest.expectedCaseCount) {
    fail(manifestSource, `expectedCaseCount=${manifest.expectedCaseCount}, loaded cases=${totalCases}`);
  }

  const lockSource = slashPath(root, thirdPartyLockPath);
  const lockDocument = readJson(thirdPartyLockPath, lockSource);
  const thirdPartyLock = parseThirdPartyLock(lockDocument.parsed, lockSource);
  const lockMeta: AtlasMetaRecord = { recordType: 'meta', key: 'benchmarks.thirdPartyLock', value: thirdPartyLock };
  records.push(sourcedRecord(lockMeta, lockSource, 0));
  addSourceFile(files, lockSource, lockDocument.bytes, lockDocument.canonical, 1);

  const resultsRoot = path.join(root, 'benchmarks', 'results');
  if (fs.existsSync(resultsRoot)) {
    for (const absolutePath of collectFiles(resultsRoot, name => name.endsWith('.json'))) {
      const sourcePath = slashPath(root, absolutePath);
      const document = readJson(absolutePath, sourcePath);
      const values = Array.isArray(document.parsed) ? document.parsed : [document.parsed];
      if (values.length === 0) fail(sourcePath, 'benchmark result file cannot be empty');
      values.forEach((value, sourceIndex) => {
        const record = validateAtlasRecord(value, `${sourcePath}[${sourceIndex}]`);
        if (record.recordType !== 'benchmark') fail(sourcePath, 'benchmark results may contain only benchmark records');
        records.push(sourcedRecord(record as AtlasBenchmarkRecord, sourcePath, sourceIndex));
      });
      addSourceFile(files, sourcePath, document.bytes, document.canonical, values.length);
    }
  }

  assertAtlasRecordSet(records);
  const sourceFiles = [...files.values()].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  const semanticManifest = sourceFiles.map(file => ({
    path: file.path,
    canonicalSha256: file.canonicalSha256,
    canonicalJson: file.canonicalJson,
    recordCount: file.recordCount,
  }));
  return {
    root,
    files: sourceFiles,
    records,
    sourceTreeSha256: sha256Hex(canonicalJson(semanticManifest)),
  };
}

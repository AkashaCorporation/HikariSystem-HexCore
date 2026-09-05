import * as assert from 'assert';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { HQLMatcher } from '../src/engine/matcher.js';
import { loadSignatureDirectory } from '../src/signatures/loader.js';
import type { CBlockStmt, CFunctionDecl, CNode } from '../src/types/ast.js';
import type { HQLCondition, HQLSignature } from '../src/types/hql.js';

type JsonScalar = string | number | boolean | null;
type JsonValue = JsonScalar | JsonValue[] | { [key: string]: JsonValue };

interface CompactNode {
  k: 'fn' | 'block' | 'bin' | 'int' | 'str' | 'var' | 'call' | 'field' |
    'for' | 'while' | 'doWhile' | 'if';
  at?: string;
  name?: string;
  value?: string | number;
  op?: string;
  a?: CompactValue;
  b?: CompactValue;
  args?: CompactValue[];
  object?: CompactValue;
  arrow?: boolean;
  body?: CompactNode[];
  condition?: CompactValue;
  init?: CompactValue;
  update?: CompactValue;
  then?: CompactNode[];
  else?: CompactNode[];
}

type CompactValue = CompactNode | string | number;

interface AtlasFixtureCase {
  caseId: string;
  branchId: string;
  branchIndex?: number;
  expectMatch: boolean;
  expectedMatchLocations: string[];
  contentSha256: string;
  ast: CompactNode;
}

interface AtlasFixtureFile {
  schemaVersion: 1;
  signatureId: string;
  cases: AtlasFixtureCase[];
}

interface AtlasManifest {
  schemaVersion: 1;
  corpusId: string;
  expectedSignatureCount: number;
  expectedCaseCount: number;
  fixtureFiles: Array<{ path: string; canonicalFileSha256: string }>;
}

interface HydratedFixture {
  root: CFunctionDecl;
  locations: WeakMap<CNode, string>;
}

const packageRoot = path.resolve(__dirname, '..');
const fixtureRoot = path.join(packageRoot, 'atlas', 'fixtures', 'v1');
const manifest = readJson<AtlasManifest>(path.join(fixtureRoot, 'manifest.json'));
const signatures = loadSignatureDirectory(path.join(packageRoot, 'signatures'))
  .filter(signature => signature.status === undefined || signature.status === 'released');
const signaturesById = new Map(signatures.map(signature => [signature.id, signature]));
const matcher = new HQLMatcher();

assert.strictEqual(manifest.schemaVersion, 1, 'unsupported Atlas fixture manifest');
assert.strictEqual(manifest.corpusId, 'hql-atlas-core-v1');
assert.strictEqual(signatures.length, manifest.expectedSignatureCount, 'fixture manifest must cover the complete active rule set');
assert.strictEqual(new Set(signatures.map(signature => signature.id)).size, signatures.length, 'active signature IDs must be unique');

const fixtureFiles = manifest.fixtureFiles.map(entry => {
  const fullPath = path.resolve(fixtureRoot, entry.path);
  assert.ok(fullPath.startsWith(fixtureRoot + path.sep), `fixture path escapes corpus: ${entry.path}`);
  const parsed = readJson<AtlasFixtureFile>(fullPath);
  assert.strictEqual(
    sha256(canonicalJson(parsed as unknown as JsonValue)),
    entry.canonicalFileSha256,
    `${entry.path}: canonical file hash drift`,
  );
  return parsed;
});

assert.strictEqual(fixtureFiles.length, manifest.expectedSignatureCount);
assert.deepStrictEqual(
  [...fixtureFiles.map(file => file.signatureId)].sort(),
  [...signaturesById.keys()].sort(),
  'fixture rule IDs must exactly equal the active signature library',
);

const caseIds = new Set<string>();
let executedCases = 0;
let positiveCases = 0;
let negativeCases = 0;

for (const fixtureFile of fixtureFiles) {
  assert.strictEqual(fixtureFile.schemaVersion, 1);
  const signature = signaturesById.get(fixtureFile.signatureId);
  assert.ok(signature, `${fixtureFile.signatureId}: missing active signature`);
  const anyBranches = getAnyBranches(signature!);

  for (const fixture of fixtureFile.cases) {
    assert.match(fixture.caseId, /^hql-atlas-v1:[a-z0-9_.-]+:(positive|negative-[12])$/);
    assert.ok(!caseIds.has(fixture.caseId), `duplicate persistent case ID: ${fixture.caseId}`);
    caseIds.add(fixture.caseId);
    assert.strictEqual(
      fixture.contentSha256,
      sha256(canonicalJson(fixture.ast as unknown as JsonValue)),
      `${fixture.caseId}: canonical AST content hash drift`,
    );
    assert.strictEqual(
      new Set(fixture.expectedMatchLocations).size,
      fixture.expectedMatchLocations.length,
      `${fixture.caseId}: expected locations must be unique`,
    );
    assert.strictEqual(
      fixture.expectedMatchLocations.length > 0,
      fixture.expectMatch,
      `${fixture.caseId}: positives require locations and negatives require none`,
    );

    const hydrated = hydrateFixture(fixture.ast, fixture.caseId);
    const result = matcher.evaluate(hydrated.root, signature!);
    assert.strictEqual(Boolean(result), fixture.expectMatch, `${fixture.caseId}: full-signature outcome`);
    assert.deepStrictEqual(
      result ? result.matches.map(node => requireLocation(hydrated.locations, node, fixture.caseId)) : [],
      fixture.expectedMatchLocations,
      `${fixture.caseId}: full-signature match locations`,
    );

    if (anyBranches) {
      assert.ok(Number.isInteger(fixture.branchIndex), `${fixture.caseId}: any-rule case requires branchIndex`);
      assert.ok(fixture.branchIndex! >= 0 && fixture.branchIndex! < anyBranches.length, `${fixture.caseId}: invalid branchIndex`);
      const branch = matcher.evaluateCondition(hydrated.root, anyBranches[fixture.branchIndex!]);
      assert.strictEqual(branch.matched, fixture.expectMatch, `${fixture.caseId}: isolated branch outcome`);
      assert.deepStrictEqual(
        branch.matches.map(node => requireLocation(hydrated.locations, node, fixture.caseId)),
        fixture.expectedMatchLocations,
        `${fixture.caseId}: isolated branch match locations`,
      );
    } else {
      assert.strictEqual(fixture.branchIndex, undefined, `${fixture.caseId}: non-any rule must not declare branchIndex`);
    }

    executedCases++;
    if (fixture.expectMatch) positiveCases++;
    else negativeCases++;
  }

  assertGateCoverage(fixtureFile, anyBranches?.length);
}

assert.strictEqual(executedCases, manifest.expectedCaseCount, 'manifest case count drift');
assert.strictEqual(executedCases, 60, 'v1 corpus is expected to contain 60 cases');
assert.strictEqual(positiveCases, 20);
assert.strictEqual(negativeCases, 40);

console.log(
  `atlasFixtures: ${fixtureFiles.length} rules, ${executedCases} canonical cases ` +
  `(${positiveCases} positive, ${negativeCases} negative), hashes and locations verified - OK`,
);

function getAnyBranches(signature: HQLSignature): HQLCondition[] | undefined {
  return signature.condition && 'any' in signature.condition ? signature.condition.any : undefined;
}

function assertGateCoverage(file: AtlasFixtureFile, anyBranchCount?: number): void {
  if (anyBranchCount !== undefined) {
    const covered = new Set(file.cases.map(fixture => fixture.branchIndex));
    assert.deepStrictEqual([...covered].sort(), Array.from({ length: anyBranchCount }, (_, index) => index));
    for (let index = 0; index < anyBranchCount; index++) {
      const branchCases = file.cases.filter(fixture => fixture.branchIndex === index);
      assert.ok(branchCases.some(fixture => fixture.expectMatch), `${file.signatureId}/branch-${index}: missing positive`);
      assert.ok(branchCases.filter(fixture => !fixture.expectMatch).length >= 2, `${file.signatureId}/branch-${index}: needs two negatives`);
      assert.strictEqual(new Set(branchCases.map(fixture => fixture.branchId)).size, 1, `${file.signatureId}/branch-${index}: unstable branch ID`);
    }
    return;
  }

  assert.ok(file.cases.some(fixture => fixture.expectMatch), `${file.signatureId}: missing positive`);
  assert.ok(file.cases.filter(fixture => !fixture.expectMatch).length >= 2, `${file.signatureId}: needs two negatives`);
  assert.deepStrictEqual([...new Set(file.cases.map(fixture => fixture.branchId))], ['rule']);
}

function hydrateFixture(compact: CompactNode, caseId: string): HydratedFixture {
  const locations = new WeakMap<CNode, string>();

  const remember = <T extends CNode>(node: T, at?: string): T => {
    if (at) locations.set(node, at);
    return node;
  };

  const value = (input: CompactValue): CNode => {
    if (typeof input === 'number') {
      return { kind: 'CIntLitExpr', value: input, exactValue: String(input), width: 64, signed: input < 0 };
    }
    if (typeof input === 'string') {
      return { kind: 'CVarRefExpr', name: input, type: 'uint64_t' };
    }
    return node(input);
  };

  const block = (body: CompactNode[] | undefined): CBlockStmt => ({
    kind: 'CBlockStmt',
    body: (body ?? []).map(node),
  });

  const node = (input: CompactNode): CNode => {
    switch (input.k) {
      case 'fn':
        return remember({
          kind: 'CFunctionDecl',
          name: input.name ?? caseId.replace(/[^a-z0-9_]/gi, '_'),
          address: '0x401000',
          returnType: 'void',
          params: [],
          body: block(input.body),
        }, input.at);
      case 'block':
        return remember(block(input.body), input.at);
      case 'bin':
        assert.ok(input.op && input.a !== undefined && input.b !== undefined, `${caseId}: malformed bin node`);
        return remember({ kind: 'CBinaryExpr', operator: input.op!, left: value(input.a!), right: value(input.b!) }, input.at);
      case 'int': {
        assert.ok(input.value !== undefined, `${caseId}: malformed int node`);
        const exact = String(input.value);
        const numeric = typeof input.value === 'number' && Number.isSafeInteger(input.value) ? input.value : exact;
        return remember({ kind: 'CIntLitExpr', value: numeric, exactValue: exact, width: 64, signed: exact.startsWith('-') }, input.at);
      }
      case 'str':
        assert.strictEqual(typeof input.value, 'string', `${caseId}: malformed str node`);
        return remember({ kind: 'CStringLitExpr', value: input.value as string, encoding: 'ascii' }, input.at);
      case 'var':
        return remember({ kind: 'CVarRefExpr', name: input.name ?? 'v', type: 'uint64_t' }, input.at);
      case 'call':
        assert.ok(input.name, `${caseId}: malformed call node`);
        return remember({ kind: 'CCallExpr', callee: input.name!, arguments: (input.args ?? []).map(value) }, input.at);
      case 'field':
        assert.ok(input.name, `${caseId}: malformed field node`);
        return remember({
          kind: 'CFieldAccessExpr',
          object: value(input.object ?? 'obj'),
          field: input.name!,
          arrow: input.arrow ?? true,
        }, input.at);
      case 'for':
        return remember({
          kind: 'CForStmt',
          ...(input.init !== undefined ? { init: value(input.init) } : {}),
          ...(input.condition !== undefined ? { condition: value(input.condition) } : {}),
          ...(input.update !== undefined ? { update: value(input.update) } : {}),
          body: block(input.body),
        }, input.at);
      case 'while':
        return remember({ kind: 'CWhileStmt', condition: value(input.condition ?? 'keepGoing'), body: block(input.body) }, input.at);
      case 'doWhile':
        return remember({ kind: 'CDoWhileStmt', condition: value(input.condition ?? 'keepGoing'), body: block(input.body) }, input.at);
      case 'if':
        return remember({
          kind: 'CIfStmt',
          condition: value(input.condition ?? 'guard'),
          then: block(input.then),
          ...(input.else ? { else: block(input.else) } : {}),
        }, input.at);
    }
  };

  const root = node(compact);
  assert.strictEqual(root.kind, 'CFunctionDecl', `${caseId}: root must be a compact fn node`);
  const functionRoot = root as CFunctionDecl;
  functionRoot.adapterCoverage = {
    totalNodes: collectNodes(functionRoot).length,
    lossyNodes: 0,
    coverage: 1,
    unsupportedNodeCounts: {},
  };
  return { root: functionRoot, locations };
}

function collectNodes(root: CNode): CNode[] {
  const nodes: CNode[] = [];
  const visit = (node: CNode): void => {
    nodes.push(node);
    for (const child of Object.values(node)) {
      if (Array.isArray(child)) {
        for (const item of child) {
          if (isNode(item)) visit(item);
        }
      } else if (isNode(child)) {
        visit(child);
      }
    }
  };
  visit(root);
  return nodes;
}

function isNode(value: unknown): value is CNode {
  return Boolean(value && typeof value === 'object' && typeof (value as { kind?: unknown }).kind === 'string');
}

function requireLocation(locations: WeakMap<CNode, string>, node: CNode, caseId: string): string {
  const location = locations.get(node);
  assert.ok(location, `${caseId}: matched ${node.kind} has no fixture location`);
  return location!;
}

function readJson<T>(file: string): T {
  return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
}

function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

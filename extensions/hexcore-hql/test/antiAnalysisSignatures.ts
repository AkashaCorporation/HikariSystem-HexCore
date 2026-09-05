import * as assert from 'assert';
import * as path from 'path';
import { HQLMatcher } from '../src/engine/matcher.js';
import { loadSignatureDirectory } from '../src/signatures/loader.js';
import type { CNode, CFunctionDecl, CBlockStmt } from '../src/types/ast.js';
import type { HQLSignature } from '../src/types/hql.js';

const matcher = new HQLMatcher();
const root = path.resolve(__dirname, '../signatures/anti-analysis');
const signatures = new Map(loadSignatureDirectory(root).map(signature => [signature.id, signature]));

const variable = (name = 'v'): CNode => ({ kind: 'CVarRefExpr', name, type: 'uint64_t' });
const integer = (value: number): CNode => ({ kind: 'CIntLitExpr', value, exactValue: String(value), width: 64, signed: false });
const string = (value: string): CNode => ({ kind: 'CStringLitExpr', value, encoding: 'ascii' });
const binary = (operator: string, left: CNode = variable(), right: CNode = integer(1)): CNode => ({
  kind: 'CBinaryExpr', operator, left, right,
});
const call = (callee: string, ...args: CNode[]): CNode => ({ kind: 'CCallExpr', callee, arguments: args });
const block = (...body: CNode[]): CBlockStmt => ({ kind: 'CBlockStmt', body });
const loop = (kind: 'CForStmt' | 'CWhileStmt', ...body: CNode[]): CNode => kind === 'CForStmt'
  ? { kind, body: block(...body) }
  : { kind, condition: variable('keepGoing'), body: block(...body) };
const fn = (...body: CNode[]): CFunctionDecl => ({
  kind: 'CFunctionDecl',
  name: 'fixture',
  address: '0x401000',
  returnType: 'void',
  params: [],
  body: block(...body),
  adapterCoverage: { totalNodes: body.length + 2, lossyNodes: 0, coverage: 1, unsupportedNodeCounts: {} },
});

interface BranchFixture {
  signatureId: string;
  label: string;
  positive: CFunctionDecl;
  nearMiss: CFunctionDecl;
}

const fixtures: BranchFixture[] = [
  {
    signatureId: 'anti-analysis.api_hash_lookup', label: 'for xor shift',
    positive: fn(loop('CForStmt', binary('^'), binary('<<'))),
    nearMiss: fn(loop('CForStmt', binary('^'), binary('+'))),
  },
  {
    signatureId: 'anti-analysis.api_hash_lookup', label: 'while xor shift',
    positive: fn(loop('CWhileStmt', binary('^'), binary('<<'))),
    nearMiss: fn(loop('CWhileStmt', binary('^'), binary('+'))),
  },
  {
    signatureId: 'anti-analysis.api_hash_lookup', label: 'for xor multiply',
    positive: fn(loop('CForStmt', binary('^'), binary('*'))),
    nearMiss: fn(loop('CForStmt', binary('^'), binary('+'))),
  },
  {
    signatureId: 'anti-analysis.peb_access', label: 'PEB field',
    positive: fn({ kind: 'CFieldAccessExpr', object: variable('process'), field: 'ProcessEnvironmentBlock', arrow: true }),
    nearMiss: fn({ kind: 'CFieldAccessExpr', object: variable('process'), field: 'Environment', arrow: true }),
  },
  {
    signatureId: 'anti-analysis.peb_access', label: 'Nt query',
    positive: fn(call('NtQueryInformationProcess')),
    nearMiss: fn(call('NtQueryInformationFile')),
  },
  {
    signatureId: 'anti-analysis.peb_access', label: 'Zw query',
    positive: fn(call('ZwQueryInformationThread')),
    nearMiss: fn(call('ZwSetInformationThread')),
  },
  {
    signatureId: 'anti-analysis.timing_check', label: 'for timer',
    positive: fn(loop('CForStmt', call('QueryPerformanceCounter'))),
    nearMiss: fn(loop('CForStmt', call('QueryPerformanceFrequency'))),
  },
  {
    signatureId: 'anti-analysis.timing_check', label: 'while timer',
    positive: fn(loop('CWhileStmt', call('GetTickCount64'))),
    nearMiss: fn(loop('CWhileStmt', call('GetSystemTime'))),
  },
  {
    signatureId: 'anti-analysis.timing_check', label: 'timer subtraction',
    positive: fn(binary('-', call('rdtsc'), variable('start'))),
    nearMiss: fn(binary('+', call('rdtsc'), variable('start'))),
  },
  {
    signatureId: 'anti-analysis.vm_detection', label: 'system enumeration',
    positive: fn(call('GetSystemFirmwareTable')),
    nearMiss: fn(call('GetSystemInfo')),
  },
  {
    signatureId: 'anti-analysis.vm_detection', label: 'registry artifact',
    positive: fn(call('RegQueryValueExW', string('VEN_VMWARE'))),
    nearMiss: fn(call('RegQueryValueExW', string('VEN_INTEL'))),
  },
  {
    signatureId: 'anti-analysis.vm_detection', label: 'WMI artifact',
    positive: fn(call('wbemServices_ExecQuery', string('SELECT * FROM Win32_BIOS'))),
    nearMiss: fn(call('wbemServices_ExecQuery', string('SELECT * FROM Win32_Process'))),
  },
];

const empty = fn(call('ordinary_work'));
for (const fixture of fixtures) {
  const signature = signatures.get(fixture.signatureId) as HQLSignature | undefined;
  assert.ok(signature, `${fixture.signatureId} must load`);
  assert.ok(matcher.evaluate(fixture.positive, signature!), `${fixture.signatureId}/${fixture.label}: positive`);
  assert.strictEqual(matcher.evaluate(fixture.nearMiss, signature!), null, `${fixture.signatureId}/${fixture.label}: near miss`);
  assert.strictEqual(matcher.evaluate(empty, signature!), null, `${fixture.signatureId}/${fixture.label}: clean negative`);
}

assert.strictEqual(fixtures.length, 12);
console.log(`antiAnalysisSignatures: ${fixtures.length} branches, 36 fixture assertions - OK`);

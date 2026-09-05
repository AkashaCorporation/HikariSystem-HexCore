/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import type { X86Operand } from 'hexcore-capstone';
import type { DisassemblerEngine, Function, Instruction, XRef } from './disassemblerEngine';
import type { CanonicalReferenceEdge, StoredReferenceEdge, TypedReferenceGraph } from './typedReferenceGraph';

function installVscodeMock(): void {
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_reference_producer__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache.__vscode_mock_reference_producer__ = {
		id: '__vscode_mock_reference_producer__',
		filename: '__vscode_mock_reference_producer__',
		loaded: true,
		exports: {
			workspace: {
				getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }),
				workspaceFolders: undefined,
			},
			commands: { getCommands: async () => [], executeCommand: async () => undefined },
			window: {},
			Uri: { file: (fsPath: string) => ({ fsPath }) },
		},
	} as NodeModule;
}

installVscodeMock();
const { decodeIatOperandVA } = require('./disassemblerEngine') as typeof import('./disassemblerEngine');
const { collectTypedReferenceEdges, syncTypedReferenceGraph } = require('./typedReferenceGraphProducer') as typeof import('./typedReferenceGraphProducer');
const { runReferenceGraphExport, runReferenceGraphQuery } = require('./typedReferenceGraphCommands') as typeof import('./typedReferenceGraphCommands');

const targetIdentity = `target:sha256:${'a'.repeat(64)}`;

function instruction(overrides: Partial<Instruction>): Instruction {
	return {
		address: 0x140001000,
		bytes: Buffer.from([0x90]),
		mnemonic: 'nop',
		opStr: '',
		size: 1,
		isCall: false,
		isJump: false,
		isRet: false,
		isConditional: false,
		...overrides,
	};
}

function x86Detail(operands: Array<Record<string, unknown>>): NonNullable<Instruction['detail']> {
	return {
		regsRead: [], regsWrite: [], groups: [],
		x86: {
			prefix: [], opcode: [], rexPrefix: 0, addrSize: 8, modRM: 0, sib: 0, disp: 0,
			sibIndex: 0, sibScale: 0, sibBase: 0, xopCC: 0, sseCC: 0, avxCC: 0,
			avxSAE: false, avxRM: 0, eflags: 0,
			operands: operands as unknown as X86Operand[],
		},
	};
}

function fixtureFunctions(): Function[] {
	const iatCallAddress = 0x140001005;
	const iatSlot = 0x140003000;
	const iatDisp = iatSlot - (iatCallAddress + 6);
	const stringInstructionAddress = 0x14000100b;
	const stringAddress = 0x140004000;
	const stringDisp = stringAddress - (stringInstructionAddress + 7);
	return [
		{
			address: 0x140001000,
			name: 'caller',
			size: 0x40,
			endAddress: 0x140001040,
			callers: [],
			callees: [0x140002000],
			instructions: [
				instruction({
					address: 0x140001000, bytes: Buffer.from([0xe8, 0, 0, 0, 0]), mnemonic: 'call', opStr: '0x140002000', size: 5,
					isCall: true, targetAddress: 0x140002000,
				}),
				instruction({
					address: iatCallAddress, bytes: Buffer.from([0xff, 0x15, 0, 0, 0, 0]), mnemonic: 'call',
					opStr: `qword ptr [rip + 0x${iatDisp.toString(16)}]`, size: 6, isCall: true,
				}),
				instruction({
					address: stringInstructionAddress, bytes: Buffer.alloc(7), mnemonic: 'lea',
					opStr: `rdx, [rip + 0x${stringDisp.toString(16)}]`, size: 7,
				}),
				instruction({
					address: 0x140001012, bytes: Buffer.alloc(7), mnemonic: 'lea',
					opStr: 'rax, [rip + 0xfe7]', size: 7,
					detail: x86Detail([
						{ type: 1, size: 8, access: 2, avxBcast: 0, avxZeroOpmask: false, reg: 1 },
						{ type: 3, size: 8, access: 0, avxBcast: 0, avxZeroOpmask: false, mem: { base: 41, index: 0, scale: 1, disp: 0xfe7 } },
					]),
				}),
				instruction({
					address: 0x140001019, bytes: Buffer.from([0xff, 0xd0]), mnemonic: 'call', opStr: 'rax', size: 2, isCall: true,
					detail: x86Detail([{ type: 1, size: 8, access: 1, avxBcast: 0, avxZeroOpmask: false, reg: 1 }]),
				}),
				instruction({
					address: 0x14000101b, bytes: Buffer.alloc(7), mnemonic: 'mov', opStr: 'rax, qword ptr [rip + 0x2fde]', size: 7,
					detail: x86Detail([
						{ type: 1, size: 8, access: 2, avxBcast: 0, avxZeroOpmask: false, reg: 1 },
						{ type: 3, size: 8, access: 1, avxBcast: 0, avxZeroOpmask: false, mem: { base: 41, index: 0, scale: 1, disp: 0x2fde } },
					]),
				}),
				instruction({
					address: 0x140001022, bytes: Buffer.alloc(7), mnemonic: 'mov', opStr: 'qword ptr [rip + 0x2fe7], rax', size: 7,
					detail: x86Detail([
						{ type: 3, size: 8, access: 2, avxBcast: 0, avxZeroOpmask: false, mem: { base: 41, index: 0, scale: 1, disp: 0x2fe7 } },
						{ type: 1, size: 8, access: 1, avxBcast: 0, avxZeroOpmask: false, reg: 1 },
					]),
				}),
				instruction({
					address: 0x140001029, bytes: Buffer.alloc(7), mnemonic: 'add', opStr: 'dword ptr [rip + 0x2ff0], 1', size: 7,
					detail: x86Detail([
						{ type: 3, size: 4, access: 3, avxBcast: 0, avxZeroOpmask: false, mem: { base: 41, index: 0, scale: 1, disp: 0x2ff0 } },
						{ type: 2, size: 4, access: 1, avxBcast: 0, avxZeroOpmask: false, imm: 1 },
					]),
				}),
				instruction({ address: 0x140001030, bytes: Buffer.from([0xff, 0xd3]), mnemonic: 'call', opStr: 'rbx', size: 2, isCall: true }),
				instruction({ address: 0x140001032, bytes: Buffer.from([0xc3]), mnemonic: 'ret', size: 1, isRet: true }),
			],
		},
		{
			address: 0x140002000,
			name: 'target',
			size: 1,
			endAddress: 0x140002001,
			callers: [0x140001000],
			callees: [],
			instructions: [instruction({ address: 0x140002000, bytes: Buffer.from([0xc3]), mnemonic: 'ret', size: 1, isRet: true })],
		},
	];
}

function fakeEngine(options: { complete?: boolean; duplicateOwner?: boolean; partialFirst?: boolean } = {}): DisassemblerEngine {
	const functions = fixtureFunctions();
	if (options.duplicateOwner) {
		functions.push({
			address: 0x140000ff0,
			name: 'overlap',
			size: 0x20,
			endAddress: 0x140001010,
			callers: [],
			callees: [],
			instructions: [{ ...functions[0].instructions[0], bytes: Buffer.from(functions[0].instructions[0].bytes) }],
		});
	}
	const xrefs: XRef[] = [
		{ from: 0x140001000, to: 0x140002000, type: 'call' },
		{ from: 0x14000100b, to: 0x140004000, type: 'string' },
		{ from: 0x140001012, to: 0x140002000, type: 'data' },
		{ from: 0x14000101b, to: 0x140004000, type: 'data' },
		{ from: 0x140001022, to: 0x140004010, type: 'data' },
		{ from: 0x140001029, to: 0x140004020, type: 'data' },
	];
	return {
		getAnalysisGeneration: () => 7,
		getFunctions: () => functions,
		getFunctionBodyStatus: (address: number) => options.partialFirst && address === functions[0].address ? 'partial' : 'materialized',
		getImports: () => [{ name: 'KERNEL32.dll', functions: [{ name: 'CreateFileW', address: 0x140003000 }] }],
		getTextRelocations: () => new Map(),
		getSections: () => [{ virtualAddress: 0x140001000, virtualSize: 0x4000, rawSize: 0x4000, isExecutable: true }],
		getDataRelocations: () => new Map(),
		getFileInfo: () => ({ format: 'PE64' }),
		getBytes: () => undefined,
		getRegisterName: (registerId: number) => registerId === 41 ? 'rip' : registerId === 1 ? 'rax' : undefined,
		getFunctionDiscoveryEvidence: (address: number) => address === 0x140002000
			? [{ kind: 'address-taken' as const, sourceAddress: 0x140001012, consumerAddress: 0x140001019 }]
			: [],
		getStrings: () => [{ address: 0x140004000, string: 'fixture', encoding: 'ascii' as const, references: [0x14000100b] }],
		getAllCrossReferences: () => xrefs,
		isAnalysisComplete: () => options.complete !== false,
	} as unknown as DisassemblerEngine;
}

class FakeGraph {
	readonly analysisTargetIdentity = targetIdentity;
	private edges: CanonicalReferenceEdge[] = [];
	private invalidated: StoredReferenceEdge[] = [];
	seed(edges: readonly CanonicalReferenceEdge[]) { this.edges = [...edges]; }

	writeBatch(edges: readonly CanonicalReferenceEdge[]) {
		this.edges = [...edges];
		return {
			transactionHash: 'batch-hash',
			results: edges.map(edge => ({ changed: true, accepted: edge, status: 'accepted', transactionHash: 'batch-hash' })),
		};
	}

	query() { return [...this.edges]; }
	listStoredEdges(includeInvalidated = false): StoredReferenceEdge[] {
		const active = this.edges.map(edge => ({ edge, active: true, validFromGeneration: edge.generation, recordHash: edge.canonicalHash }));
		return includeInvalidated ? [...active, ...this.invalidated] : active;
	}
	listVersions() { return []; }
	listConflicts() { return []; }
	invalidateEdges() { return 0; }
	exportHash() { return 'f'.repeat(64); }
}

function engineWithSession(graph: FakeGraph, options: { complete?: boolean; duplicateOwner?: boolean; partialFirst?: boolean } = {}): DisassemblerEngine {
	const engine = fakeEngine(options) as unknown as Record<string, unknown>;
	engine.getSessionStore = () => ({
		getSemanticStore: () => ({ getReferenceGraph: () => graph }),
	});
	return engine as unknown as DisassemblerEngine;
}

suite('R33 typed reference producer and headless commands', () => {
	test('defers invalidation when restored analysis is older than an active edge', () => {
		const graph = new FakeGraph();
		const collected = collectTypedReferenceEdges(fakeEngine(), graph as unknown as TypedReferenceGraph);
		const future = { ...collected.edges[0], generation: 9 };
		graph.seed([future]);
		const result = syncTypedReferenceGraph(engineWithSession(graph, { partialFirst: true }));
		assert.strictEqual(result.edgesInvalidated, 0);
		assert.strictEqual(result.futureGenerationInvalidationDeferred, 1);
		assert.strictEqual(result.status, 'partial');
		assert.match(result.partialReasons.join('\n'), /restored analysis generation is older/);
	});

	test('declares each public reference command exactly once across manifest, handler and pipeline ownership', () => {
		const root = path.resolve(__dirname, '..');
		const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as {
			activationEvents: string[];
			contributes: { commands: Array<{ command: string }> };
		};
		const extensionSource = fs.readFileSync(path.join(root, 'src', 'extension.ts'), 'utf8');
		const runnerSource = fs.readFileSync(path.join(root, 'src', 'automationPipelineRunner.ts'), 'utf8');
		for (const command of ['hexcore.references.query', 'hexcore.references.export']) {
			assert.strictEqual(manifest.activationEvents.filter(item => item === `onCommand:${command}`).length, 1);
			assert.strictEqual(manifest.contributes.commands.filter(item => item.command === command).length, 1);
			assert.strictEqual(extensionSource.split(`registerCommand('${command}'`).length - 1, 1);
			assert.strictEqual(runnerSource.split(`['${command}'`).length - 1, 2, 'capability and owner entries are both required');
		}
	});

	test('preserves PE64 IAT addresses above 4 GiB without uint32 truncation', () => {
		assert.strictEqual(
			decodeIatOperandVA('qword ptr [rip + 0x1ffa]', 0x140001000, 6),
			0x140003000,
		);
	});

	test('emits only exact direct/import/string/address-taken facts and keeps unknown indirects explicit', () => {
		const graph = { analysisTargetIdentity: targetIdentity } as TypedReferenceGraph;
		const result = collectTypedReferenceEdges(fakeEngine(), graph);
		assert.strictEqual(result.status, 'ok');
		assert.ok(result.edges.some(edge => edge.relation === 'code-call-near' && edge.target.address === '0x140002000'));
		assert.ok(result.edges.some(edge => edge.relation === 'import-iat' && edge.target.address === '0x140003000'));
		const iat = result.edges.find(edge => edge.relation === 'code-indirect-resolved');
		assert.strictEqual(iat?.indirectResolution?.source, 'import-table');
		assert.strictEqual(iat?.target.identity, 'import:kernel32.dll!createfilew');
		const string = result.edges.find(edge => edge.relation === 'string-reference');
		assert.strictEqual(string?.source.operandIndex, 1);
		const addressTaken = result.edges.find(edge => edge.relation === 'data-address-taken');
		assert.strictEqual(addressTaken?.source.address, '0x140001012');
		assert.strictEqual(addressTaken?.source.operandIndex, 1);
		const read = result.edges.find(edge => edge.relation === 'data-read');
		assert.strictEqual(read?.source.address, '0x14000101b');
		assert.strictEqual(read?.source.operandIndex, 1);
		assert.strictEqual(read?.accessWidthBits, 64);
		const write = result.edges.find(edge => edge.relation === 'data-write');
		assert.strictEqual(write?.source.address, '0x140001022');
		assert.strictEqual(write?.source.operandIndex, 0);
		assert.strictEqual(write?.accessWidthBits, 64);
		const readWrite = result.edges.find(edge => edge.relation === 'data-read-write');
		assert.strictEqual(readWrite?.source.address, '0x140001029');
		assert.strictEqual(readWrite?.source.operandIndex, 0);
		assert.strictEqual(readWrite?.accessWidthBits, 32);
		assert.strictEqual(result.unresolvedIndirectSets.length, 1);
		assert.strictEqual(result.unresolvedIndirectSets[0].callsiteAddress, '0x140001030');
		assert.deepStrictEqual(result.unresolvedIndirectSets[0].qualifiedSources, []);
		const localCandidate = result.edges.find(edge => edge.source.address === '0x140001019' && edge.relation === 'code-indirect-candidate');
		assert.strictEqual(localCandidate?.target.identity, 'function:0x140002000');
		assert.strictEqual(localCandidate?.indirectResolution?.source, 'constant-function-pointer');
		assert.ok(!result.edges.some(edge => edge.source.address === '0x140001030'), 'call rbx must not acquire fabricated candidates');
	});

	test('rejects ambiguous instruction ownership and reports bounded partial collections', () => {
		const graph = { analysisTargetIdentity: targetIdentity } as TypedReferenceGraph;
		const ambiguous = collectTypedReferenceEdges(fakeEngine({ duplicateOwner: true }), graph);
		assert.ok(ambiguous.skipped.ambiguousInstructionOwnership > 0);
		assert.ok(!ambiguous.edges.some(edge => edge.source.address === '0x140001000'));

		const bounded = collectTypedReferenceEdges(fakeEngine(), graph, { maxInstructions: 1 });
		assert.strictEqual(bounded.status, 'partial');
		assert.ok(bounded.partialReasons.includes('instruction-budget:1'));
	});

	test('keeps partial bodies display-only and excludes their typed edges', () => {
		const graph = { analysisTargetIdentity: targetIdentity } as TypedReferenceGraph;
		const result = collectTypedReferenceEdges(fakeEngine({ partialFirst: true }), graph);
		assert.strictEqual(result.status, 'partial');
		assert.deepStrictEqual(result.incompleteFunctions, ['function:0x140001000']);
		assert.ok(result.partialReasons.includes('incomplete-function-body:function:0x140001000'));
		assert.ok(!result.edges.some(edge => edge.source.ownerFunctionIdentity === 'function:0x140001000'));
	});

	test('query/export envelopes are deterministic and visibly truncate bounded output', () => {
		const graph = new FakeGraph();
		const engine = engineWithSession(graph);
		const queryA = runReferenceGraphQuery(engine, { maxResults: 1 });
		const queryB = runReferenceGraphQuery(engine, { maxResults: 1 });
		assert.strictEqual(queryA.status, 'partial');
		assert.strictEqual(queryA.returned, 1);
		assert.strictEqual(queryA.truncated, true);
		assert.strictEqual(queryA.outputHash, queryB.outputHash);

		const exported = runReferenceGraphExport(engine, { maxEdges: 1, maxVersions: 1, maxConflicts: 1 });
		assert.strictEqual(exported.status, 'partial');
		assert.strictEqual(exported.returned.edges, 1);
		assert.strictEqual(exported.truncated, true);
		assert.throws(() => runReferenceGraphQuery(engine, { maxResults: 0 }), /maxResults/);
	});
});

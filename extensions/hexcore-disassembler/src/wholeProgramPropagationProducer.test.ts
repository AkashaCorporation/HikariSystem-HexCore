/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import type { DisassemblerEngine, Function, Instruction } from './disassemblerEngine';
import { canonicalizeFunctionPrototype, type SemanticEvidence } from './semanticModel';
import type { SemanticStore } from './semanticStore';
import type { CanonicalReferenceEdge, TypedReferenceGraph } from './typedReferenceGraph';

function installVscodeMock(): void {
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_propagation_producer__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache.__vscode_mock_propagation_producer__ = {
		id: '__vscode_mock_propagation_producer__', filename: '__vscode_mock_propagation_producer__', loaded: true,
		exports: {
			workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }), workspaceFolders: undefined },
			commands: { getCommands: async () => [], executeCommand: async () => undefined },
			window: {}, Uri: { file: (fsPath: string) => ({ fsPath }) },
		},
	} as NodeModule;
}

installVscodeMock();
const { collectWholeProgramPropagationInputs } = require('./wholeProgramPropagationProducer') as typeof import('./wholeProgramPropagationProducer');

const targetIdentity = `target:sha256:${'9'.repeat(64)}`;
const evidence: SemanticEvidence = { strength: 'signature', source: 'signature', producer: 'fixture', generation: 4 };

function instruction(overrides: Partial<Instruction>): Instruction {
	return {
		address: 0x140001000, bytes: Buffer.from([0x90]), mnemonic: 'nop', opStr: '', size: 1,
		isCall: false, isJump: false, isRet: false, isConditional: false, ...overrides,
	};
}

function edge(overrides: Partial<CanonicalReferenceEdge>): CanonicalReferenceEdge {
	return {
		schemaVersion: 1, edgeId: 'edge', family: 'code', analysisTargetIdentity: targetIdentity,
		relation: 'code-call-near',
		source: { address: '0x140001000', ownerFunctionIdentity: 'function:0x140001000', basicBlockIdentity: 'basic-block:fixture', operandIndex: 0 },
		target: { kind: 'function', identity: 'function:0x140002000', address: '0x140002000' },
		accessWidthBits: null,
		provenance: { sourceEngine: 'fixture', evidenceAddress: '0x140001000' },
		provenanceSet: [{ sourceEngine: 'fixture', evidenceAddress: '0x140001000' }],
		evidence, evidenceSet: [evidence], userDefined: false, generation: 4,
		invalidationDependencies: [], indirectResolutionSet: [],
		canonicalSerialization: '{}', canonicalHash: 'a'.repeat(64),
		...overrides,
	};
}

suite('R34 whole-program input producer', () => {
	test('declares solve, status and export exactly once across manifest, handler and pipeline ownership', () => {
		const root = path.resolve(__dirname, '..');
		const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as {
			activationEvents: string[];
			contributes: { commands: Array<{ command: string }> };
		};
		const extensionSource = fs.readFileSync(path.join(root, 'src', 'extension.ts'), 'utf8');
		const runnerSource = fs.readFileSync(path.join(root, 'src', 'automationPipelineRunner.ts'), 'utf8');
		for (const command of ['hexcore.propagation.solve', 'hexcore.propagation.status', 'hexcore.propagation.export']) {
			assert.strictEqual(manifest.activationEvents.filter(item => item === `onCommand:${command}`).length, 1);
			assert.strictEqual(manifest.contributes.commands.filter(item => item.command === command).length, 1);
			assert.strictEqual(extensionSource.split(`registerCommand('${command}'`).length - 1, 1);
			assert.strictEqual(runnerSource.split(`['${command}'`).length - 1, 2);
		}
	});

	test('materializes ABI calls, typed arguments, globals and unresolved barriers from the live R33 graph', () => {
		const caller: Function = {
			address: 0x140001000, name: 'caller', size: 0x20, endAddress: 0x140001020, callers: [], callees: [0x140002000],
			instructions: [
				instruction({ address: 0x140001000, mnemonic: 'call', opStr: '0x140002000', size: 5, isCall: true, targetAddress: 0x140002000 }),
				instruction({ address: 0x140001005, mnemonic: 'mov', opStr: 'rax, [rip + 0xff4]', size: 7 }),
				instruction({ address: 0x14000100c, mnemonic: 'call', opStr: 'rax', size: 2, isCall: true }),
				instruction({
					address: 0x14000100e, mnemonic: 'mov', opStr: 'eax, dword ptr [rcx + 8]', size: 3,
					detail: { regsRead: [], regsWrite: [], groups: [], x86: {
						prefix: [], opcode: [], rexPrefix: 0, addrSize: 8, modRM: 0, sib: 0, disp: 8,
						sibIndex: 0, sibScale: 0, sibBase: 0, xopCC: 0, sseCC: 0, avxCC: 0, avxSAE: false, avxRM: 0, eflags: 0,
						operands: [
							{ type: 1, size: 4, access: 2, avxBcast: 0, avxZeroOpmask: false, reg: 11 },
							{ type: 3, size: 4, access: 1, avxBcast: 0, avxZeroOpmask: false, mem: { base: 10, index: 0, scale: 1, disp: 8 } },
						],
					} },
				}),
				instruction({ address: 0x140001011, mnemonic: 'ret', opStr: '', size: 1, isRet: true }),
			],
		};
		const callee: Function = {
			address: 0x140002000, name: 'callee', size: 1, endAddress: 0x140002001, callers: [0x140001000], callees: [],
			instructions: [instruction({ address: 0x140002000, mnemonic: 'ret', opStr: '', size: 1, isRet: true })],
		};
		const prototype = canonicalizeFunctionPrototype({
			targetIdentity,
			functionIdentity: 'function:0x140002000',
			functionAddress: '0x140002000',
			returnTypeId: 'type:uint64', callingConventionId: 'win64',
			parameters: [{ ordinal: 0, name: 'context', typeId: 'type:context_ptr', location: { kind: 'register', registers: ['rcx'] } }],
			evidence,
		});
		const callerPrototype = canonicalizeFunctionPrototype({
			targetIdentity, functionIdentity: 'function:0x140001000', functionAddress: '0x140001000',
			returnTypeId: 'type:uint32', callingConventionId: 'win64',
			parameters: [{ ordinal: 0, name: 'context', typeId: 'type:context_ptr', location: { kind: 'register', registers: ['rcx'] } }],
			evidence,
		});
		const edges = [
			edge({ edgeId: 'call', canonicalHash: '1'.repeat(64) }),
			edge({
				edgeId: 'read', canonicalHash: '2'.repeat(64), family: 'data', relation: 'data-read',
				source: { address: '0x140001005', ownerFunctionIdentity: 'function:0x140001000', basicBlockIdentity: 'basic-block:fixture', operandIndex: 1 },
				target: { kind: 'global', identity: 'global:0x140002000', address: '0x140002000' }, accessWidthBits: 64,
			}),
		];
		const graph = {
			query: (query: { functionIdentity?: string; families?: string[] }) => edges.filter(item =>
				(query.functionIdentity === undefined || item.source.ownerFunctionIdentity === query.functionIdentity) &&
				(!query.families || query.families.includes(item.family))),
		} as unknown as TypedReferenceGraph;
		const store = {
			targetIdentity,
			getReferenceGraph: () => graph,
			getPrototype: (identity: string) => identity === prototype.functionIdentity ? prototype : identity === callerPrototype.functionIdentity ? callerPrototype : undefined,
			getPrototypeAtAddress: () => undefined,
		} as unknown as SemanticStore;
		const engine = {
			getAnalysisGeneration: () => 4,
			getFunctions: () => [caller, callee],
			getFunctionBodyStatus: () => 'materialized',
			isAnalysisComplete: () => true,
			getRegisterName: (registerId: number) => registerId === 10 ? 'rcx' : registerId === 11 ? 'eax' : undefined,
		} as unknown as DisassemblerEngine;

		const result = collectWholeProgramPropagationInputs(engine, store);
		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.functionsMaterialized, 2);
		const callerInput = result.inputs.find(item => item.functionIdentity === 'function:0x140001000')!;
		assert.strictEqual(callerInput.calls?.length, 1);
		assert.strictEqual(callerInput.calls?.[0].arguments[0].argument.identity, 'call:0x140001000:arg:0:register:rcx');
		assert.strictEqual(callerInput.calls?.[0].result?.typeId, 'type:uint64');
		assert.strictEqual(callerInput.globalEffects?.[0].access, 'read');
		assert.strictEqual(callerInput.globalEffects?.[0].value?.widthBits, 64);
		assert.strictEqual(callerInput.barriers?.length, 1);
		assert.strictEqual(callerInput.fieldAccesses?.length, 1);
		assert.strictEqual(callerInput.fieldAccesses?.[0].offsetBytes, 8);
		assert.strictEqual(callerInput.fieldAccesses?.[0].base.identity, 'parameter:0:register:rcx');
		assert.strictEqual(callerInput.fieldAccesses?.[0].value?.widthBits, 32);
		assert.match(callerInput.barriers?.[0].reason ?? '', /No qualified R33 reference edge/);
		assert.ok(callerInput.constraints.some(item => item.kind === 'call'));
		assert.ok(callerInput.constraints.some(item => item.kind === 'global-read'));
		assert.ok(callerInput.constraints.some(item => item.kind === 'barrier'));
	});

	test('excludes partial bodies and reports an explicit incomplete-body collection barrier', () => {
		const partial: Function = {
			address: 0x140003000, name: 'partial', size: 4, endAddress: 0x140003004, callers: [], callees: [],
			instructions: [instruction({ address: 0x140003000, mnemonic: 'ret', size: 1, isRet: true })],
		};
		const graph = { query: () => [] } as unknown as TypedReferenceGraph;
		const store = {
			targetIdentity,
			getReferenceGraph: () => graph,
			getPrototype: () => undefined,
			getPrototypeAtAddress: () => undefined,
		} as unknown as SemanticStore;
		const engine = {
			getAnalysisGeneration: () => 5,
			getFunctions: () => [partial],
			getFunctionBodyStatus: () => 'partial',
			isAnalysisComplete: () => true,
		} as unknown as DisassemblerEngine;
		const result = collectWholeProgramPropagationInputs(engine, store);
		assert.strictEqual(result.status, 'partial');
		assert.strictEqual(result.functionsMaterialized, 0);
		assert.deepStrictEqual(result.incompleteFunctions, ['function:0x140003000']);
		assert.deepStrictEqual(result.inputs, []);
		assert.ok(result.partialReasons.includes('incomplete-function-body:function:0x140003000'));
	});
});

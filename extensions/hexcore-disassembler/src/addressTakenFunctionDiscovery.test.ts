/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import {
	collectAddressTakenFunctionCandidates,
	validateAddressTakenFunctionExtent,
} from './addressTakenFunctionDiscovery';
import { CapstoneWrapper, type DisassembledInstruction } from './capstoneWrapper';

suite('address-taken function discovery', () => {
	let capstone: CapstoneWrapper;
	let evidence: DisassembledInstruction[];

	suiteSetup(async () => {
		capstone = new CapstoneWrapper();
		await capstone.initialize('x64', { detail: true });
		evidence = await capstone.disassemble(
			Buffer.from('488d1d9af3ffff48895810', 'hex'),
			0x140001e5f,
			2,
		);
	});

	suiteTeardown(() => capstone.dispose());

	const collect = (overrides: Partial<Parameters<typeof collectAddressTakenFunctionCandidates>[1]> = {}) =>
		collectAddressTakenFunctionCandidates(evidence, {
			isExecutableAddress: address => address >= 0x140001000 && address < 0x140002000,
			registerName: registerId => capstone.getRegisterName(registerId),
			knownFunctions: [],
			...overrides,
		});

	test('collects the race_worker LEA-to-store callback with provenance', () => {
		const candidates = collect();
		assert.strictEqual(candidates.length, 1);
		assert.deepStrictEqual(candidates[0], {
			address: 0x140001200,
			leaAddress: 0x140001e5f,
			storeAddress: 0x140001e66,
			registerId: candidates[0].registerId,
			confidence: 0.9,
			reasons: ['rip-relative-lea', 'stored-function-pointer', 'executable-target'],
		});
	});

	test('does not promote a LEA into non-executable data', () => {
		assert.deepStrictEqual(collect({ isExecutableAddress: () => false }), []);
	});

	test('does not split an address-taken internal label from its owning function', () => {
		assert.deepStrictEqual(collect({
			knownFunctions: [{ start: 0x1400011f0, endExclusive: 0x140001210 }],
		}), []);
	});

	test('requires a bounded memory consumer instead of promoting every RIP-relative LEA', () => {
		assert.deepStrictEqual(collectAddressTakenFunctionCandidates(evidence.slice(0, 1), {
			isExecutableAddress: () => true,
			registerName: registerId => capstone.getRegisterName(registerId),
			knownFunctions: [],
		}), []);
	});

	test('validates the exact worker extent without absorbing the adjacent function', async () => {
		const worker = await capstone.disassemble(
			Buffer.from('85d27e0a8bc2ff014883e80175f8c3cc48895c241055', 'hex'),
			0x140001200,
			32,
		);
		assert.deepStrictEqual(validateAddressTakenFunctionExtent(
			0x140001200,
			worker,
			0x140001210,
		), {
			semanticEnd: 0x14000120f,
			endExclusive: 0x140001210,
			terminalAddress: 0x14000120e,
			terminalKind: 'return',
		});
	});

	test('rejects decodable bytes without a return terminal', async () => {
		const randomLooking = await capstone.disassemble(Buffer.from('4889c84883c00190', 'hex'), 0x401000, 16);
		assert.strictEqual(validateAddressTakenFunctionExtent(0x401000, randomLooking), undefined);
	});
});

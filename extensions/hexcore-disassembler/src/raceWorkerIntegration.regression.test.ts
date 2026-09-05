/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') { return '__vscode_mock_race_worker__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache['__vscode_mock_race_worker__'] = {
	id: '__vscode_mock_race_worker__',
	filename: '__vscode_mock_race_worker__',
	loaded: true,
	exports: {
		workspace: {
			getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }),
			onDidChangeConfiguration: () => ({ dispose() { /* noop */ } }),
		},
		commands: { executeCommand: async () => undefined },
		extensions: { getExtension: () => undefined },
		Uri: { file: (file: string) => ({ fsPath: file, scheme: 'file' }) },
	},
} as unknown as NodeModule;

const { DisassemblerEngine } = require('./disassemblerEngine');

suite('race_worker address-taken integration regression', () => {
	test('promotes the callback and assigns [0x1200, 0x1210) without adjacent bleed', async () => {
		const base = 0x140001000;
		const worker = 0x140001200;
		const adjacent = 0x140001210;
		const lea = 0x140001e5f;
		const store = 0x140001e66;
		const image = Buffer.alloc(0x1000, 0xcc);
		image.set(Buffer.from('85d27e0a8bc2ff014883e80175f8c3cc', 'hex'), worker - base);
		image.set(Buffer.from('48895c24105556574154415541564157c3', 'hex'), adjacent - base);
		image.set(Buffer.from('488d1d9af3ffff48895810', 'hex'), lea - base);

		const engine = new DisassemblerEngine();
		try {
			engine.loadBuffer(image, base, 'x64');
			await (engine as any).ensureCapstoneInitialized();
			const functions = (engine as any).functions as Map<number, any>;
			functions.clear();
			functions.set(adjacent, {
				address: adjacent, name: 'decode_mode', size: 0x20, endAddress: adjacent + 0x20,
				instructions: [], callers: [], callees: [],
			});
			functions.set(lea, {
				address: lea, name: 'callback_setup', size: 11, endAddress: lea + 11,
				instructions: [{
					address: lea, bytes: image.subarray(lea - base, lea - base + 7),
					mnemonic: 'lea', opStr: 'rbx, [rip - 0xc66]', size: 7,
					isCall: false, isJump: false, isRet: false, isConditional: false,
				}], callers: [], callees: [],
			});

			assert.strictEqual(await (engine as any).discoverAddressTakenFunctionEntries(), 1);
			const recovered = engine.getFunctionAt(worker)!;
			assert.ok(recovered, 'race_worker must be present in the function index');
			assert.strictEqual(recovered.endAddress, adjacent);
			assert.strictEqual(recovered.size, 0x10);
			assert.ok(recovered.instructions.every((instruction: { address: number }) => instruction.address < adjacent));
			assert.strictEqual(recovered.instructions.at(-1)?.address, 0x14000120e);
			assert.deepStrictEqual(engine.getFunctionDiscoveryEvidence(worker), [{
				kind: 'address-taken',
				sourceAddress: lea,
				consumerAddress: store,
				confidence: 0.9,
			}]);
		} finally {
			engine.dispose();
		}
	});
});

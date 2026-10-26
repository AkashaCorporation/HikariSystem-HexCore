/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import type { StringReference } from './disassemblerEngine';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') { return '__vscode_mock_string_query_slice__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache.__vscode_mock_string_query_slice__ = {
	id: '__vscode_mock_string_query_slice__',
	filename: '__vscode_mock_string_query_slice__',
	loaded: true,
	exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } },
} as NodeModule;
const { DisassemblerEngine, deriveInteriorStringQuerySlices } = require('./disassemblerEngine') as typeof import('./disassemblerEngine');

suite('aggregated string query slices', () => {
	test('derives the exact ASCII address of a Rust interior string', () => {
		const parent: StringReference = {
			address: 0x140876298,
			fileOffset: 0x874e98,
			string: 'actionportnoncecert_thumbprintMessageForWebviewMessageForTcpSocket',
			encoding: 'ascii',
			references: [0x14025c4a2],
			terminated: false,
		};
		const slices = deriveInteriorStringQuerySlices(parent, 'cert_thumbprint');
		assert.strictEqual(slices.length, 1);
		assert.strictEqual(slices[0].address, 0x1408762a7);
		assert.strictEqual(slices[0].fileOffset, 0x874ea7);
		assert.strictEqual(slices[0].parentStringAddress, parent.address);
		assert.strictEqual(slices[0].querySliceOffsetBytes, 15);
		assert.strictEqual(slices[0].evidenceClass, 'referenced-interior-slice');
	});

	test('accounts for UTF-16 byte width and does not duplicate a prefix match', () => {
		const parent: StringReference = {
			address: 0x1000, string: 'alphabeta', encoding: 'unicode', references: [],
		};
		assert.strictEqual(deriveInteriorStringQuerySlices(parent, 'alpha').length, 0);
		assert.strictEqual(deriveInteriorStringQuerySlices(parent, 'beta')[0].address, 0x1000 + 5 * 2);
	});

	test('maps an interior xref to its indexed owner without materializing it', () => {
		const engine = new DisassemblerEngine();
		try {
			(engine as any).functions.set(0x1402a7ab0, {
				address: 0x1402a7ab0, endAddress: 0x1402a7dcc, size: 0x31c,
				name: 'sub_1402A7AB0', instructions: [], callers: [], callees: [],
			});
			assert.strictEqual(engine.getFunctionContaining(0x1402a7b71)?.address, 0x1402a7ab0);
			assert.strictEqual(engine.getFunctionContaining(0x1402a7dcc), undefined);
		} finally {
			engine.dispose();
		}
	});
});

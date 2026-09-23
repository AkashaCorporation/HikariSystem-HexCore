/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import type { DisassemblerEngine } from './disassemblerEngine';
import { runSessionExport } from './sessionExport';

suite('session export command', () => {
	function engine(): DisassemblerEngine {
		const functions = [
			{ address: 0x1000, endAddress: 0x1010, name: 'first', size: 16, instructions: [], callers: [], callees: [0x2000] },
			{ address: 0x2000, endAddress: 0x2010, name: 'second', size: 16, instructions: [], callers: [0x1004], callees: [] },
		];
		return {
			getFunctions: () => functions,
			getSessionStore: () => ({
				getAnalysisSession: () => ({ id: 'session-1', generation: 3 }),
				getAnalysisUniverseManifest: () => ({ universeSha256: 'abc', materializedFunctions: [{}] }),
			}),
			getFunctionBodyStatus: (address: number) => address === 0x1000 ? 'lazy' : 'materialized',
			peekFunctionBodyCompleteness: () => undefined,
			getFunctionDiscoveryEvidence: () => [{ kind: 'direct-call' }],
			getAllCrossReferences: () => [{ from: 0x1004, to: 0x2000, type: 'call' }],
			getImports: () => [{ name: 'KERNEL32.dll', functions: [{ name: 'ExitProcess', address: 0x3000 }] }],
			getStrings: () => [{ address: 0x4000, string: 'hello', encoding: 'ascii', references: [0x1008] }],
			getSections: () => [{ name: '.text', virtualAddress: 0x1000, virtualSize: 0x2000, rawAddress: 0x400, rawSize: 0x2000, permissions: 'r-x', isCode: true, isData: false, isReadable: true, isWritable: false, isExecutable: true, characteristics: 0 }],
			getPdataEntries: () => [{ beginAddress: 0x1000, endAddress: 0x1010, unwindInfoAddress: 0x5000 }],
			getBaseAddress: () => 0x140000000,
			getFilePath: () => 'C:\\fixture.exe',
			getFileInfo: () => ({ format: 'PE64', architecture: 'x64', entryPoint: 0x140001000, baseAddress: 0x140000000, imageSize: 0x5000 }),
			getArchitecture: () => 'x64',
			isAnalysisComplete: () => true,
			getAnalysisGeneration: () => 2,
			getAnalysisClosureRestoration: () => ({ status: 'none', requested: 0, restored: 0, failed: [] }),
		} as unknown as DisassemblerEngine;
	}

	test('exports exact addresses, owners, callers and unwind VA/RVA deterministically', () => {
		const first = runSessionExport(engine());
		const second = runSessionExport(engine());
		assert.strictEqual(first.status, 'ok');
		assert.strictEqual(first.outputHash, second.outputHash);
		assert.strictEqual((first.collections.functions.items[0] as any).address, '0x1000');
		assert.strictEqual((first.collections.xrefs.items[0] as any).ownerFunction, '0x1000');
		assert.deepStrictEqual((first.collections.callers.items[1] as any).callerSites, ['0x1004']);
		assert.strictEqual((first.collections.unwind.items[0] as any).beginAddress, '0x140001000');
	});

	test('bounds every selected collection and reports truncation', () => {
		const result = runSessionExport(engine(), { include: ['functions', 'callers'], limit: 1 });
		assert.strictEqual(result.status, 'partial');
		assert.deepStrictEqual(result.truncatedCollections, ['functions', 'callers']);
		assert.strictEqual(result.collections.functions.returned, 1);
		assert.strictEqual(result.collections.xrefs, undefined);
	});

	test('rejects unknown collections and unsupported formats', () => {
		assert.throws(() => runSessionExport(engine(), { include: ['bogus' as any] }));
		assert.throws(() => runSessionExport(engine(), { format: 'csv' as any }));
	});
});

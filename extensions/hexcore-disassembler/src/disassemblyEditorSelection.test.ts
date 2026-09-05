import * as assert from 'assert';

suite('Disassembly editor selection', () => {
	test('tree navigation records a function without an active editor webview', () => {
		const Module = require('module');
		const originalResolveFilename = Module._resolveFilename;
		const mockId = '__vscode_mock_disassembly_selection__';
		Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
			if (request === 'vscode') { return mockId; }
			return originalResolveFilename.call(this, request, parent, isMain, options);
		};
		require.cache[mockId] = {
			id: mockId,
			filename: mockId,
			loaded: true,
			exports: {},
		} as unknown as NodeModule;

		try {
			const modulePath = require.resolve('./disassemblyEditor');
			delete require.cache[modulePath];
			const { DisassemblyEditorProvider } = require(modulePath);
			const engine = {
				getFunctions: () => [{ address: 0x140001000, endAddress: 0x140001100 }],
			};
			const provider = new DisassemblyEditorProvider({}, engine, {});
			provider.navigateToAddress(0x140001050);

			assert.strictEqual(provider.getCurrentAddress(), 0x140001050);
			assert.strictEqual(provider.getCurrentFunctionAddress(), 0x140001000);
		} finally {
			Module._resolveFilename = originalResolveFilename;
			delete require.cache[mockId];
		}
	});
});

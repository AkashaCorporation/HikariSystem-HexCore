import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') { return '__vscode_mock_raw_arch__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache['__vscode_mock_raw_arch__'] = {
	id: '__vscode_mock_raw_arch__', filename: '__vscode_mock_raw_arch__', loaded: true,
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

suite('raw binary architecture override', () => {
	test('loads a headerless blob as explicit x86 at the requested base', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-raw-arch-'));
		const file = path.join(dir, 'shellcode.bin');
		const engine = new DisassemblerEngine();
		try {
			fs.writeFileSync(file, Buffer.from([0x55, 0x8b, 0xec, 0xc3]));
			assert.strictEqual(await engine.loadFile(file, { architecture: 'x86', baseAddress: 0x1000 }), true);
			assert.strictEqual(engine.getArchitecture(), 'x86');
			assert.strictEqual(engine.getBaseAddress(), 0x1000);
			assert.strictEqual(engine.getSections()[0].virtualAddress, 0x1000);
		} finally {
			engine.dispose();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

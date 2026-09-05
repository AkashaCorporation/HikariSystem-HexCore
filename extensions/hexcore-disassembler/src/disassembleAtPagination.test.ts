import * as assert from 'assert';
import * as path from 'path';

let maxCount: number;
let parseDisassembleAtAddress: (args: unknown) => {
	address: number;
	count: number;
	effectiveCount: number;
	countingDomain: 'byte-range' | 'instruction-count';
	endExclusive?: number;
	stopAtFunctionBoundary: boolean;
};
let computeContextRecovery: (engine: any, targetAddress: number, contextCount: number, maxInstructionSize: number) => Promise<any>;

function installVscodeMock(): void {
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_disassemble_pagination__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	class TreeItem { constructor(public label?: unknown, public collapsibleState?: unknown) { } }
	class EventEmitter { event = () => ({ dispose() { } }); fire() { } dispose() { } }
	class ThemeIcon { constructor(public id?: unknown) { } }
	class ThemeColor { constructor(public id?: unknown) { } }
	require.cache['__vscode_mock_disassemble_pagination__'] = {
		id: '__vscode_mock_disassemble_pagination__',
		filename: '__vscode_mock_disassemble_pagination__',
		loaded: true,
		exports: {
			commands: { getCommands: async () => [], executeCommand: async () => undefined, registerCommand: () => ({ dispose() { } }) },
			workspace: { getConfiguration: () => ({ get: (_key: string, value: unknown) => value }), workspaceFolders: undefined },
			extensions: { getExtension: () => undefined },
			Uri: { file: (file: string) => ({ fsPath: file, scheme: 'file' }) },
			window: { createOutputChannel: () => ({ appendLine() { }, show() { }, dispose() { } }) },
			TreeItem, EventEmitter, ThemeIcon, ThemeColor,
			TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
		},
	} as unknown as NodeModule;
}

suite('disassembleAtHeadless pagination', () => {
	suiteSetup(() => {
		installVscodeMock();
		const extension = require(path.resolve(__dirname, 'extension'));
		maxCount = extension.MAX_DISASSEMBLE_AT_COUNT;
		parseDisassembleAtAddress = extension.parseDisassembleAtAddress;
		computeContextRecovery = extension.computeContextRecovery;
	});

	test('preserves the requested count and exposes the effective page limit', () => {
		const parsed = parseDisassembleAtAddress({ address: '0x401000', count: 25000 });
		assert.strictEqual(parsed.count, 25000);
		assert.strictEqual(parsed.effectiveCount, maxCount);
	});

	test('does not alter counts already inside the supported page size', () => {
		const parsed = parseDisassembleAtAddress({ address: '0x401000', count: 4096 });
		assert.strictEqual(parsed.count, 4096);
		assert.strictEqual(parsed.effectiveCount, 4096);
	});

	test('uses an explicit half-open byte range without borrowing an instruction count', () => {
		const parsed = parseDisassembleAtAddress({
			address: '0x14018D720',
			endExclusive: '0x14018DF4A',
		});
		assert.strictEqual(parsed.address, 0x14018D720);
		assert.strictEqual(parsed.endExclusive, 0x14018DF4A);
		assert.strictEqual(parsed.endExclusive! - parsed.address, 2090);
		assert.strictEqual(parsed.countingDomain, 'byte-range');
		assert.strictEqual(parsed.count, maxCount);
	});

	test('marks function-boundary mode as a byte-range contract', () => {
		const parsed = parseDisassembleAtAddress({
			address: '0x140190370',
			stopAtFunctionBoundary: true,
		});
		assert.strictEqual(parsed.stopAtFunctionBoundary, true);
		assert.strictEqual(parsed.countingDomain, 'byte-range');
		assert.strictEqual(parsed.count, maxCount);
	});

	test('rejects a non-increasing explicit endpoint', () => {
		assert.throws(() => parseDisassembleAtAddress({
			address: '0x401000',
			endExclusive: '0x401000',
		}), /must be greater/);
	});

	test('rejects a decoded prefix that does not reach the requested target', async () => {
		const engine = {
			getBaseAddress: () => 0x400000,
			disassembleRange: async () => [
				{ address: 0x40B320, size: 2 },
				{ address: 0x40B322, size: 1 }
			]
		};
		const recovered = await computeContextRecovery(engine, 0x40BDAC, 180, 15);
		assert.deepStrictEqual(recovered.instructions, []);
		assert.strictEqual(recovered.summary.status, 'unavailable');
		assert.strictEqual(recovered.summary.contiguous, false);
		assert.strictEqual(recovered.summary.reason, 'no-contiguous-predecessor');
	});

	test('returns only the contiguous suffix ending at the target', async () => {
		const engine = {
			getBaseAddress: () => 0x400000,
			disassembleRange: async () => [
				{ address: 0x401000, size: 2 },
				{ address: 0x401002, size: 3 },
				{ address: 0x401005, size: 1 }
			]
		};
		const recovered = await computeContextRecovery(engine, 0x401006, 2, 15);
		assert.deepStrictEqual(recovered.instructions.map((i: any) => i.address), [0x401002, 0x401005]);
		assert.strictEqual(recovered.summary.status, 'complete');
		assert.strictEqual(recovered.summary.contiguous, true);
	});
});

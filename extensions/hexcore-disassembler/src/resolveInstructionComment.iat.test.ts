/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * PE IAT naming in the INTERACTIVE comment path (`resolveInstructionComment`). v3.8.5 follow-up.
 *
 * The engine post-pass `applyIatCallNames` stamps `instruction.comment` (rendered by the function
 * view + headless). A SECOND interactive path -- the `disassembleAtInstruction` handler -- instead
 * re-disassembles fresh via `disassembleRange` and derives each comment through
 * `resolveInstructionComment`, which previously only resolved a `targetAddress` (undefined for
 * `[...]` memory operands), so IAT indirect calls stayed unannotated there.
 *
 * The fix wires the SHARED `decodeIatOperandVA` (exported from the engine) into
 * `resolveInstructionComment` as the LOWEST-priority resolution, PE-gated, additive. These tests
 * load the real `resolveInstructionComment` from `extension.ts` (with a fuller vscode mock, since
 * requiring it transitively pulls in the tree providers) and prove:
 *   - PE32 absolute + PE64 rip-relative IAT operands resolve to `<dll>!<api>`;
 *   - non-IAT operands (`call eax`, `[rsp + 0x20]`) get NO IAT name;
 *   - ELF (isPE=false) is a no-op;
 *   - PRIORITY ORDERING: a string-xref / function / user comment is NEVER overridden by IAT.
 */

import * as assert from 'assert';

/**
 * Fuller vscode mock. Requiring extension.ts transitively loads functionTree.ts and the other tree
 * providers, which `extends vscode.TreeItem` and construct `EventEmitter`s at module-load time, so
 * the mock must expose those classes (not just the config/window stubs the engine needs).
 */
function installVscodeMock(): void {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_ric_iat__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	class TreeItem { label: unknown; collapsibleState: unknown; constructor(label?: unknown, collapsibleState?: unknown) { this.label = label; this.collapsibleState = collapsibleState; } }
	class EventEmitter { event = () => ({ dispose() { /* noop */ } }); fire() { /* noop */ } dispose() { /* noop */ } }
	class ThemeIcon { id: unknown; constructor(id?: unknown) { this.id = id; } }
	class ThemeColor { id: unknown; constructor(id?: unknown) { this.id = id; } }
	require.cache['__vscode_mock_ric_iat__'] = {
		id: '__vscode_mock_ric_iat__',
		filename: '__vscode_mock_ric_iat__',
		loaded: true,
		exports: {
			commands: { getCommands: async () => [], executeCommand: async () => undefined, registerCommand: () => ({ dispose() { /* noop */ } }) },
			workspace: { getConfiguration: () => ({ get: (_k: string, def: unknown) => def }), onDidChangeConfiguration: () => ({ dispose() { /* noop */ } }), workspaceFolders: undefined },
			extensions: { getExtension: () => undefined },
			Uri: { file: (f: string) => ({ fsPath: f, scheme: 'file' }) },
			window: {
				showInformationMessage: () => { }, showWarningMessage: () => { }, showErrorMessage: () => { },
				withProgress: async (_o: unknown, t: (p: { report: () => void }) => unknown) => t({ report: () => { } }),
				createOutputChannel: () => ({ appendLine: () => { }, append: () => { }, show: () => { }, clear: () => { }, replace: () => { }, dispose: () => { } }),
				createTreeView: () => ({ dispose() { /* noop */ } }), registerTreeDataProvider: () => ({ dispose() { /* noop */ } })
			},
			TreeItem, EventEmitter, ThemeIcon, ThemeColor,
			TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 }
		}
	} as unknown as NodeModule;
}

installVscodeMock();
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { resolveInstructionComment } = require('./extension');

type StrMap = Map<number, { string: string; address: number }>;
type FnMap = Map<number, { name: string; address: number }>;
type Imports = { name: string; functions: { name: string; address: number }[] }[];

const KERNEL32: Imports = [{
	name: 'KERNEL32.dll',
	functions: [
		{ name: 'ReadFile', address: 0x402000 },
		{ name: 'WriteFile', address: 0x402004 },
		{ name: 'OpenProcess', address: 0x4000e020 }
	]
}];

const noStr: StrMap = new Map();
const noFn: FnMap = new Map();
const noUser = new Map<number, string>();

suite('resolveInstructionComment: PE IAT indirect-call naming (v3.8.5)', () => {

	test('PE32 absolute `call dword ptr [IAT]` -> <dll>!<api>', () => {
		const ins = { mnemonic: 'call', opStr: 'dword ptr [0x402000]', size: 6, address: 0x401145 };
		const c = resolveInstructionComment(ins, noStr, noFn, KERNEL32, noUser, 0x401145, true);
		assert.strictEqual(c, 'KERNEL32.dll!ReadFile');
	});

	test('PE64 rip-relative `call qword ptr [rip + disp]` -> <dll>!<api>', () => {
		// nextVA = 0x4000108a + 6 = 0x40001090; + 0xcf90 = 0x4000e020 (OpenProcess slot).
		const ins = { mnemonic: 'call', opStr: 'qword ptr [rip + 0xcf90]', size: 6, address: 0x4000108a };
		assert.strictEqual((0x4000108a + 6 + 0xcf90) >>> 0, 0x4000e020, 'decode arithmetic sanity');
		const c = resolveInstructionComment(ins, noStr, noFn, KERNEL32, noUser, 0x4000108a, true);
		assert.strictEqual(c, 'KERNEL32.dll!OpenProcess');
	});

	test('non-IAT register-indirect `call eax` -> no IAT name', () => {
		const ins = { mnemonic: 'call', opStr: 'eax', size: 2, address: 0x401000 };
		const c = resolveInstructionComment(ins, noStr, noFn, KERNEL32, noUser, 0x401000, true);
		assert.strictEqual(c, '', 'register-indirect is not an IAT reference');
	});

	test('non-IAT `call [rsp + 0x20]` (stack slot) -> no IAT name', () => {
		const ins = { mnemonic: 'call', opStr: 'qword ptr [rsp + 0x20]', size: 5, address: 0x401000 };
		const c = resolveInstructionComment(ins, noStr, noFn, KERNEL32, noUser, 0x401000, true);
		assert.strictEqual(c, '', 'base-register memory operand is not an IAT reference');
	});

	test('a `call dword ptr [<addr-not-in-imports>]` -> no IAT name', () => {
		const ins = { mnemonic: 'call', opStr: 'dword ptr [0x499999]', size: 6, address: 0x401000 };
		const c = resolveInstructionComment(ins, noStr, noFn, KERNEL32, noUser, 0x401000, true);
		assert.strictEqual(c, '', 'absolute operand not matching any IAT slot is not named');
	});

	test('ELF (isPE=false) -> no-op even for a valid IAT-shaped operand', () => {
		const ins = { mnemonic: 'call', opStr: 'dword ptr [0x402000]', size: 6, address: 0x401145 };
		const c = resolveInstructionComment(ins, noStr, noFn, KERNEL32, noUser, 0x401145, false);
		assert.strictEqual(c, '', 'PE-gate: ELF keeps the @plt path, no IAT naming here');
	});

	// --- PRIORITY ORDERING: IAT is the LOWEST priority and never overrides ---

	test('PRIORITY: a string-xref on the SAME instruction is NOT overridden by IAT', () => {
		// An instruction that both has a targetAddress hitting a string AND looks like an IAT call.
		// The string must win; IAT must not run.
		const strings: StrMap = new Map([[0x403000, { string: 'hello', address: 0x403000 }]]);
		const ins = { targetAddress: 0x403000, mnemonic: 'call', opStr: 'dword ptr [0x402000]', size: 6, address: 0x401145 };
		const c = resolveInstructionComment(ins, strings, noFn, KERNEL32, noUser, 0x401145, true);
		assert.ok(c.includes('"hello"'), 'string-xref wins over IAT');
		assert.ok(!c.includes('ReadFile'), 'IAT name does not appear');
	});

	test('PRIORITY: a function-target resolution is NOT overridden by IAT', () => {
		const functions: FnMap = new Map([[0x401500, { name: 'my_func', address: 0x401500 }]]);
		const ins = { targetAddress: 0x401500, mnemonic: 'call', opStr: 'dword ptr [0x402000]', size: 6, address: 0x401145 };
		const c = resolveInstructionComment(ins, noStr, functions, KERNEL32, noUser, 0x401145, true);
		assert.ok(c.includes('func:my_func'), 'function-target wins over IAT');
		assert.ok(!c.includes('ReadFile'), 'IAT name does not appear');
	});

	test('PRIORITY: a direct-target import resolution is NOT overridden by IAT', () => {
		// targetAddress directly equals an import slot -> the existing import path resolves it.
		const ins = { targetAddress: 0x402000, mnemonic: 'call', opStr: 'dword ptr [0x402004]', size: 6, address: 0x401145 };
		const c = resolveInstructionComment(ins, noStr, noFn, KERNEL32, noUser, 0x401145, true);
		assert.ok(c.includes('import:KERNEL32.dll!ReadFile'), 'direct-target import (arrow form) wins');
		assert.ok(!c.endsWith('WriteFile'), 'the indirect IAT name (WriteFile) does not replace it');
	});

	test('PRIORITY: a user comment is preserved and IAT is appended after " | "', () => {
		const user = new Map<number, string>([[0x401145, 'my note']]);
		const ins = { mnemonic: 'call', opStr: 'dword ptr [0x402000]', size: 6, address: 0x401145 };
		const c = resolveInstructionComment(ins, noStr, noFn, KERNEL32, user, 0x401145, true);
		assert.strictEqual(c, 'my note | KERNEL32.dll!ReadFile', 'user comment first, IAT appended');
	});
});

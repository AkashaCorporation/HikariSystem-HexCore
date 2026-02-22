/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Bugfix: searchstring-xref-fix, Property 1: Fault Condition
// Referências de Strings Não Resolvidas via Byte-Pattern Scan
// **Validates: Requirements 1.1, 1.2, 1.3**
//
// This test is EXPECTED TO FAIL on unfixed code — failure confirms the bug exists.

import * as assert from 'assert';
import * as fc from 'fast-check';
import * as path from 'path';

/**
 * Minimal vscode mock — DisassemblerEngine imports 'vscode' for configuration.
 */
function installVscodeMock(): void {
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') {
			return '__vscode_mock__';
		}
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};

	require.cache['__vscode_mock__'] = {
		id: '__vscode_mock__',
		filename: '__vscode_mock__',
		loaded: true,
		exports: {
			commands: {
				getCommands: async () => [],
				executeCommand: async () => undefined,
				registerCommand: () => ({ dispose() { /* noop */ } })
			},
			workspace: {
				getConfiguration: () => ({
					get: (_key: string, def: unknown) => def
				}),
				workspaceFolders: undefined
			},
			extensions: { getExtension: () => undefined },
			Uri: { file: (f: string) => ({ fsPath: f, scheme: 'file' }) },
			window: {
				showInformationMessage: () => { },
				showErrorMessage: () => { },
				createOutputChannel: () => ({
					appendLine: () => { },
					show: () => { },
					dispose: () => { }
				})
			}
		}
	} as unknown as NodeModule;
}


// ── Interfaces matching DisassemblerEngine internals ──

interface StringReference {
	address: number;
	string: string;
	encoding: 'ascii' | 'unicode';
	references: number[];
}

interface Section {
	name: string;
	virtualAddress: number;
	virtualSize: number;
	rawAddress: number;
	rawSize: number;
	characteristics: number;
	permissions: string;
	isCode: boolean;
	isData: boolean;
	isReadable: boolean;
	isWritable: boolean;
	isExecutable: boolean;
}

// ── Helpers to build synthetic PE64 buffers ──

/**
 * Encode a LEA RIP-relative instruction: `48 8D 0D <disp32>`
 * instrVA + 7 + disp32 = targetVA  →  disp32 = targetVA - instrVA - 7
 */
function encodeLEA_RIPRelative(instrVA: number, targetVA: number): Buffer {
	const instrSize = 7; // REX.W + opcode + ModR/M + disp32
	const disp32 = targetVA - (instrVA + instrSize);
	const buf = Buffer.alloc(instrSize);
	buf[0] = 0x48; // REX.W
	buf[1] = 0x8D; // LEA opcode
	buf[2] = 0x0D; // ModR/M: mod=00, reg=rcx(001), rm=101 (RIP-relative)
	buf.writeInt32LE(disp32, 3);
	return buf;
}

/**
 * Build a synthetic buffer simulating a PE64 binary with:
 * - .rdata section containing a known string at a specific VA
 * - .text section containing LEA RIP-relative bytes referencing that string
 *
 * Returns all the pieces needed to inject into a DisassemblerEngine instance.
 */
function buildSyntheticPE64(params: {
	baseAddress: number;
	textRawOffset: number;
	textVA: number;
	textSize: number;
	rdataRawOffset: number;
	rdataVA: number;
	rdataSize: number;
	stringText: string;
	/** Offset within .rdata where the string is placed */
	stringOffsetInRdata: number;
	/** Offsets within .text where LEA instructions are placed (relative to .text start) */
	leaOffsetsInText: number[];
}): {
	fileBuffer: Buffer;
	sections: Section[];
	strings: Map<number, StringReference>;
	stringVA: number;
	leaVAs: number[];
} {
	const totalSize = Math.max(
		params.rdataRawOffset + params.rdataSize,
		params.textRawOffset + params.textSize,
		4096
	);
	const fileBuffer = Buffer.alloc(totalSize, 0);

	// Place string in .rdata
	const stringRawAddr = params.rdataRawOffset + params.stringOffsetInRdata;
	fileBuffer.write(params.stringText, stringRawAddr, 'ascii');
	fileBuffer[stringRawAddr + params.stringText.length] = 0; // null terminator

	const stringVA = params.rdataVA + params.stringOffsetInRdata;

	// Place LEA instructions in .text
	const leaVAs: number[] = [];
	for (const leaOff of params.leaOffsetsInText) {
		const instrVA = params.textVA + leaOff;
		const leaBytes = encodeLEA_RIPRelative(instrVA, stringVA);
		leaBytes.copy(fileBuffer, params.textRawOffset + leaOff);
		leaVAs.push(instrVA);
	}

	const sections: Section[] = [
		{
			name: '.text',
			virtualAddress: params.textVA,
			virtualSize: params.textSize,
			rawAddress: params.textRawOffset,
			rawSize: params.textSize,
			characteristics: 0x60000020,
			permissions: 'r-x',
			isCode: true,
			isData: false,
			isReadable: true,
			isWritable: false,
			isExecutable: true,
		},
		{
			name: '.rdata',
			virtualAddress: params.rdataVA,
			virtualSize: params.rdataSize,
			rawAddress: params.rdataRawOffset,
			rawSize: params.rdataSize,
			characteristics: 0x40000040,
			permissions: 'r--',
			isCode: false,
			isData: true,
			isReadable: true,
			isWritable: false,
			isExecutable: false,
		}
	];

	const strings = new Map<number, StringReference>();
	strings.set(stringVA, {
		address: stringVA,
		string: params.stringText,
		encoding: 'ascii',
		references: [], // empty — this is the bug condition
	});

	return { fileBuffer, sections, strings, stringVA, leaVAs };
}


// ── Test Suite ──

suite('Property 1: Fault Condition — String Xref References Empty Despite LEA in .text', () => {

	let DisassemblerEngine: any;

	suiteSetup(() => {
		installVscodeMock();
		const modulePath = path.resolve(__dirname, 'disassemblerEngine');
		const mod = require(modulePath);
		DisassemblerEngine = mod.DisassemblerEngine;
	});

	/**
	 * **Validates: Requirements 1.1, 1.2, 1.3**
	 *
	 * For any string placed in .rdata whose address is referenced by a
	 * LEA RIP-relative instruction in .text, searchStringReferences MUST
	 * return that instruction address in the references array.
	 *
	 * On UNFIXED code this WILL FAIL because searchStringReferences only
	 * filters this.strings by text — it does not scan .text bytes.
	 */
	test('searchStringReferences finds LEA RIP-relative xrefs in .text (PBT)', async () => {
		// PE64 base address
		const baseAddress = 0x140000000;

		await fc.assert(
			fc.asyncProperty(
				// Generate random but valid section layout
				fc.record({
					// String offset within .rdata (0..0x1000 range, leave room for string)
					stringOffset: fc.integer({ min: 0x10, max: 0xF00 }),
					// Number of LEA references (1..4)
					leaCount: fc.integer({ min: 1, max: 4 }),
				}).chain(({ stringOffset, leaCount }) =>
					fc.record({
						stringOffset: fc.constant(stringOffset),
						// Generate distinct LEA offsets within .text, each 7-byte aligned
						// Ensure they don't overlap (each LEA is 7 bytes)
						leaOffsets: fc.uniqueArray(
							fc.integer({ min: 0x10, max: 0x3F00 }),
							{ minLength: leaCount, maxLength: leaCount }
						).filter(offsets => {
							// Ensure no two LEA instructions overlap (each is 7 bytes)
							const sorted = [...offsets].sort((a, b) => a - b);
							for (let i = 1; i < sorted.length; i++) {
								if (sorted[i] - sorted[i - 1] < 7) {
									return false;
								}
							}
							return true;
						}),
						stringText: fc.stringOf(
							fc.char().filter(c => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) < 0x7F),
							{ minLength: 3, maxLength: 30 }
						),
					})
				),
				async ({ stringOffset, leaOffsets, stringText }) => {
					// Layout: .text at VA 0x1000, raw 0x200; .rdata at VA 0x5000, raw 0x2000
					const textVA = baseAddress + 0x1000;
					const rdataVA = baseAddress + 0x5000;

					const { fileBuffer, sections, strings, leaVAs } = buildSyntheticPE64({
						baseAddress,
						textRawOffset: 0x200,
						textVA,
						textSize: 0x4000,
						rdataRawOffset: 0x2000,
						rdataVA,
						rdataSize: 0x2000,
						stringText,
						stringOffsetInRdata: stringOffset,
						leaOffsetsInText: leaOffsets,
					});

					// Create engine and inject private fields
					const engine = new DisassemblerEngine();
					(engine as any).fileBuffer = fileBuffer;
					(engine as any).sections = sections;
					(engine as any).strings = strings;
					(engine as any).instructions = new Map(); // EMPTY — bug condition
					(engine as any).baseAddress = baseAddress;
					(engine as any).architecture = 'x64';

					// Call the method under test
					const results = await engine.searchStringReferences(stringText);

					// Must find the string
					assert.ok(
						results.length > 0,
						`Expected to find string "${stringText}" but got 0 results`
					);

					const match = results[0];

					// The references array MUST contain all LEA instruction addresses
					for (const leaVA of leaVAs) {
						const leaHex = '0x' + leaVA.toString(16);
						assert.ok(
							match.references.includes(leaVA),
							`Expected references to include LEA at ${leaHex}, ` +
							`but references = [${match.references.map((r: number) => '0x' + r.toString(16)).join(', ')}]`
						);
					}
				}
			),
			{ numRuns: 50 }
		);
	});

	/**
	 * **Validates: Requirements 1.1**
	 *
	 * Deterministic test: single LEA RIP-relative reference to a known string.
	 * Confirms the bug with a concrete, reproducible example.
	 */
	test('searchStringReferences returns empty references despite LEA in .text (deterministic)', async () => {
		const baseAddress = 0x140000000;
		const textVA = baseAddress + 0x1000;
		const rdataVA = baseAddress + 0x5000;

		const { fileBuffer, sections, strings, leaVAs } = buildSyntheticPE64({
			baseAddress,
			textRawOffset: 0x200,
			textVA,
			textSize: 0x4000,
			rdataRawOffset: 0x2000,
			rdataVA,
			rdataSize: 0x2000,
			stringText: 'Loading texture',
			stringOffsetInRdata: 0x200,
			leaOffsetsInText: [0x100],
		});

		const engine = new DisassemblerEngine();
		(engine as any).fileBuffer = fileBuffer;
		(engine as any).sections = sections;
		(engine as any).strings = strings;
		(engine as any).instructions = new Map(); // EMPTY — bug condition
		(engine as any).baseAddress = baseAddress;
		(engine as any).architecture = 'x64';

		const results = await engine.searchStringReferences('Loading');

		assert.strictEqual(results.length, 1, 'Should find exactly one matching string');

		const match = results[0];
		assert.strictEqual(match.string, 'Loading texture');

		// This assertion is the bug detector:
		// On unfixed code, references will be [] because searchStringReferences
		// only filters this.strings by text — it does NOT scan .text bytes.
		const expectedLEA = leaVAs[0];
		assert.ok(
			match.references.length > 0,
			`Bug confirmed: references is empty []. Expected at least LEA at 0x${expectedLEA.toString(16)}. ` +
			`searchStringReferences does not scan .text bytes for LEA/MOV instructions.`
		);

		assert.ok(
			match.references.includes(expectedLEA),
			`Expected references to include 0x${expectedLEA.toString(16)}, ` +
			`got [${match.references.map((r: number) => '0x' + r.toString(16)).join(', ')}]`
		);
	});
});

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Bugfix: searchstring-xref-fix, Property 2: Preservation
// Comportamento Existente Inalterado para Entradas Não-Buggy
// **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
//
// These tests MUST PASS on the unfixed code — they capture baseline behavior.

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

interface Instruction {
	address: number;
	bytes: Buffer;
	mnemonic: string;
	opStr: string;
	size: number;
	comment?: string;
	isCall: boolean;
	isJump: boolean;
	isRet: boolean;
	isConditional: boolean;
	targetAddress?: number;
}

// ── Test Suite ──

suite('Property 2: Preservation — Existing Behavior Unchanged for Non-Buggy Inputs', () => {

	let DisassemblerEngine: any;

	suiteSetup(() => {
		installVscodeMock();
		const modulePath = path.resolve(__dirname, 'disassemblerEngine');
		const mod = require(modulePath);
		DisassemblerEngine = mod.DisassemblerEngine;
	});

	/**
	 * **Validates: Requirements 3.3**
	 *
	 * For any random query that does not match any string in the map,
	 * searchStringReferences MUST return an empty array.
	 */
	test('PBT: random queries that do not match any string return empty results', async () => {
		const baseAddress = 0x400000;

		// Fixed set of known strings
		const knownStrings: StringReference[] = [
			{ address: baseAddress + 0x5000, string: 'Loading texture', encoding: 'ascii', references: [] },
			{ address: baseAddress + 0x5100, string: 'Error: file not found', encoding: 'ascii', references: [] },
			{ address: baseAddress + 0x5200, string: 'Connection established', encoding: 'ascii', references: [baseAddress + 0x1000] },
		];

		await fc.assert(
			fc.asyncProperty(
				// Generate random query strings that won't match any known string
				fc.stringOf(
					fc.constantFrom('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'z', 'q', 'x', 'j', 'k'),
					{ minLength: 8, maxLength: 20 }
				).filter(q => {
					const lq = q.toLowerCase();
					return !knownStrings.some(s => s.string.toLowerCase().includes(lq));
				}),
				async (randomQuery) => {
					const engine = new DisassemblerEngine();
					const stringsMap = new Map<number, StringReference>();
					for (const s of knownStrings) {
						stringsMap.set(s.address, { ...s, references: [...s.references] });
					}
					(engine as any).strings = stringsMap;
					(engine as any).baseAddress = baseAddress;

					const results = await engine.searchStringReferences(randomQuery);

					assert.ok(
						Array.isArray(results),
						'searchStringReferences must return an array'
					);
					assert.strictEqual(
						results.length,
						0,
						`Query "${randomQuery}" should not match any string, but got ${results.length} results`
					);
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 3.1**
	 *
	 * Strings that already have xrefs via this.instructions (populated by
	 * buildStringXrefs) must maintain their correct references after the method runs.
	 */
	test('PBT: existing xrefs via this.instructions are preserved by buildStringXrefs', async () => {
		const baseAddress = 0x140000000;

		await fc.assert(
			fc.asyncProperty(
				fc.record({
					// Number of strings (1..3)
					strCount: fc.integer({ min: 1, max: 3 }),
					// Number of instructions per string (1..3)
					instrPerStr: fc.integer({ min: 1, max: 3 }),
				}),
				async ({ strCount, instrPerStr }) => {
					const engine = new DisassemblerEngine();
					const stringsMap = new Map<number, StringReference>();
					const instructionsMap = new Map<number, Instruction>();
					const expectedRefs = new Map<number, number[]>();

					for (let si = 0; si < strCount; si++) {
						const strAddr = baseAddress + 0x5000 + si * 0x100;
						const strText = `TestString_${si}`;

						stringsMap.set(strAddr, {
							address: strAddr,
							string: strText,
							encoding: 'ascii',
							references: [], // will be populated by buildStringXrefs
						});

						const refs: number[] = [];
						for (let ii = 0; ii < instrPerStr; ii++) {
							const instrAddr = baseAddress + 0x1000 + si * 0x200 + ii * 0x10;
							const strAddrHex = '0x' + strAddr.toString(16);

							instructionsMap.set(instrAddr, {
								address: instrAddr,
								bytes: Buffer.alloc(7),
								mnemonic: 'lea',
								opStr: `rcx, [${strAddrHex}]`,
								size: 7,
								isCall: false,
								isJump: false,
								isRet: false,
								isConditional: false,
							});
							refs.push(instrAddr);
						}
						expectedRefs.set(strAddr, refs);
					}

					(engine as any).strings = stringsMap;
					(engine as any).instructions = instructionsMap;
					(engine as any).baseAddress = baseAddress;
					(engine as any).xrefs = [];

					// Call buildStringXrefs (private method)
					(engine as any).buildStringXrefs();

					// Verify references are populated correctly
					for (const [strAddr, expected] of expectedRefs) {
						const strRef = stringsMap.get(strAddr)!;
						for (const instrAddr of expected) {
							assert.ok(
								strRef.references.includes(instrAddr),
								`String at 0x${strAddr.toString(16)} should reference instruction at 0x${instrAddr.toString(16)}, ` +
								`but references = [${strRef.references.map(r => '0x' + r.toString(16)).join(', ')}]`
							);
						}
					}

					// Now verify searchStringReferences also returns these references
					for (const [strAddr, expected] of expectedRefs) {
						const strRef = stringsMap.get(strAddr)!;
						const results = await engine.searchStringReferences(strRef.string);
						assert.ok(results.length > 0, `Should find string "${strRef.string}"`);
						const match = results[0];
						for (const instrAddr of expected) {
							assert.ok(
								match.references.includes(instrAddr),
								`searchStringReferences for "${strRef.string}" should include ref 0x${instrAddr.toString(16)}`
							);
						}
					}
				}
			),
			{ numRuns: 50 }
		);
	});

	/**
	 * **Validates: Requirements 3.5**
	 *
	 * For any result from searchStringReferences, each match MUST have
	 * the correct output format: address (number), string (string),
	 * encoding ('ascii' | 'unicode'), references (number[]).
	 */
	test('PBT: output format validation for searchStringReferences results', async () => {
		const baseAddress = 0x400000;

		await fc.assert(
			fc.asyncProperty(
				fc.record({
					strText: fc.stringOf(
						fc.char().filter(c => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) < 0x7F),
						{ minLength: 4, maxLength: 30 }
					),
					encoding: fc.constantFrom('ascii' as const, 'unicode' as const),
					refCount: fc.integer({ min: 0, max: 3 }),
				}),
				async ({ strText, encoding, refCount }) => {
					const engine = new DisassemblerEngine();
					const stringsMap = new Map<number, StringReference>();
					const strAddr = baseAddress + 0x5000;

					const refs: number[] = [];
					for (let i = 0; i < refCount; i++) {
						refs.push(baseAddress + 0x1000 + i * 0x10);
					}

					stringsMap.set(strAddr, {
						address: strAddr,
						string: strText,
						encoding,
						references: refs,
					});

					(engine as any).strings = stringsMap;
					(engine as any).baseAddress = baseAddress;

					// Search with a substring of the string
					const query = strText.substring(0, Math.max(1, Math.floor(strText.length / 2)));
					const results = await engine.searchStringReferences(query);

					assert.ok(Array.isArray(results), 'Results must be an array');

					for (const match of results) {
						// address must be a number
						assert.strictEqual(
							typeof match.address,
							'number',
							`match.address must be a number, got ${typeof match.address}`
						);

						// string must be a string
						assert.strictEqual(
							typeof match.string,
							'string',
							`match.string must be a string, got ${typeof match.string}`
						);

						// encoding must be 'ascii' or 'unicode'
						assert.ok(
							match.encoding === 'ascii' || match.encoding === 'unicode',
							`match.encoding must be 'ascii' or 'unicode', got "${match.encoding}"`
						);

						// references must be an array of numbers
						assert.ok(
							Array.isArray(match.references),
							`match.references must be an array, got ${typeof match.references}`
						);
						for (const ref of match.references) {
							assert.strictEqual(
								typeof ref,
								'number',
								`Each reference must be a number, got ${typeof ref}`
							);
						}
					}
				}
			),
			{ numRuns: 100 }
		);
	});


	/**
	 * **Validates: Requirements 3.4**
	 *
	 * findStrings() preserves address, string, encoding fields without alteration.
	 * Create a buffer with known ASCII strings and verify the fields are correct.
	 */
	test('deterministic: findStrings preserves address, string, encoding fields', async () => {
		const engine = new DisassemblerEngine();
		const baseAddress = 0x400000;

		// Build a buffer with known ASCII strings at known offsets
		const bufferSize = 0x2000;
		const fileBuffer = Buffer.alloc(bufferSize, 0);

		// Place known strings (min 4 chars for ASCII detection)
		const testStrings = [
			{ offset: 0x100, text: 'Hello World' },
			{ offset: 0x200, text: 'Test String Here' },
			{ offset: 0x300, text: 'Another Example' },
		];

		for (const ts of testStrings) {
			fileBuffer.write(ts.text, ts.offset, 'ascii');
			fileBuffer[ts.offset + ts.text.length] = 0; // null terminator
		}

		(engine as any).fileBuffer = fileBuffer;
		(engine as any).baseAddress = baseAddress;
		(engine as any).sections = []; // no sections → offsetToAddress uses baseAddress + offset

		await engine.findStrings();

		const stringsMap: Map<number, StringReference> = (engine as any).strings;

		for (const ts of testStrings) {
			const expectedAddr = baseAddress + ts.offset;
			const found = stringsMap.get(expectedAddr);

			assert.ok(
				found !== undefined,
				`Expected to find string "${ts.text}" at address 0x${expectedAddr.toString(16)}`
			);

			if (found) {
				// address must match
				assert.strictEqual(
					found.address,
					expectedAddr,
					`Address mismatch for "${ts.text}": expected 0x${expectedAddr.toString(16)}, got 0x${found.address.toString(16)}`
				);

				// string must contain the original text
				assert.ok(
					found.string.includes(ts.text),
					`String field should contain "${ts.text}", got "${found.string}"`
				);

				// encoding must be 'ascii'
				assert.strictEqual(
					found.encoding,
					'ascii',
					`Encoding for "${ts.text}" should be 'ascii', got "${found.encoding}"`
				);

				// references must be an empty array (no xrefs built yet)
				assert.ok(
					Array.isArray(found.references),
					`references must be an array`
				);
			}
		}
	});
});

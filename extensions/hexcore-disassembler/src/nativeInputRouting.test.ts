/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

suite('native input routing', () => {
	let directory: string;
	let gate: any;
	let Engine: any;
	suiteSetup(() => {
		const Module = require('module');
		const resolve = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) {
			return request === 'vscode' ? '__vscode_native_routing__' : resolve.call(this, request, ...args);
		};
		require.cache['__vscode_native_routing__'] = {
			id: '__vscode_native_routing__', filename: '__vscode_native_routing__', loaded: true,
			exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } },
		} as NodeModule;
		gate = require('./automationPipelineRunner').checkBinaryFormatGate;
		Engine = require('./disassemblerEngine').DisassemblerEngine;
	});
	setup(() => { directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-native-routing-')); });
	teardown(() => { fs.rmSync(directory, { recursive: true, force: true }); });

	function input(bytes: Buffer, name = 'target.bin'): string {
		const file = path.join(directory, name);
		fs.writeFileSync(file, bytes);
		return file;
	}

	for (const [format, magic] of [['dex', 'dex\n039\0'], ['cdex', 'cdex001\0'], ['vdex', 'vdex019\0'], ['zip', 'PK\x03\x04']] as const) {
		test(`rejects ${format} before native pipeline execution, independent of extension`, () => {
			const file = input(Buffer.from(magic, 'latin1'), 'renamed.exe');
			for (const command of ['hexcore.disasm.analyzeAll', 'hexcore.disasm.liftToIR', 'hexcore.helix.decompile']) {
				const result = gate(command, file);
				assert.strictEqual(result.skip, true);
				assert.strictEqual(result.code, 'unsupported-format');
				assert.strictEqual(result.detectedFormat, format);
			}
			assert.strictEqual(gate('hexcore.hashcalc.calculate', file).skip, false);
			assert.strictEqual(gate('hexcore.helix.decompileIR', file).skip, false, 'IR commands validate their actual IR input');
		});
	}

	test('does not reject raw code by filename or embedded magic', () => {
		const file = input(Buffer.concat([Buffer.from([0x90, 0xc3]), Buffer.from('dex\n039\0')]), 'classes.dex');
		assert.strictEqual(gate('hexcore.disasm.analyzeAll', file).skip, false);
	});

	test('preserves PE and ELF routing', () => {
		const elf = Buffer.alloc(64);
		elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]);
		elf.writeUInt16LE(183, 18);
		assert.strictEqual(gate('hexcore.disasm.analyzeAll', input(elf, 'arm64.so')).skip, false);
		const pe = Buffer.alloc(128);
		pe.write('MZ'); pe.writeUInt32LE(64, 60); pe.write('PE\0\0', 64);
		pe.writeUInt16LE(0x8664, 68);
		assert.strictEqual(gate('hexcore.disasm.analyzeAll', input(pe, 'control.exe')).skip, false);
	});

	for (const method of ['loadFile', 'loadAnalysisSnapshot']) {
		test(`${method} refuses DEX before persistence, decoding or replacing the active target`, async () => {
			const file = input(Buffer.from('dex\n039\0'));
			const engine = new Engine();
			engine.currentFile = 'accepted-target';
			engine.fileBuffer = Buffer.from([0xc3]);
			const generation = engine.analysisGeneration;
			try {
				await assert.rejects(engine[method](file, { architecture: 'x64', baseAddress: 0x400000 }), (error: any) => {
					assert.strictEqual(error.code, 'unsupported-format');
					assert.strictEqual(error.detectedFormat, 'dex');
					return true;
				});
				assert.strictEqual(engine.currentFile, 'accepted-target');
				assert.strictEqual(engine.analysisGeneration, generation);
				assert.deepStrictEqual([...engine.fileBuffer], [0xc3]);
				assert.deepStrictEqual(fs.readdirSync(directory), ['target.bin']);
			} finally {
				engine.dispose();
			}
		});
	}
});

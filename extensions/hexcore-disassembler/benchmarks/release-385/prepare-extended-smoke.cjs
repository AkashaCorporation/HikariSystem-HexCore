/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
'use strict';

const fs = require('fs');
const path = require('path');

function writeNew(file, contents) {
	if (fs.existsSync(file)) {
		throw new Error(`Refusing to replace existing fixture: ${file}`);
	}
	fs.mkdirSync(path.dirname(file), { recursive: true });
	fs.writeFileSync(file, contents);
}

function writeJob(root, name, target, steps, continueOnError = false) {
	const job = {
		file: target,
		outDir: path.join(root, 'hexcore-reports', name),
		quiet: true,
		continueOnError,
		steps,
		autoRun: false,
	};
	writeNew(path.join(root, 'jobs', name, `${name}.hexcore_job.json`),
		`${JSON.stringify(job, null, 2)}\n`);
}

function arm64ElfFixture(corruptRelocation = false) {
	const bytes = Buffer.alloc(0x4000);
	bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
	bytes.writeUInt16LE(3, 16);
	bytes.writeUInt16LE(183, 18);
	bytes.writeUInt32LE(1, 20);
	bytes.writeBigUInt64LE(0x1000n, 24);
	bytes.writeBigUInt64LE(64n, 32);
	bytes.writeBigUInt64LE(0x3000n, 40);
	bytes.writeUInt16LE(64, 52);
	bytes.writeUInt16LE(56, 54);
	bytes.writeUInt16LE(1, 56);
	bytes.writeUInt16LE(64, 58);
	bytes.writeUInt16LE(7, 60);
	bytes.writeUInt16LE(6, 62);
	bytes.writeUInt32LE(1, 64);
	bytes.writeUInt32LE(7, 68);
	bytes.writeBigUInt64LE(BigInt(bytes.length), 96);
	bytes.writeBigUInt64LE(BigInt(bytes.length), 104);
	bytes.writeBigUInt64LE(0x1000n, 112);
	const names = '\0.plt\0.got\0.rela.plt\0.dynsym\0.dynstr\0.shstrtab\0';
	bytes.write(names, 0x2b00);
	const section = (index, name, type, flags, offset, size, link = 0, entrySize = 0) => {
		const at = 0x3000 + index * 64;
		bytes.writeUInt32LE(names.indexOf(name), at);
		bytes.writeUInt32LE(type, at + 4);
		bytes.writeBigUInt64LE(BigInt(flags), at + 8);
		bytes.writeBigUInt64LE(BigInt(flags ? offset : 0), at + 16);
		bytes.writeBigUInt64LE(BigInt(offset), at + 24);
		bytes.writeBigUInt64LE(BigInt(size), at + 32);
		bytes.writeUInt32LE(link, at + 40);
		bytes.writeBigUInt64LE(8n, at + 48);
		bytes.writeBigUInt64LE(BigInt(entrySize), at + 56);
	};
	section(1, '.plt', 1, 6, 0x1000, 48);
	section(2, '.got', 1, 3, 0x2268, 16);
	section(3, '.rela.plt', 4, 2, 0x2800, 48, 4, 24);
	section(4, '.dynsym', 11, 2, 0x2900, 72, 5, 24);
	section(5, '.dynstr', 3, 2, 0x2a00, 14);
	section(6, '.shstrtab', 3, 0, 0x2b00, names.length);
	bytes.write('\0first\0second\0', 0x2a00);
	for (let index = 1; index <= 2; index++) {
		bytes.writeUInt32LE(index === 1 ? 1 : 7, 0x2900 + index * 24);
		bytes[0x2900 + index * 24 + 4] = 0x12;
		bytes.writeBigUInt64LE(BigInt(0x2268 + (index - 1) * 8), 0x2800 + (index - 1) * 24);
		const relocationType = corruptRelocation && index === 1 ? 1027n : 1026n;
		bytes.writeBigUInt64LE((BigInt(index) << 32n) | relocationType, 0x2808 + (index - 1) * 24);
	}
	Buffer.from('100000b0113a41f910c2099120021fd61f2003d51f2003d5', 'hex').copy(bytes, 0x1000);
	Buffer.from('100000b0113641f910a2099120021fd61f2003d51f2003d5', 'hex').copy(bytes, 0x1018);
	return bytes;
}

function main() {
	const root = path.resolve(process.argv[2] ?? '');
	if (!root || !fs.statSync(root).isDirectory()) {
		throw new Error('Usage: node prepare-extended-smoke.cjs <existing-smoke-root>');
	}
	const settingsPath = path.join(root, '.vscode', 'settings.json');
	const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
	settings['hexcore.yara.rulesPath'] = path.join(root, 'rules');
	fs.writeFileSync(settingsPath, `${JSON.stringify(settings, null, 2)}\n`);

	const negative = path.join(root, 'fixtures', 'static', 'negative-extended.bin');
	writeNew(negative, Buffer.alloc(512, 0x41));
	const dex = path.join(root, 'fixtures', 'routing', 'sample.dex');
	writeNew(dex, Buffer.from('dex\n039\0HEXCORE_ANDROID_ROUTE_CONTROL', 'ascii'));
	const arm64 = path.join(root, 'fixtures', 'aarch64', 'plt-positive.elf');
	const arm64Bad = path.join(root, 'fixtures', 'aarch64', 'plt-corrupt-reloc.elf');
	writeNew(arm64, arm64ElfFixture(false));
	writeNew(arm64Bad, arm64ElfFixture(true));

	writeJob(root, '16-yara-positive', path.join(root, 'fixtures', 'static', 'smoke.exe'), [
		{ id: 'yara', cmd: 'hexcore.yara.scan', output: { path: '01-yara.json' }, timeoutMs: 60000 },
	]);
	writeJob(root, '17-yara-negative', negative, [
		{ id: 'yara', cmd: 'hexcore.yara.scan', output: { path: '01-yara.json' }, timeoutMs: 60000 },
	]);
	writeJob(root, '18-dex-routing', dex, [
		{ id: 'native-analysis', cmd: 'hexcore.disasm.analyzeAll', output: { path: '01-analysis.json' }, timeoutMs: 60000 },
	], true);
	const arm64Steps = [
		{ id: 'analyze', cmd: 'hexcore.disasm.analyzeAll', args: { forceReload: true, allowLazy: true, maxFunctions: 100, includeInstructions: true }, output: { path: '01-analysis.json' }, timeoutMs: 120000, allowPartial: true },
		{ id: 'asm', cmd: 'hexcore.disasm.disassembleAtHeadless', args: { address: '0x1000', count: 12, context: 0, autoBacktrack: false }, output: { path: '02-plt.json' }, timeoutMs: 60000, allowPartial: true },
		{ id: 'session', cmd: 'hexcore.session.export', output: { path: '03-session.json' }, timeoutMs: 60000 },
	];
	writeJob(root, '19-aarch64-plt-positive', arm64, arm64Steps);
	writeJob(root, '20-aarch64-plt-corrupt', arm64Bad, arm64Steps, true);

	writeJob(root, '21-invalid-duplicate-id', path.join(root, 'fixtures', 'static', 'smoke.exe'), [
		{ id: 'duplicate', cmd: 'hexcore.hashcalc.calculate', output: { path: 'one.json' } },
		{ id: 'duplicate', cmd: 'hexcore.hashcalc.calculate', output: { path: 'two.json' } },
	]);
	writeJob(root, '22-escape-path', 'C:\\Windows\\System32\\notepad.exe', [
		{ id: 'hash', cmd: 'hexcore.hashcalc.calculate', output: { path: 'hash.json' } },
	]);

	process.stdout.write(`${JSON.stringify({ root, fixtures: { negative, dex, arm64, arm64Bad }, jobs: 7 }, null, 2)}\n`);
}

main();

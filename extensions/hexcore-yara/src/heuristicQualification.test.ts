import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { inspectBinaryScanContext, YaraEngine } from './yaraEngine';

function makeElf64(machine: number, opcodeOffset: number): Buffer {
	const data = Buffer.alloc(0x240);
	data.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
	data.writeUInt16LE(2, 16);
	data.writeUInt16LE(machine, 18);
	data.writeUInt32LE(1, 20);
	data.writeBigUInt64LE(0x400080n, 24);
	data.writeBigUInt64LE(0x100n, 40);
	data.writeUInt16LE(64, 52);
	data.writeUInt16LE(64, 58);
	data.writeUInt16LE(3, 60);
	data.writeUInt16LE(2, 62);

	// Section #1: executable .text at file offset 0x80..0x8f.
	const text = 0x140;
	data.writeUInt32LE(1, text);
	data.writeUInt32LE(1, text + 4);
	data.writeBigUInt64LE(0x6n, text + 8);
	data.writeBigUInt64LE(0x400080n, text + 16);
	data.writeBigUInt64LE(0x80n, text + 24);
	data.writeBigUInt64LE(0x10n, text + 32);

	// Section #2: section-name string table.
	const shstr = 0x180;
	data.writeUInt32LE(7, shstr);
	data.writeUInt32LE(3, shstr + 4);
	data.writeBigUInt64LE(0xc0n, shstr + 24);
	data.writeBigUInt64LE(17n, shstr + 32);
	data.write('\0.text\0.shstrtab\0', 0xc0, 'ascii');
	data.set([0x0f, 0x31], opcodeOffset);
	return data;
}

const X86_OPCODE_RULE = `
rule Qualified_RDTSC {
  meta:
    severity = "high"
    architecture = "x86"
    requires_executable = "true"
  strings:
    $op = { 0F 31 }
  condition:
    $op
}`;

suite('YARA architecture and section qualification (3.8.3 RC)', () => {
	let tempDir: string;

	setup(() => { tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-yara-qualify-')); });
	teardown(() => { fs.rmSync(tempDir, { recursive: true, force: true }); });

	test('AArch64 opcode collision is retained as advisory and scores zero', async () => {
		const file = path.join(tempDir, 'arm64.elf');
		fs.writeFileSync(file, makeElf64(183, 0x80));
		const engine = new YaraEngine();
		engine.loadRuleString('test', X86_OPCODE_RULE);

		const result = await engine.scanFileWithResult(file);
		const match = result.matches.find(candidate => candidate.ruleName === 'Qualified_RDTSC');
		assert.ok(match);
		assert.strictEqual(result.binaryContext?.architecture, 'aarch64');
		assert.strictEqual(match.advisoryOnly, true);
		assert.match(match.advisoryReason ?? '', /requires x86.*aarch64/i);
		assert.strictEqual(match.strings[0].section, '.text');
		assert.strictEqual(match.strings[0].executable, true);
		assert.strictEqual(match.strings[0].virtualAddress, '0x400080');
		assert.strictEqual(result.threatScore, 0);
		assert.strictEqual(result.heuristicAdvisory?.suppressedRuleMatches, 1);
	});

	test('x86 opcode collision in data is advisory even on x86-64', async () => {
		const file = path.join(tempDir, 'x64-data.elf');
		fs.writeFileSync(file, makeElf64(62, 0x60));
		const engine = new YaraEngine();
		engine.loadRuleString('test', X86_OPCODE_RULE);

		const result = await engine.scanFileWithResult(file);
		const match = result.matches.find(candidate => candidate.ruleName === 'Qualified_RDTSC');
		assert.ok(match);
		assert.strictEqual(match.advisoryOnly, true);
		assert.match(match.advisoryReason ?? '', /outside executable sections/i);
		assert.strictEqual(result.threatScore, 0);
	});

	test('x86 opcode in executable x86-64 text retains its score', async () => {
		const file = path.join(tempDir, 'x64-text.elf');
		fs.writeFileSync(file, makeElf64(62, 0x80));
		const engine = new YaraEngine();
		engine.loadRuleString('test', X86_OPCODE_RULE);

		const result = await engine.scanFileWithResult(file);
		const match = result.matches.find(candidate => candidate.ruleName === 'Qualified_RDTSC');
		assert.ok(match);
		assert.strictEqual(match.advisoryOnly, undefined);
		assert.strictEqual(result.threatScore, 75);
	});

	test('ELF inspector exposes architecture and executable ranges', () => {
		const context = inspectBinaryScanContext(makeElf64(183, 0x80));
		assert.strictEqual(context.format, 'elf');
		assert.strictEqual(context.architecture, 'aarch64');
		assert.deepStrictEqual(context.sections.find(section => section.name === '.text'), {
			name: '.text', fileOffset: 0x80, size: 0x10, virtualAddress: 0x400080n, executable: true,
		});
	});
});

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { inspectBinaryScanContext, YaraEngine, scorePriorityLabel } from './yaraEngine';

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

	test('unknown architecture cannot qualify an architecture-specific rule', async () => {
		const file = path.join(tempDir, 'unknown.bin'); fs.writeFileSync(file, Buffer.from([0x0f, 0x31]));
		const engine = new YaraEngine();
		engine.loadRuleString('test', X86_OPCODE_RULE.replace('requires_executable = "true"', ''));
		const result = await engine.scanFileWithResult(file);
		assert.strictEqual(result.threatScore, 0);
		assert.strictEqual(result.matches[0].advisoryOnly, true);
	});

	test('advisory metadata cannot inflate the primary score', async () => {
		const file = path.join(tempDir, 'marker.bin'); fs.writeFileSync(file, 'CONSTANT_MARKER');
		const engine = new YaraEngine();
		engine.loadRuleString('test', `rule AdvisoryConstant {
  meta:
    severity = "high"
    advisory_only = "true"
  strings:
    $a = "CONSTANT_MARKER"
  condition:
    $a
}`);
		const result = await engine.scanFileWithResult(file);
		assert.strictEqual(result.threatScore, 0);
		assert.strictEqual(result.matches[0].score, 75);
		assert.strictEqual(result.matches[0].advisoryOnly, true);
	});

	test('requires the complete opcode match inside executable bytes', async () => {
		const file = path.join(tempDir, 'crossing.elf'); fs.writeFileSync(file, makeElf64(62, 0x8f));
		const engine = new YaraEngine(); engine.loadRuleString('test', X86_OPCODE_RULE);
		const result = await engine.scanFileWithResult(file);
		assert.strictEqual(result.threatScore, 0);
	});

	test('executable evidence must satisfy the condition, not just one unrelated string', async () => {
		const data = makeElf64(62, 0x80); data.set([0x0f, 0xa2], 0x60);
		const file = path.join(tempDir, 'mixed.elf'); fs.writeFileSync(file, data);
		const engine = new YaraEngine(); engine.loadRuleString('test', X86_OPCODE_RULE.replace('$op = { 0F 31 }', '$op = { 0F 31 }\n $other = { 0F A2 }').replace('    $op\n', '    $op and $other\n'));
		const result = await engine.scanFileWithResult(file);
		assert.strictEqual(result.threatScore, 0);
	});

	test('classifies DEX and ZIP bytes without pretending to inspect Android components', () => {
		assert.strictEqual(inspectBinaryScanContext(Buffer.from('dex\n039\0')).format, 'dex');
		assert.strictEqual(inspectBinaryScanContext(Buffer.from('PK\x03\x04')).format, 'zip');
	});

	test('bundled generic constants and alphabets remain visible without a threat score', async () => {
		const file = path.join(tempDir, 'classes.dex');
		fs.writeFileSync(file, Buffer.concat([Buffer.from('dex\n039\0'), Buffer.from([0xc5, 0x9d, 0x1c, 0x81]), Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 VIRTUAL QEMU')]));
		const engine = new YaraEngine(); engine.loadRulesFromDirectory(path.join(__dirname, '..', 'rules', 'AntiAnalysis'));
		const result = await engine.scanFileWithResult(file);
		assert.strictEqual(result.threatScore, 0);
		for (const name of ['ApiHashing_FNV1a_Constant', 'Obfuscation_Base64_Alphabet', 'AntiVM_Generic_Virtual_Strings']) {
			const match = result.matches.find(item => item.ruleName === name);
			assert.ok(match, name);
			assert.strictEqual(match.scoreContribution, 0);
			assert.strictEqual(match.advisoryOnly, true);
		}
		assert.strictEqual(result.scoring?.advisoryScore, 75);
	});

	test('format-scoped ZIP rules can score while PE-only rules remain advisory', async () => {
		const file = path.join(tempDir, 'sample.zip'); fs.writeFileSync(file, 'PK\x03\x04FORMAT_MARKER');
		const engine = new YaraEngine();
		for (const format of ['zip', 'pe']) {
			engine.loadRuleString('test', `rule Format_${format} {
  meta:
    severity = "high"
    formats = "${format}"
  strings:
    $a = "FORMAT_MARKER"
  condition:
    $a
}`);
		}
		const result = await engine.scanFileWithResult(file);
		assert.strictEqual(result.threatScore, 75);
		assert.strictEqual(result.matches.find(match => match.ruleName === 'Format_pe')?.advisoryOnly, true);
		assert.strictEqual(result.matches.find(match => match.ruleName === 'Format_zip')?.scoreContribution, 75);
		assert.strictEqual(result.scoring?.scoredMatches, 1);
	});

	test('a zero score is not labeled clean', () => {
		assert.strictEqual(scorePriorityLabel(0), 'NO SCORED MATCHES');
		assert.strictEqual(scorePriorityLabel(10), 'LOW PRIORITY');
	});

	test('the display preview cannot turn a failing executable cardinality condition into a match', async () => {
		const data = makeElf64(62, 0x80);
		data.writeBigUInt64LE(0x40n, 0x140 + 32);
		for (let offset = 0x80; offset < 0xc0; offset += 2) { data.set([0x0f, 0x31], offset); }
		data.set([0x0f, 0xa2], 0x60);
		const file = path.join(tempDir, 'many.elf'); fs.writeFileSync(file, data);
		const engine = new YaraEngine();
		engine.loadRuleString('test', X86_OPCODE_RULE.replace('$op = { 0F 31 }', '$op = { 0F 31 }\n $other = { 0F A2 }').replace('    $op\n', '    $other or #op < 20\n'));
		const result = await engine.scanFileWithResult(file);
		assert.strictEqual(result.matches.length, 1);
		assert.strictEqual(result.matches[0].strings.filter(item => item.identifier === '$op').length, 10);
		assert.strictEqual(result.threatScore, 0);
	});

	test('text patterns retain correct ASCII and wide match extents', async () => {
		for (const wide of [false, true]) {
			const data = makeElf64(62, 0x80);
			const bytes = Buffer.from('TEXT', wide ? 'utf16le' : 'ascii');
			const offset = wide ? 0x8c : 0x84;
			bytes.copy(data, offset);
			const file = path.join(tempDir, `text-${wide}.elf`); fs.writeFileSync(file, data);
			const engine = new YaraEngine();
			engine.loadRuleString('test', X86_OPCODE_RULE.replace('{ 0F 31 }', `"TEXT"${wide ? ' wide' : ''}`));
			const result = await engine.scanFileWithResult(file);
			assert.strictEqual(result.matches[0].strings[0].length, bytes.length);
			assert.strictEqual(result.threatScore, wide ? 0 : 75);
		}
	});
});

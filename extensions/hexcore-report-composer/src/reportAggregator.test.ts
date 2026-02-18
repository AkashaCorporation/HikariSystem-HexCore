/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ReportAggregator, detectReportType } from './reportAggregator';

/**
 * Unit tests for ReportAggregator.
 * Validates: Requirements 3.1, 3.3, 3.5
 */

suite('ReportAggregator — scanReportsDirectory', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-report-test-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	test('returns 3 sources from directory with 3 .md reports', () => {
		const files = [
			{ name: 'pe-report.md', content: '# PE Analysis\n\nDOS Header found.' },
			{ name: 'strings-report.md', content: '# Extracted Strings\n\nFound 42 strings.' },
			{ name: 'entropy-report.md', content: '# Entropy\n\nAverage entropy: 6.2' },
		];
		for (const f of files) {
			fs.writeFileSync(path.join(tmpDir, f.name), f.content, 'utf8');
		}

		const aggregator = new ReportAggregator();
		const sources = aggregator.scanReportsDirectory(tmpDir);

		assert.strictEqual(sources.length, 3);
		const names = sources.map(s => s.fileName).sort();
		assert.deepStrictEqual(names, ['entropy-report.md', 'pe-report.md', 'strings-report.md']);

		// Verify detected types
		const peSource = sources.find(s => s.fileName === 'pe-report.md');
		assert.strictEqual(peSource?.type, 'pe-analysis');

		const strSource = sources.find(s => s.fileName === 'strings-report.md');
		assert.strictEqual(strSource?.type, 'strings');

		const entSource = sources.find(s => s.fileName === 'entropy-report.md');
		assert.strictEqual(entSource?.type, 'entropy');
	});

	test('includes both .md and .json files', () => {
		fs.writeFileSync(path.join(tmpDir, 'report.md'), '# PE Analysis report', 'utf8');
		fs.writeFileSync(path.join(tmpDir, 'data.json'), '{"type":"hash","SHA256":"abc"}', 'utf8');

		const aggregator = new ReportAggregator();
		const sources = aggregator.scanReportsDirectory(tmpDir);

		assert.strictEqual(sources.length, 2);
		const exts = sources.map(s => path.extname(s.fileName)).sort();
		assert.deepStrictEqual(exts, ['.json', '.md']);
	});

	test('ignores non-.md/.json files', () => {
		fs.writeFileSync(path.join(tmpDir, 'report.md'), '# Entropy analysis', 'utf8');
		fs.writeFileSync(path.join(tmpDir, 'notes.txt'), 'some notes', 'utf8');
		fs.writeFileSync(path.join(tmpDir, 'image.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));

		const aggregator = new ReportAggregator();
		const sources = aggregator.scanReportsDirectory(tmpDir);

		assert.strictEqual(sources.length, 1);
		assert.strictEqual(sources[0].fileName, 'report.md');
	});

	test('throws error when directory does not exist', () => {
		const aggregator = new ReportAggregator();
		const fakePath = path.join(tmpDir, 'nonexistent');

		assert.throws(
			() => aggregator.scanReportsDirectory(fakePath),
			(err: Error) => {
				assert.ok(err.message.includes('Reports directory not found'));
				return true;
			}
		);
	});

	test('throws error when path is a file, not a directory', () => {
		const filePath = path.join(tmpDir, 'afile.md');
		fs.writeFileSync(filePath, 'content', 'utf8');

		const aggregator = new ReportAggregator();

		assert.throws(
			() => aggregator.scanReportsDirectory(filePath),
			(err: Error) => {
				assert.ok(err.message.includes('Path is not a directory'));
				return true;
			}
		);
	});

	test('returns empty array when directory has no .md or .json files', () => {
		fs.writeFileSync(path.join(tmpDir, 'readme.txt'), 'hello', 'utf8');
		fs.writeFileSync(path.join(tmpDir, 'data.csv'), 'a,b,c', 'utf8');

		const aggregator = new ReportAggregator();
		const sources = aggregator.scanReportsDirectory(tmpDir);

		assert.strictEqual(sources.length, 0);
	});
});

suite('ReportAggregator — compose', () => {

	test('compose with analyst notes sets analystNotes and includes in Markdown', () => {
		const sources = [
			{ filePath: '/reports/pe.md', fileName: 'pe.md', content: '# PE Analysis\nDOS Header', type: 'pe-analysis' },
		];
		const notes = 'This sample appears to be a dropper. Further sandbox analysis recommended.';

		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources, notes);

		assert.strictEqual(report.analystNotes, notes);

		const markdown = aggregator.toMarkdown(report);
		assert.ok(markdown.includes('## Analyst Notes'));
		assert.ok(markdown.includes(notes));
	});

	test('compose without notes leaves analystNotes undefined', () => {
		const sources = [
			{ filePath: '/reports/strings.md', fileName: 'strings.md', content: '# Extracted Strings', type: 'strings' },
		];

		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources);

		assert.strictEqual(report.analystNotes, undefined);

		const markdown = aggregator.toMarkdown(report);
		assert.ok(!markdown.includes('## Analyst Notes'));
	});

	test('compose with empty string notes leaves analystNotes undefined', () => {
		const sources = [
			{ filePath: '/reports/hash.md', fileName: 'hash.md', content: '# Hash report', type: 'hash' },
		];

		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources, '');

		assert.strictEqual(report.analystNotes, undefined);
	});

	test('compose creates sections with correct titles from file names', () => {
		const sources = [
			{ filePath: '/reports/pe-analysis.md', fileName: 'pe-analysis.md', content: 'PE content', type: 'pe-analysis' },
			{ filePath: '/reports/entropy_report.md', fileName: 'entropy_report.md', content: 'Entropy content', type: 'entropy' },
		];

		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources);

		assert.strictEqual(report.sections.length, 2);
		assert.strictEqual(report.sections[0].title, 'Pe Analysis');
		assert.strictEqual(report.sections[1].title, 'Entropy Report');
	});
});

suite('ReportAggregator — detectReportType', () => {

	test('detects PE Analysis', () => {
		assert.strictEqual(detectReportType('# PE Analysis\nDOS Header found'), 'pe-analysis');
	});

	test('detects Strings', () => {
		assert.strictEqual(detectReportType('Extracted Strings from binary'), 'strings');
	});

	test('detects Entropy', () => {
		assert.strictEqual(detectReportType('Entropy analysis: 7.2'), 'entropy');
	});

	test('detects Base64', () => {
		assert.strictEqual(detectReportType('Base64 decoded content at offset 0x100'), 'base64');
	});

	test('detects Hash/SHA/MD5', () => {
		assert.strictEqual(detectReportType('SHA256: abcdef1234'), 'hash');
		assert.strictEqual(detectReportType('MD5 checksum'), 'hash');
	});

	test('detects ELF Analysis', () => {
		assert.strictEqual(detectReportType('ELF Analysis of /bin/ls'), 'elf-analysis');
	});

	test('detects Disassembly', () => {
		assert.strictEqual(detectReportType('Disassembly output at 0x401000'), 'disassembly');
	});

	test('detects YARA', () => {
		assert.strictEqual(detectReportType('YARA rule matched: suspicious_packer'), 'yara');
	});

	test('returns unknown for unrecognized content', () => {
		assert.strictEqual(detectReportType('Just some random text here'), 'unknown');
	});
});

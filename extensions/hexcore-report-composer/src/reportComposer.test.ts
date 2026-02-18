/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 5: Report Composer agrega todas as fontes com metadados

import * as assert from 'assert';
import * as fc from 'fast-check';
import { ReportAggregator, ReportSource } from './reportAggregator';

/**
 * Generates a non-empty alphanumeric string suitable for file names.
 */
function fileNameArb(): fc.Arbitrary<string> {
	return fc.stringOf(
		fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-_'.split('')),
		{ minLength: 1, maxLength: 20 }
	).map(name => name + '.md');
}

/**
 * Generates a non-empty content string with some report-like text.
 */
function contentArb(): fc.Arbitrary<string> {
	return fc.stringOf(
		fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n'.split('')),
		{ minLength: 1, maxLength: 200 }
	);
}

/**
 * Generates a report type string from the known set.
 */
function reportTypeArb(): fc.Arbitrary<string> {
	return fc.constantFrom(
		'pe-analysis', 'strings', 'entropy', 'base64',
		'hash', 'elf-analysis', 'disassembly', 'yara', 'unknown'
	);
}

/**
 * Generates a single ReportSource with random but valid data.
 */
function reportSourceArb(): fc.Arbitrary<ReportSource> {
	return fc.record({
		filePath: fileNameArb().map(name => '/reports/' + name),
		fileName: fileNameArb(),
		content: contentArb(),
		type: reportTypeArb(),
	});
}

/**
 * Generates an array of 1-10 ReportSource objects with unique file names.
 */
function reportSourcesArb(): fc.Arbitrary<ReportSource[]> {
	return fc.array(reportSourceArb(), { minLength: 1, maxLength: 10 })
		.map(sources => {
			// Ensure unique file names by appending index
			return sources.map((s, i) => ({
				...s,
				fileName: `report-${i}-${s.fileName}`,
				filePath: `/reports/report-${i}-${s.fileName}`,
			}));
		});
}

suite('Property: Report Composer agrega todas as fontes com metadados', () => {

	/**
	 * **Validates: Requirements 3.1, 3.2, 3.6**
	 *
	 * For any set of N ReportSource objects, the composed report MUST
	 * contain exactly N sources, at least N sections, and include
	 * the metadata fields generatedAt, hexcoreVersion, and sources
	 * with length N.
	 */
	test('composed report contains all sources and required metadata', () => {
		fc.assert(
			fc.property(reportSourcesArb(), (sources) => {
				const aggregator = new ReportAggregator();
				const report = aggregator.compose(sources);
				const n = sources.length;

				// report.sources.length === N
				assert.strictEqual(report.sources.length, n,
					`Expected ${n} sources, got ${report.sources.length}`);

				// report.sections.length >= N
				assert.ok(report.sections.length >= n,
					`Expected at least ${n} sections, got ${report.sections.length}`);

				// generatedAt is a non-empty string
				assert.strictEqual(typeof report.generatedAt, 'string');
				assert.ok(report.generatedAt.length > 0,
					'generatedAt must be a non-empty string');

				// hexcoreVersion is a non-empty string
				assert.strictEqual(typeof report.hexcoreVersion, 'string');
				assert.ok(report.hexcoreVersion.length > 0,
					'hexcoreVersion must be a non-empty string');

				// Each source fileName appears in report.sources
				for (const source of sources) {
					const found = report.sources.some(s => s.fileName === source.fileName);
					assert.ok(found,
						`Source fileName '${source.fileName}' not found in report.sources`);
				}
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 3.1, 3.2, 3.6**
	 *
	 * For any set of N ReportSource objects, each section in the
	 * composed report MUST reference a valid source file from the
	 * input sources.
	 */
	test('each section references a valid source file', () => {
		fc.assert(
			fc.property(reportSourcesArb(), (sources) => {
				const aggregator = new ReportAggregator();
				const report = aggregator.compose(sources);
				const sourceFileNames = new Set(sources.map(s => s.fileName));

				for (const section of report.sections) {
					assert.ok(sourceFileNames.has(section.sourceFile),
						`Section '${section.title}' references unknown source '${section.sourceFile}'`);
				}
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 3.6**
	 *
	 * The generatedAt metadata MUST be a valid ISO 8601 timestamp.
	 */
	test('generatedAt is a valid ISO 8601 timestamp', () => {
		fc.assert(
			fc.property(reportSourcesArb(), (sources) => {
				const aggregator = new ReportAggregator();
				const report = aggregator.compose(sources);

				const parsed = Date.parse(report.generatedAt);
				assert.ok(!isNaN(parsed),
					`generatedAt '${report.generatedAt}' is not a valid ISO date`);
			}),
			{ numRuns: 100 }
		);
	});
});


// Feature: v3.5.2-pipeline-maturity, Property 6: Report Composer inclui notas do analista

/**
 * Generates a non-empty printable ASCII string suitable for analyst notes.
 * Avoids markdown special characters that could break parsing.
 */
function analystNotesArb(): fc.Arbitrary<string> {
	// Printable ASCII excluding markdown-special chars: # * _ ` [ ] | > ~ -
	const safeChars = 'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,;:!?()+=/@\'"{}%&^$'.split('');
	return fc.stringOf(
		fc.constantFrom(...safeChars),
		{ minLength: 1, maxLength: 200 }
	);
}

suite('Property: Report Composer inclui notas do analista', () => {

	/**
	 * **Validates: Requirements 3.3**
	 *
	 * For any non-empty notes string provided to the Report Composer,
	 * the generated Markdown MUST contain the full notes content in
	 * a dedicated "## Analyst Notes" section, and the report object
	 * MUST have analystNotes === notes.
	 */
	test('analyst notes appear in composed report and Markdown output', () => {
		fc.assert(
			fc.property(
				fc.array(reportSourceArb(), { minLength: 1, maxLength: 5 })
					.map(sources => sources.map((s, i) => ({
						...s,
						fileName: `report-${i}-${s.fileName}`,
						filePath: `/reports/report-${i}-${s.fileName}`,
					}))),
				analystNotesArb(),
				(sources, notes) => {
					const aggregator = new ReportAggregator();
					const report = aggregator.compose(sources, notes);
					const markdown = aggregator.toMarkdown(report);

					// report.analystNotes must equal the provided notes
					assert.strictEqual(report.analystNotes, notes,
						`Expected analystNotes to be '${notes}', got '${report.analystNotes}'`);

					// Markdown must contain the "## Analyst Notes" heading
					assert.ok(markdown.includes('## Analyst Notes'),
						'Markdown must contain "## Analyst Notes" heading');

					// Markdown must contain the full notes string
					assert.ok(markdown.includes(notes),
						`Markdown must contain the full notes string: '${notes}'`);
				}
			),
			{ numRuns: 100 }
		);
	});
});


// Feature: v3.5.2-pipeline-maturity, Property 7: Report Composer round-trip Markdown

/**
 * Generates content that is safe for Markdown round-trip.
 * Avoids # (headings), --- (separators), > (blockquotes), * (emphasis),
 * and other markdown constructs that would confuse the parser.
 */
function safeContentArb(): fc.Arbitrary<string> {
	const safeChars = 'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,;:!?()+=/@\'"{}%&^'.split('');
	return fc.stringOf(
		fc.constantFrom(...safeChars),
		{ minLength: 1, maxLength: 150 }
	);
}

/**
 * Generates a safe file name (no markdown-special chars).
 */
function safeFileNameArb(): fc.Arbitrary<string> {
	return fc.stringOf(
		fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'.split('')),
		{ minLength: 1, maxLength: 15 }
	).map(name => name + '.md');
}

/**
 * Generates a ReportSource with safe content for round-trip testing.
 */
function safeReportSourceArb(): fc.Arbitrary<ReportSource> {
	return fc.record({
		filePath: safeFileNameArb().map(name => '/reports/' + name),
		fileName: safeFileNameArb(),
		content: safeContentArb(),
		type: reportTypeArb(),
	});
}

/**
 * Generates 1-5 ReportSource objects with unique file names for round-trip.
 */
function safeReportSourcesArb(): fc.Arbitrary<ReportSource[]> {
	return fc.array(safeReportSourceArb(), { minLength: 1, maxLength: 5 })
		.map(sources => {
			return sources.map((s, i) => ({
				...s,
				fileName: `rt-${i}-${s.fileName}`,
				filePath: `/reports/rt-${i}-${s.fileName}`,
			}));
		});
}

/**
 * Generates analyst notes that survive Markdown round-trip (non-whitespace-only).
 * The fromMarkdown parser trims whitespace, so notes must have visible content.
 */
function roundTripNotesArb(): fc.Arbitrary<string> {
	const safeChars = 'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,;:!?()+=/@\'"{}%&^'.split('');
	return fc.stringOf(
		fc.constantFrom(...safeChars),
		{ minLength: 1, maxLength: 150 }
	).filter(s => s.trim().length > 0);
}

suite('Property: Report Composer round-trip Markdown', () => {

	/**
	 * **Validates: Requirements 3.8**
	 *
	 * For any valid ComposedReport, converting to Markdown via toMarkdown()
	 * and reconstructing via fromMarkdown() MUST produce an object with
	 * the same title, generatedAt, hexcoreVersion, sources (fileName, type),
	 * sections (title, sourceFile), and analystNotes.
	 */
	test('fromMarkdown(toMarkdown(report)) preserves structure', () => {
		fc.assert(
			fc.property(
				safeReportSourcesArb(),
				fc.option(roundTripNotesArb(), { nil: undefined }),
				(sources, notes) => {
					const aggregator = new ReportAggregator();
					const original = aggregator.compose(sources, notes);
					const markdown = aggregator.toMarkdown(original);
					const reconstructed = aggregator.fromMarkdown(markdown);

					// Title
					assert.strictEqual(reconstructed.title, original.title,
						`Title mismatch: expected '${original.title}', got '${reconstructed.title}'`);

					// generatedAt
					assert.strictEqual(reconstructed.generatedAt, original.generatedAt,
						`generatedAt mismatch: expected '${original.generatedAt}', got '${reconstructed.generatedAt}'`);

					// hexcoreVersion
					assert.strictEqual(reconstructed.hexcoreVersion, original.hexcoreVersion,
						`hexcoreVersion mismatch: expected '${original.hexcoreVersion}', got '${reconstructed.hexcoreVersion}'`);

					// Sources count
					assert.strictEqual(reconstructed.sources.length, original.sources.length,
						`Sources count mismatch: expected ${original.sources.length}, got ${reconstructed.sources.length}`);

					// Each source fileName and type match
					for (let i = 0; i < original.sources.length; i++) {
						assert.strictEqual(reconstructed.sources[i].fileName, original.sources[i].fileName,
							`Source[${i}] fileName mismatch`);
						assert.strictEqual(reconstructed.sources[i].type, original.sources[i].type,
							`Source[${i}] type mismatch`);
					}

					// Sections count
					assert.strictEqual(reconstructed.sections.length, original.sections.length,
						`Sections count mismatch: expected ${original.sections.length}, got ${reconstructed.sections.length}`);

					// Each section title and sourceFile match
					for (let i = 0; i < original.sections.length; i++) {
						assert.strictEqual(reconstructed.sections[i].title, original.sections[i].title,
							`Section[${i}] title mismatch`);
						assert.strictEqual(reconstructed.sections[i].sourceFile, original.sections[i].sourceFile,
							`Section[${i}] sourceFile mismatch`);
					}

					// Analyst notes (fromMarkdown trims whitespace, so compare trimmed)
					const originalNotes = original.analystNotes?.trim();
					const reconstructedNotes = reconstructed.analystNotes?.trim();
					assert.strictEqual(reconstructedNotes, originalNotes,
						`analystNotes mismatch: expected '${originalNotes}', got '${reconstructedNotes}'`);
				}
			),
			{ numRuns: 100 }
		);
	});
});

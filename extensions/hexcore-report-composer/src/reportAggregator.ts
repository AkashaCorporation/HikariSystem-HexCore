/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';

/**
 * A single report source file discovered in the reports directory.
 */
export interface ReportSource {
	filePath: string;
	fileName: string;
	content: string;
	type: string; // 'pe-analysis', 'strings', 'entropy', etc.
}

/**
 * A section within the composed report.
 */
export interface ReportSection {
	title: string;
	content: string;
	sourceFile: string;
}

/**
 * Cross-module evidence for a single IOC / offset — when multiple analyzers
 * (strings, YARA, IOC extractor) independently flag the same thing, we
 * collapse them into a single high-confidence finding. Built by
 * `fuseEvidence()` from the JSON reports before Markdown serialization.
 *
 * v3.8.0: the rationale is that two analysts looking at the same binary
 * want ONE line saying "http://evil.tld was flagged by {strings, ioc, yara}
 * at offsets {0x1234, 0x1234, 0x1300}" rather than three disjoint lists.
 */
export interface CrossModuleFinding {
	/** Normalized value (URL, IP, offset, hash). */
	value: string;
	/** Which analyzer reports referenced this finding. */
	sources: string[];
	/** File offsets where the finding appears (may be empty if unknown). */
	offsets: number[];
	/** Classification (url / ip / domain / mutex / offset / yara-rule / hash). */
	kind: string;
}

/**
 * The fully composed report aggregating multiple sources.
 */
export interface ComposedReport {
	title: string;
	generatedAt: string;
	hexcoreVersion: string;
	sources: ReportSource[];
	sections: ReportSection[];
	analystNotes?: string;
	/** v3.8.0 cross-module evidence fusion — findings corroborated by ≥ 2 sources. */
	crossModuleFindings?: CrossModuleFinding[];
}

/**
 * Detects the report type based on content keywords.
 */
export function detectReportType(content: string): string {
	if (/PE Analysis|DOS Header/i.test(content)) {
		return 'pe-analysis';
	}
	if (/Strings|Extracted Strings/i.test(content)) {
		return 'strings';
	}
	if (/Entropy/i.test(content)) {
		return 'entropy';
	}
	if (/Base64/i.test(content)) {
		return 'base64';
	}
	if (/Hash|SHA|MD5/i.test(content)) {
		return 'hash';
	}
	if (/ELF Analysis/i.test(content)) {
		return 'elf-analysis';
	}
	if (/Disassembly/i.test(content)) {
		return 'disassembly';
	}
	if (/YARA/i.test(content)) {
		return 'yara';
	}
	return 'unknown';
}


/**
 * Derives a section title from a report source file name.
 */
function deriveSectionTitle(source: ReportSource): string {
	const name = path.basename(source.fileName, path.extname(source.fileName));
	// Convert kebab-case or snake_case to Title Case
	return name
		.replace(/[-_]/g, ' ')
		.replace(/\b\w/g, c => c.toUpperCase());
}

/**
 * Slugifies a title for use as a Markdown anchor.
 */
function slugify(title: string): string {
	return title
		.toLowerCase()
		.replace(/[^\w\s-]/g, '')
		.replace(/\s+/g, '-')
		.trim();
}

// ---------------------------------------------------------------------------
// v3.8.0: Cross-module evidence fusion
// ---------------------------------------------------------------------------

/**
 * Extract candidate finding "values" from a report source. Parses JSON sources
 * structurally; falls back to a best-effort regex pass for Markdown sources.
 *
 * The goal is NOT to re-implement every analyzer's output schema — it's to
 * spot the same URL / IP / domain / mutex / offset / YARA rule name showing
 * up across ≥ 2 reports and collapse them into a single fused finding.
 */
interface RawEvidence {
	value: string;
	kind: string;
	offset?: number;
}

function extractEvidenceFromSource(source: ReportSource): RawEvidence[] {
	const ev: RawEvidence[] = [];
	const lowerName = source.fileName.toLowerCase();

	// JSON structured path — try to parse and pick common shapes.
	if (lowerName.endsWith('.json')) {
		try {
			const data = JSON.parse(source.content);
			// IOC extractor shape: { indicators: { url: [{value, offset, ...}], ... } }
			if (data && typeof data === 'object' && data.indicators && typeof data.indicators === 'object') {
				for (const [cat, arr] of Object.entries<any>(data.indicators)) {
					if (!Array.isArray(arr)) { continue; }
					for (const item of arr) {
						if (item && typeof item.value === 'string') {
							ev.push({ value: item.value, kind: String(cat), offset: typeof item.offset === 'number' ? item.offset : undefined });
						}
					}
				}
			}
			// YARA shape: { matches: [{ ruleName, strings: [{offset}] }] }
			if (data && Array.isArray(data.matches)) {
				for (const m of data.matches) {
					if (m && typeof m.ruleName === 'string') {
						ev.push({ value: m.ruleName, kind: 'yara-rule' });
					}
					if (m && Array.isArray(m.strings)) {
						for (const s of m.strings) {
							if (s && typeof s.offset === 'number') {
								ev.push({ value: `0x${s.offset.toString(16)}`, kind: 'offset', offset: s.offset });
							}
						}
					}
				}
			}
			// Strings shape: { results: [{ value, offset }] } (conservative)
			if (data && Array.isArray(data.results)) {
				for (const r of data.results) {
					if (r && typeof r.value === 'string' && typeof r.offset === 'number') {
						ev.push({ value: r.value, kind: 'string', offset: r.offset });
					}
				}
			}
		} catch { /* not JSON; fall through to regex */ }
	}

	// Best-effort regex scan on the raw content — catches Markdown-rendered
	// reports and anything the JSON branch missed.
	const urlRx = /https?:\/\/[A-Za-z0-9\-._~:/?#%=&]+/g;
	const ipRx = /\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}\b/g;
	const offRx = /\b0x[0-9a-fA-F]{4,16}\b/g;
	for (const m of source.content.matchAll(urlRx)) { ev.push({ value: m[0], kind: 'url' }); }
	for (const m of source.content.matchAll(ipRx))  { ev.push({ value: m[0], kind: 'ipv4' }); }
	for (const m of source.content.matchAll(offRx)) {
		const n = parseInt(m[0], 16);
		if (Number.isFinite(n)) { ev.push({ value: m[0].toLowerCase(), kind: 'offset', offset: n }); }
	}

	return ev;
}

/**
 * Fuse evidence across multiple reports. A finding is emitted only when at
 * least two distinct source files reference the same value — this prevents
 * trivially-quadratic expansion from a single analyzer's dump.
 */
export function fuseEvidence(sources: ReportSource[]): CrossModuleFinding[] {
	// Map<"kind::value", { sources: Set, offsets: Set }>
	const bucket = new Map<string, { value: string; kind: string; sources: Set<string>; offsets: Set<number> }>();

	for (const src of sources) {
		const evidence = extractEvidenceFromSource(src);
		// Track which source names we already charged for a (kind,value) pair
		// in THIS source — prevents double-count from a source that mentions
		// the same URL 20 times.
		const seenThisSource = new Set<string>();
		for (const e of evidence) {
			const key = `${e.kind}::${e.value}`;
			let bucketEntry = bucket.get(key);
			if (!bucketEntry) {
				bucketEntry = { value: e.value, kind: e.kind, sources: new Set(), offsets: new Set() };
				bucket.set(key, bucketEntry);
			}
			if (!seenThisSource.has(key)) {
				bucketEntry.sources.add(src.fileName);
				seenThisSource.add(key);
			}
			if (typeof e.offset === 'number') { bucketEntry.offsets.add(e.offset); }
		}
	}

	const findings: CrossModuleFinding[] = [];
	for (const entry of bucket.values()) {
		// Only emit findings corroborated by 2+ distinct reports.
		if (entry.sources.size < 2) { continue; }
		findings.push({
			value: entry.value,
			kind: entry.kind,
			sources: [...entry.sources].sort(),
			offsets: [...entry.offsets].sort((a, b) => a - b),
		});
	}
	// Sort: more sources = higher confidence, then alphabetical
	findings.sort((a, b) => b.sources.length - a.sources.length || a.value.localeCompare(b.value));
	return findings;
}

/**
 * Aggregates report sources into a composed report.
 */
export class ReportAggregator {
	/**
	 * Scans a directory for `.md` and `.json` report files.
	 * @param dirPath Absolute path to the reports directory.
	 * @returns Array of discovered report sources.
	 */
	scanReportsDirectory(dirPath: string): ReportSource[] {
		if (!fs.existsSync(dirPath)) {
			throw new Error(`Reports directory not found: ${dirPath}`);
		}

		const stat = fs.statSync(dirPath);
		if (!stat.isDirectory()) {
			throw new Error(`Path is not a directory: ${dirPath}`);
		}

		const entries = fs.readdirSync(dirPath);
		const sources: ReportSource[] = [];

		for (const entry of entries) {
			const ext = path.extname(entry).toLowerCase();
			if (ext !== '.md' && ext !== '.json') {
				continue;
			}

			const filePath = path.join(dirPath, entry);
			const fileStat = fs.statSync(filePath);
			if (!fileStat.isFile()) {
				continue;
			}

			const content = fs.readFileSync(filePath, 'utf8');
			sources.push({
				filePath,
				fileName: entry,
				content,
				type: detectReportType(content)
			});
		}

		return sources;
	}

	/**
	 * Composes a unified report from multiple sources.
	 * @param sources Array of report sources to aggregate.
	 * @param notes Optional analyst notes to include.
	 * @returns The composed report object.
	 */
	compose(sources: ReportSource[], notes?: string): ComposedReport {
		const sections: ReportSection[] = sources.map(source => ({
			title: deriveSectionTitle(source),
			content: source.content,
			sourceFile: source.fileName
		}));

		const report: ComposedReport = {
			title: 'HexCore Composed Report',
			generatedAt: new Date().toISOString(),
			hexcoreVersion: '3.5.3',
			sources,
			sections
		};

		if (notes !== undefined && notes.length > 0) {
			report.analystNotes = notes;
		}

		// v3.8.0: run cross-module evidence fusion. Only attach when we found
		// at least one corroborated finding — keeps the report clean for
		// single-analyzer runs.
		const fused = fuseEvidence(sources);
		if (fused.length > 0) {
			report.crossModuleFindings = fused;
		}

		return report;
	}

	/**
	 * Serializes a composed report to Markdown format.
	 * @param report The composed report to serialize.
	 * @returns Markdown string.
	 */
	toMarkdown(report: ComposedReport): string {
		const lines: string[] = [];

		// Title
		lines.push(`# ${report.title}`);
		lines.push('');

		// Metadata
		lines.push(`> Generated at: ${report.generatedAt}`);
		lines.push(`> HexCore Version: ${report.hexcoreVersion}`);
		lines.push(`> Sources: ${report.sources.length} reports`);
		lines.push('');

		// Table of Contents
		lines.push('## Table of Contents');
		lines.push('');
		for (let i = 0; i < report.sections.length; i++) {
			const section = report.sections[i];
			lines.push(`${i + 1}. [${section.title}](#${slugify(section.title)})`);
		}
		lines.push('');

		// Analyst Notes
		if (report.analystNotes !== undefined && report.analystNotes.length > 0) {
			lines.push('## Analyst Notes');
			lines.push('');
			lines.push(report.analystNotes);
			lines.push('');
		}

		// v3.8.0: Cross-module corroborated findings. Rendered BEFORE individual
		// sections so analysts see the high-signal summary first.
		if (report.crossModuleFindings && report.crossModuleFindings.length > 0) {
			lines.push('## Cross-Module Findings');
			lines.push('');
			lines.push('Findings corroborated by two or more analyzers (higher confidence).');
			lines.push('');
			lines.push('| Kind | Value | Sources | Offsets |');
			lines.push('|------|-------|---------|---------|');
			for (const f of report.crossModuleFindings) {
				const offsetsStr = f.offsets.length === 0
					? '—'
					: f.offsets.slice(0, 5).map(o => `0x${o.toString(16)}`).join(', ')
						+ (f.offsets.length > 5 ? ` (+${f.offsets.length - 5} more)` : '');
				// Markdown-escape the value (primarily for `|` which breaks tables)
				const safeValue = f.value.replace(/\|/g, '\\|');
				lines.push(`| ${f.kind} | \`${safeValue}\` | ${f.sources.length} (${f.sources.join(', ')}) | ${offsetsStr} |`);
			}
			lines.push('');
		}

		// Sections
		for (const section of report.sections) {
			lines.push('---');
			lines.push('');
			lines.push(`## ${section.title}`);
			lines.push('');
			lines.push(`*Source: ${section.sourceFile}*`);
			lines.push('');
			lines.push(section.content);
			lines.push('');
		}

		// Sources table
		lines.push('---');
		lines.push('');
		lines.push('## Sources');
		lines.push('');
		lines.push('| # | File | Type |');
		lines.push('|---|------|------|');
		for (let i = 0; i < report.sources.length; i++) {
			const source = report.sources[i];
			lines.push(`| ${i + 1} | ${source.fileName} | ${source.type} |`);
		}
		lines.push('');

		return lines.join('\n');
	}

	/**
	 * Reconstructs a ComposedReport from serialized Markdown.
	 * @param markdown The Markdown string to parse.
	 * @returns The reconstructed ComposedReport.
	 */
	fromMarkdown(markdown: string): ComposedReport {
		const lines = markdown.split('\n');

		// Extract title from first # heading
		let title = 'HexCore Composed Report';
		for (const line of lines) {
			const titleMatch = line.match(/^# (.+)$/);
			if (titleMatch) {
				title = titleMatch[1];
				break;
			}
		}

		// Extract metadata
		let generatedAt = '';
		let hexcoreVersion = '';
		for (const line of lines) {
			const genMatch = line.match(/^> Generated at:\s*(.+)$/);
			if (genMatch) {
				generatedAt = genMatch[1].trim();
			}
			const verMatch = line.match(/^> HexCore Version:\s*(.+)$/);
			if (verMatch) {
				hexcoreVersion = verMatch[1].trim();
			}
		}

		// Extract analyst notes
		let analystNotes: string | undefined;
		const notesIdx = lines.findIndex(l => l.trim() === '## Analyst Notes');
		if (notesIdx !== -1) {
			const notesLines: string[] = [];
			for (let i = notesIdx + 1; i < lines.length; i++) {
				const line = lines[i];
				// Stop at next section separator or heading
				if (line.trim() === '---' || (line.startsWith('## ') && line.trim() !== '## Analyst Notes')) {
					break;
				}
				notesLines.push(line);
			}
			// Trim leading/trailing empty lines
			const trimmed = notesLines.join('\n').trim();
			if (trimmed.length > 0) {
				analystNotes = trimmed;
			}
		}

		// Extract sections (## headings that are not TOC, Analyst Notes, Sources,
		// or the v3.8.0 Cross-Module Findings summary block).
		const skipHeadings = new Set(['Table of Contents', 'Analyst Notes', 'Sources', 'Cross-Module Findings']);
		const sections: ReportSection[] = [];
		for (let i = 0; i < lines.length; i++) {
			const headingMatch = lines[i].match(/^## (.+)$/);
			if (!headingMatch || skipHeadings.has(headingMatch[1])) {
				continue;
			}

			const sectionTitle = headingMatch[1];

			// Extract source file from *Source: ...* line
			let sourceFile = '';
			const contentLines: string[] = [];
			let foundSource = false;
			for (let j = i + 1; j < lines.length; j++) {
				const line = lines[j];
				// Stop at next --- separator or next ## heading
				if (line.trim() === '---' || (line.startsWith('## ') && j > i + 1)) {
					break;
				}
				const sourceMatch = line.match(/^\*Source:\s*(.+)\*$/);
				if (sourceMatch && !foundSource) {
					sourceFile = sourceMatch[1].trim();
					foundSource = true;
					continue;
				}
				contentLines.push(line);
			}

			// Trim leading/trailing empty lines from content
			const content = contentLines.join('\n').trim();
			if (content.length > 0 || sourceFile.length > 0) {
				sections.push({
					title: sectionTitle,
					content,
					sourceFile
				});
			}
		}

		// Extract sources from the Sources table
		const sources: ReportSource[] = [];
		const sourcesIdx = lines.findIndex(l => l.trim() === '## Sources');
		if (sourcesIdx !== -1) {
			for (let i = sourcesIdx + 1; i < lines.length; i++) {
				const line = lines[i].trim();
				// Match table rows: | N | filename | type |
				const rowMatch = line.match(/^\|\s*\d+\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|$/);
				if (rowMatch) {
					const fileName = rowMatch[1].trim();
					const type = rowMatch[2].trim();
					// Find matching section content
					const matchingSection = sections.find(s => s.sourceFile === fileName);
					sources.push({
						filePath: fileName,
						fileName,
						content: matchingSection ? matchingSection.content : '',
						type
					});
				}
			}
		}

		const report: ComposedReport = {
			title,
			generatedAt,
			hexcoreVersion,
			sources,
			sections
		};

		if (analystNotes !== undefined) {
			report.analystNotes = analystNotes;
		}

		return report;
	}
}

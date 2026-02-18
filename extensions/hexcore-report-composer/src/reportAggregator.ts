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
 * The fully composed report aggregating multiple sources.
 */
export interface ComposedReport {
	title: string;
	generatedAt: string;
	hexcoreVersion: string;
	sources: ReportSource[];
	sections: ReportSection[];
	analystNotes?: string;
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

		// Extract sections (## headings that are not TOC, Analyst Notes, or Sources)
		const skipHeadings = new Set(['Table of Contents', 'Analyst Notes', 'Sources']);
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

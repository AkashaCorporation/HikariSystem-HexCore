/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { indicatorRejection } from './indicatorEvidence';

/**
 * A single report source file discovered in the reports directory.
 */
export interface ReportSource {
	filePath: string;
	fileName: string;
	content: string;
	type: string; // 'pe-analysis', 'strings', 'entropy', etc.
	lineage?: ReportSourceLineage;
	normalizedIdentity?: string;
}

export interface ReportSourceLineage {
	targetId: string;
	producers: string[];
	command: string;
	configurationSha256?: string;
	inputIds: string[];
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
	/** Repeated observations never establish independent behavioral corroboration. */
	evidenceLevel?: 'signal';
	independentCorroboration?: false;
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
	replicatedSources?: ReplicatedSourceGroup[];
	rejectedIndicators?: Array<{ source: string; kind: string; value: string; reason: string }>;
}

export interface ReplicatedSourceGroup {
	representative: string;
	replicas: string[];
	command: string;
	normalizedIdentity: string;
}

interface SourceSummary {
	fileName: string;
	type: string;
	bytes: number;
	highlights: string[];
}

function asRecord(value: unknown): Record<string, any> | undefined {
	return value !== null && typeof value === 'object' && !Array.isArray(value)
		? value as Record<string, any>
		: undefined;
}

function canonicalizeJson(value: unknown): unknown {
	if (Array.isArray(value)) { return value.map(canonicalizeJson); }
	const record = asRecord(value);
	if (!record) { return value; }
	return Object.fromEntries(Object.keys(record).sort().map(key => [key, canonicalizeJson(record[key])]));
}

function normalizedContentIdentity(fileName: string, content: string): string {
	let normalized: unknown = content.replace(/\r\n/g, '\n');
	if (fileName.toLowerCase().endsWith('.json')) {
		try {
			const parsed = JSON.parse(content);
			const declaredNormalization = asRecord(asRecord(parsed)?.normalization);
			if (asRecord(parsed)) {
				delete parsed.generatedAt;
				delete parsed.normalization;
				if (asRecord(parsed.analysisContext)) {
					delete parsed.analysisContext.engineGeneration;
					delete parsed.analysisContext.closureRestoration;
				}
			}
			normalized = canonicalizeJson(parsed);
			const computed = crypto.createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
			if (declaredNormalization?.algorithm === 'hexcore-canonical-json-v1' &&
				typeof declaredNormalization.sha256 === 'string' && declaredNormalization.sha256 === computed) {
				return computed;
			}
		} catch { /* retain normalized text */ }
	}
	return crypto.createHash('sha256')
		.update(typeof normalized === 'string' ? normalized : JSON.stringify(normalized))
		.digest('hex');
}

function targetScope(source: ReportSource): string {
	return source.lineage?.targetId ?? 'target:unknown';
}

function independenceKey(source: ReportSource): string {
	if (!source.lineage) { return `legacy-file:${source.fileName}`; }
	return JSON.stringify({
		producers: [...source.lineage.producers].sort(),
		command: source.lineage.command,
		inputs: [...source.lineage.inputIds].sort(),
	});
}

function invocationKey(source: ReportSource): string | undefined {
	if (!source.lineage) { return undefined; }
	return JSON.stringify({
		target: source.lineage.targetId,
		producers: [...source.lineage.producers].sort(),
		command: source.lineage.command,
		configuration: source.lineage.configurationSha256 ?? 'unknown',
		inputs: [...source.lineage.inputIds].sort(),
	});
}

function loadProvenanceIndex(dirPath: string): Map<string, ReportSourceLineage> {
	const index = new Map<string, ReportSourceLineage>();
	const manifestPath = path.join(dirPath, '.hexcore-meta', 'provenance.json');
	try {
		const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
		if (!Array.isArray(manifest?.artifacts)) { return index; }
		for (const rawEntry of manifest.artifacts) {
			const entry = asRecord(rawEntry);
			const artifact = asRecord(entry?.artifact);
			const contract = asRecord(entry?.analysisContract);
			const target = asRecord(contract?.target);
			const step = asRecord(entry?.step);
			if (!artifact || typeof artifact.path !== 'string' || !target || typeof target.id !== 'string' || !step) { continue; }
			const owners = Array.isArray(entry?.ownerExtensions) ? entry.ownerExtensions : [];
			const producers = owners.map((owner: unknown) => {
				const record = asRecord(owner);
				return `${String(record?.id ?? 'unknown')}@${String(record?.version ?? 'unknown')}`;
			});
			const inputs = Array.isArray(entry?.inputs) ? entry.inputs : [];
			index.set(path.resolve(artifact.path).toLowerCase(), {
				targetId: target.id,
				producers,
				command: String(step.resolvedCmd ?? step.cmd ?? 'unknown'),
				...(typeof step.configurationSha256 === 'string' ? { configurationSha256: step.configurationSha256 } : {}),
				inputIds: inputs.map((input: unknown) => String(asRecord(input)?.id ?? '')).filter(Boolean),
			});
		}
	} catch { /* legacy report directory without consolidated provenance */ }
	return index;
}

function findSourceReplications(sources: ReportSource[]): ReplicatedSourceGroup[] {
	const groups = new Map<string, ReportSource[]>();
	for (const source of sources) {
		const invocation = invocationKey(source);
		if (!invocation || !source.normalizedIdentity) { continue; }
		const key = `${invocation}::${source.normalizedIdentity}`;
		const group = groups.get(key) ?? [];
		group.push(source);
		groups.set(key, group);
	}
	return [...groups.values()].filter(group => group.length > 1).map(group => {
		const sorted = [...group].sort((left, right) => {
			const replicaPenalty = (source: ReportSource) => /(?:repeat|rerun|replica|copy)/i.test(source.fileName) ? 1 : 0;
			return replicaPenalty(left) - replicaPenalty(right) || left.fileName.localeCompare(right.fileName);
		});
		return {
			representative: sorted[0].fileName,
			replicas: sorted.slice(1).map(source => source.fileName),
			command: sorted[0].lineage?.command ?? 'unknown',
			normalizedIdentity: sorted[0].normalizedIdentity!,
		};
	});
}

/**
 * Detects the report type based on content keywords.
 */
export function detectReportType(content: string, fileName = '', lineage?: ReportSourceLineage): string {
	const lowerName = fileName.toLowerCase();
	const commandTypes: Record<string, string> = {
		'hexcore.filetype.detect': 'filetype', 'hexcore.hashcalc.calculate': 'hash',
		'hexcore.peanalyzer.analyze': 'pe-analysis', 'hexcore.entropy.analyze': 'entropy',
		'hexcore.disasm.analyzePEHeadless': 'pe-analysis', 'hexcore.disasm.analyzeELFHeadless': 'elf-analysis',
		'hexcore.ioc.extract': 'ioc', 'hexcore.ioc.extractHeadless': 'ioc',
		'hexcore.yara.scan': 'yara', 'hexcore.yara.scanHeadless': 'yara',
		'hexcore.audit.refcountScan': 'refcount-audit',
		'hexcore.disasm.detectPackerHeadless': 'packer', 'hexcore.disasm.detectPacker': 'packer',
		'hexcore.disasm.disassembleAtHeadless': 'disassembly', 'hexcore.disasm.liftToIR': 'llvm-ir',
		'hexcore.helix.decompile': 'decompilation', 'hexcore.helix.decompileIR': 'decompilation',
	};
	if (lineage?.command && commandTypes[lineage.command]) return commandTypes[lineage.command];
	if (lineage?.command?.startsWith('hexcore.strings.')) return 'strings';
	if (lowerName === 'hexcore-pipeline.status.json' || lineage?.command === 'hexcore.pipeline.jobStatus') {
		return 'pipeline-status';
	}
	if (lineage?.command === 'hexcore.disasm.windowsFilesystemAuditHeadless') {
		return 'windows-filesystem-audit';
	}
	if (lineage?.command === 'hexcore.disasm.analyzeAll') {
		return 'analysis-index';
	}
	if (lineage?.command === 'hexcore.peanalyzer.analyze') {
		return 'pe-analysis';
	}
	if (lineage?.command === 'hexcore.hql.scanHeadless') {
		return 'hql';
	}
	if (lineage?.command?.startsWith('hexcore.propagation.')) { return 'semantic-propagation'; }
	if (lineage?.command?.startsWith('hexcore.typeManager.') || lineage?.command === 'hexcore.types.ingestDebug' || lineage?.command === 'hexcore.records.recover') { return 'semantic-types'; }
	if (lineage?.command?.startsWith('hexcore.pdb.') || lineage?.command === 'hexcore.signatures.apply') { return 'semantic-provider'; }
	if (lineage?.command && lineage.command !== 'unknown') return 'unknown';
	if (lowerName.endsWith('.json')) {
		try {
			const parsed = asRecord(JSON.parse(content));
			if (parsed) {
				if (typeof parsed.magicBytesHex === 'string' && Array.isArray(parsed.matches)) return 'filetype';
				if (typeof parsed.command === 'string' && commandTypes[parsed.command]) return commandTypes[parsed.command];
				if (typeof parsed.command === 'string' && parsed.command.startsWith('hexcore.propagation.')) return 'semantic-propagation';
				if (parsed.format === 'hexcore-type-manager-export' || parsed.command === 'hexcore.records.recover' || parsed.command === 'hexcore.types.ingestDebug') return 'semantic-types';
				if (parsed.command === 'hexcore.pdb.importSemantics' || parsed.command === 'hexcore.signatures.apply') return 'semantic-provider';
				if (asRecord(parsed.runtimeEvidence)?.producer === 'hexcore-debugger:runtime-observations-r37') return 'runtime-evidence';
				if (parsed.command === 'hexcore.hql.scanHeadless' && Array.isArray(parsed.results) && typeof parsed.targetCount === 'number') {
					return 'hql';
				}
				if (Array.isArray(parsed.steps) && asRecord(parsed.provenance) && typeof parsed.jobFile === 'string') {
					return 'pipeline-status';
				}
				if (Array.isArray(parsed.chain) && Array.isArray(parsed.candidateFunctions) && Array.isArray(parsed.capabilities)) {
					return 'windows-filesystem-audit';
				}
				if (typeof parsed.materializedFunctionRatio === 'number' && Array.isArray(parsed.functions) && typeof parsed.totalFunctions === 'number') {
					return 'analysis-index';
				}
				if (parsed.executionManifest || parsed.windowsSecuritySummary || parsed.isPE === true ||
					(/^PE(?:32|64)?$/.test(String(asRecord(parsed.fileInfo)?.format ?? '')) && Array.isArray(parsed.sections))) {
					return 'pe-analysis';
				}
				if (parsed.indicators && typeof parsed.indicators === 'object') { return 'ioc'; }
				if (Array.isArray(parsed.matches) && parsed.matches.some((match: unknown) => typeof asRecord(match)?.ruleName === 'string')) { return 'yara'; }
				if (Array.isArray(parsed.results) && parsed.results.some((item: unknown) => typeof asRecord(item)?.value === 'string')) {
					return 'strings';
				}
				if (typeof parsed.entropy === 'number' || Array.isArray(parsed.entropyBySection)) { return 'entropy'; }
				// Arbitrary JSON text (including strings inside PE metadata) is not a schema.
				return 'unknown';
			}
		} catch { /* keyword fallback for malformed/legacy JSON */ }
	}
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
 * Escape a value for safe inclusion in a single Markdown table cell. An
 * unescaped `|` splits the cell and a literal newline breaks the whole table
 * row -- both can arrive from untrusted analyzed content (IOC values, file
 * names). The prior cross-module value escape handled only `|`, and the Sources
 * table file name was unescaped.
 */
export function escapeMarkdownCell(value: string): string {
	return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
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

function extractEvidenceFromSource(source: ReportSource, rejected: NonNullable<ComposedReport['rejectedIndicators']> = []): RawEvidence[] {
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
							const reason = indicatorRejection(String(cat), item.value, typeof item.context === 'string' ? item.context : '');
							if (reason) rejected.push({ source: source.fileName, kind: String(cat), value: item.value, reason });
							else ev.push({ value: item.value, kind: String(cat), offset: typeof item.offset === 'number' ? item.offset : undefined });
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
			return ev;
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
	const bucket = new Map<string, {
		value: string;
		kind: string;
		lineages: Map<string, Set<string>>;
		offsets: Set<number>;
	}>();

	for (const src of sources) {
		const evidence = extractEvidenceFromSource(src);
		// Track which source names we already charged for a (kind,value) pair
		// in THIS source — prevents double-count from a source that mentions
		// the same URL 20 times.
		const seenThisSource = new Set<string>();
		for (const e of evidence) {
			const key = `${targetScope(src)}::${e.kind}::${e.value}`;
			let bucketEntry = bucket.get(key);
			if (!bucketEntry) {
				bucketEntry = { value: e.value, kind: e.kind, lineages: new Map(), offsets: new Set() };
				bucket.set(key, bucketEntry);
			}
			if (!seenThisSource.has(key)) {
				const lineage = independenceKey(src);
				const lineageSources = bucketEntry.lineages.get(lineage) ?? new Set<string>();
				lineageSources.add(src.fileName);
				bucketEntry.lineages.set(lineage, lineageSources);
				seenThisSource.add(key);
			}
			if (typeof e.offset === 'number') { bucketEntry.offsets.add(e.offset); }
		}
	}

	const findings: CrossModuleFinding[] = [];
	for (const entry of bucket.values()) {
		// Only emit findings corroborated by 2+ distinct reports.
		if (entry.lineages.size < 2) { continue; }
		const independentSources = [...entry.lineages.values()]
			.map(sourceNames => [...sourceNames].sort()[0])
			.sort();
		findings.push({
			evidenceLevel: 'signal', independentCorroboration: false,
			value: entry.value,
			kind: entry.kind,
			sources: independentSources,
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
	scanReportsDirectory(dirPath: string, excludePaths: readonly string[] = []): ReportSource[] {
		if (!fs.existsSync(dirPath)) {
			throw new Error(`Reports directory not found: ${dirPath}`);
		}

		const stat = fs.statSync(dirPath);
		if (!stat.isDirectory()) {
			throw new Error(`Path is not a directory: ${dirPath}`);
		}

		const excluded = new Set(excludePaths.map(candidate => path.resolve(candidate).toLowerCase()));
		const provenanceIndex = loadProvenanceIndex(dirPath);
		const entries = fs.readdirSync(dirPath);
		const sources: ReportSource[] = [];

		for (const entry of entries) {
			const ext = path.extname(entry).toLowerCase();
			if (ext !== '.md' && ext !== '.json') {
				continue;
			}

			const filePath = path.join(dirPath, entry);
			if (excluded.has(path.resolve(filePath).toLowerCase())) {
				continue;
			}
			const fileStat = fs.statSync(filePath);
			if (!fileStat.isFile()) {
				continue;
			}

			const content = fs.readFileSync(filePath, 'utf8');
			const lineage = provenanceIndex.get(path.resolve(filePath).toLowerCase());
			sources.push({
				filePath,
				fileName: entry,
				content,
				type: detectReportType(content, entry, lineage),
				...(lineage ? { lineage } : {}),
				normalizedIdentity: normalizedContentIdentity(entry, content),
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
			hexcoreVersion: '3.8.4',
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
		const rejected: NonNullable<ComposedReport['rejectedIndicators']> = [];
		for (const source of sources) extractEvidenceFromSource(source, rejected);
		if (rejected.length) report.rejectedIndicators = rejected;
		const replicatedSources = findSourceReplications(sources);
		if (replicatedSources.length > 0) {
			report.replicatedSources = replicatedSources;
		}

		return report;
	}

	private summarizeSource(source: ReportSource): SourceSummary {
		const highlights: string[] = [];
		if (source.fileName.toLowerCase().endsWith('.json')) {
			try {
				const parsed = JSON.parse(source.content) as Record<string, unknown>;
				if (source.type === 'hql') {
					for (const key of ['status', 'targetCount', 'completedTargetCount', 'failedTargetCount', 'matchedFunctionCount', 'totalFindings']) {
						const value = parsed[key];
						if (typeof value === 'string' || typeof value === 'number') highlights.push(`${key}: ${String(value)}`);
					}
				}
				for (const key of ['status', 'success', 'summary', 'verdict', 'confidence', 'error']) {
					const value = parsed[key];
					if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
						highlights.push(`${key}: ${String(value)}`);
					}
				}
				for (const [key, value] of Object.entries(parsed)) {
					if (Array.isArray(value) && value.length > 0) {
						highlights.push(`${key}: ${value.length} item(s)`);
					}
					if (highlights.length >= 8) { break; }
				}
			} catch {
				// Invalid JSON remains an attachment and is described by size/type.
			}
		} else {
			const meaningful = source.content.split(/\r?\n/)
				.map(line => line.trim())
				.filter(line => line.length > 0 && !/^[-|: ]+$/.test(line));
			const priority = meaningful.filter(line =>
				/^(#{1,4}\s)|\b(critical|high|warning|error|finding|verdict|confidence)\b/i.test(line));
			for (const line of [...priority, ...meaningful]) {
				const normalized = line.replace(/\s+/g, ' ');
				if (!highlights.includes(normalized)) {
					highlights.push(normalized.slice(0, 240));
				}
				if (highlights.length >= 8) { break; }
			}
		}

		return {
			fileName: source.fileName,
			type: source.type,
			bytes: Buffer.byteLength(source.content, 'utf8'),
			highlights,
		};
	}

	/**
	 * Produces an operational handoff. Analyzer blobs remain linked attachments
	 * instead of being copied into a multi-megabyte Markdown document.
	 */
	toSummaryMarkdown(report: ComposedReport): string {
		const lines: string[] = [
			`# ${report.title}`,
			'',
			`> Generated at: ${report.generatedAt}`,
			`> HexCore Version: ${report.hexcoreVersion}`,
			`> Sources: ${report.sources.length} report(s); full evidence remains in the linked attachments.`,
			'',
		];

		if (report.analystNotes) {
			lines.push('## Analyst Notes', '', report.analystNotes, '');
		}

		const indexes = report.sources.filter(source => source.type === 'analysis-index');
		if (indexes.length) {
			lines.push('## Analysis Coverage', '', 'A successful discovery command is not a clean security assessment.', '',
				'| Artifact | Depth | Complete / indexed | Ratio | Negative evidence |',
				'|----------|-------|-------------------:|------:|-------------------|');
			for (const source of indexes) {
				try {
					const data = JSON.parse(source.content);
					const complete = data.functionsMaterialized ?? data.functions?.filter((fn: any) => fn.bodyStatus === 'materialized').length;
					lines.push(`| ${escapeMarkdownCell(source.fileName)} | ${escapeMarkdownCell(data.analysisDepth ?? 'depth-not-declared')} | ${complete ?? 'unknown'} / ${data.totalFunctions ?? 'unknown'} | ${typeof data.materializedFunctionRatio === 'number' ? (data.materializedFunctionRatio * 100).toFixed(4) + '%' : 'unknown'} | not established |`);
				} catch { lines.push(`| ${escapeMarkdownCell(source.fileName)} | unreadable | unknown | unknown | unusable |`); }
			}
			lines.push('');
		}
		const refcountAudits = report.sources.filter(source => source.type === 'refcount-audit');
		if (refcountAudits.length) {
			lines.push('## Audit Input Quality', '', '| Artifact | Status | Negative evidence usable | Conclusion |', '|----------|--------|--------------------------|------------|');
			for (const source of refcountAudits) {
				try {
					const data = JSON.parse(source.content);
					lines.push(`| ${escapeMarkdownCell(source.fileName)} | ${escapeMarkdownCell(data.status ?? 'quality-not-declared')} | ${data.negativeEvidenceUsable === true ? 'within scanner scope only' : 'false'} | ${escapeMarkdownCell(data.conclusion ?? 'inconclusive: upstream quality not declared')} |`);
				} catch { /* malformed artifacts remain linked */ }
			}
			lines.push('');
		}
		if (report.rejectedIndicators?.length) {
			lines.push('## Indicator Validation', '', `${report.rejectedIndicators.length} extracted values excluded from IOC assertions; originals remain in the attachments.`, '',
				'| Source | Kind | Value | Reason |', '|--------|------|-------|--------|');
			for (const item of report.rejectedIndicators.slice(0, 50)) lines.push(`| ${escapeMarkdownCell(item.source)} | ${escapeMarkdownCell(item.kind)} | ${escapeMarkdownCell(item.value)} | ${escapeMarkdownCell(item.reason)} |`);
			lines.push('');
		}

		const semanticFindings = (report.crossModuleFindings ?? []).filter(finding => finding.kind !== 'offset');
		if (semanticFindings.length) {
			lines.push('## Cross-Analyzer Observations', '', 'Evidence level: signal. Agreement between parsers of the same bytes does not establish independent corroboration or malicious behavior.', '');
			lines.push('| Kind | Value | Sources | Offsets |');
			lines.push('|------|-------|---------|---------|');
			for (const finding of semanticFindings.slice(0, 50)) {
				const offsets = finding.offsets.slice(0, 5)
					.map(offset => `0x${offset.toString(16)}`).join(', ') || '—';
				lines.push(`| ${escapeMarkdownCell(finding.kind)} | \`${escapeMarkdownCell(finding.value)}\` | ${finding.sources.length} | ${offsets} |`);
			}
			lines.push('');
		}

		if (report.replicatedSources?.length) {
			lines.push('## Replicated Evidence', '');
			lines.push('| Representative | Replicas | Producer method |');
			lines.push('|----------------|----------|-----------------|');
			for (const group of report.replicatedSources) {
				lines.push(`| ${escapeMarkdownCell(group.representative)} | ${escapeMarkdownCell(group.replicas.join(', '))} | ${escapeMarkdownCell(group.command)} |`);
			}
			lines.push('', 'Replicated artifacts confirm deterministic reproduction but do not increase independent corroboration.', '');
		}

		const hqlReplicaNames = new Set((report.replicatedSources ?? []).flatMap(group => group.replicas));
		const hqlArtifacts = report.sources.flatMap(source => {
			if (source.type !== 'hql' || hqlReplicaNames.has(source.fileName)) return [];
			try {
				const parsed = asRecord(JSON.parse(source.content));
				return parsed && Array.isArray(parsed.results) ? [{ source, parsed }] : [];
			} catch { return []; }
		});
		if (hqlArtifacts.length > 0) {
			lines.push('## HQL Semantic Scan', '');
			const findings = hqlArtifacts.flatMap(({ parsed }) => parsed.results.flatMap((result: any) => result.findings ?? []));
			const semanticFacts = hqlArtifacts.reduce((sum, { parsed }) => sum + parsed.results.reduce((count: number, result: any) => count + Number(result.semanticFactCount ?? 0), 0), 0);
			lines.push(`Evidence levels: ${['signal', 'candidate', 'proven'].map(level => `${level}=${findings.filter((finding: any) => (finding.evidenceLevel ?? 'signal') === level).length}`).join(', ')}. Semantic facts: ${semanticFacts}.`, '');
			lines.push('HQL findings are structural evidence. Presentation severity and structural completeness are not vulnerability confidence.', '');
			lines.push('| Artifact | Status | Targets | No matches | Matched | Findings | Lossy functions | HAST | Signature sets |');
			lines.push('|----------|--------|--------:|------:|--------:|---------:|----------------:|------|----------------|');
			for (const { source, parsed } of hqlArtifacts) {
				const results = parsed.results as unknown[];
				const completed = results.filter(result => !asRecord(result)?.error);
				const clean = completed.filter(result => Array.isArray(asRecord(result)?.findings) && asRecord(result)!.findings.length === 0).length;
				const matched = completed.filter(result => Array.isArray(asRecord(result)?.findings) && asRecord(result)!.findings.length > 0).length;
				const lossy = completed.filter(result => Number(asRecord(asRecord(result)?.adapterCoverage)?.lossyNodes ?? 0) > 0).length;
				const signatureSets = [...new Set(completed.map(result => String(asRecord(result)?.signatureSetSha256 ?? '')).filter(Boolean))];
				const hast = asRecord(asRecord(completed[0])?.hast) ?? {};
				const capabilityLabel = Array.isArray(hast.capabilities) ? hast.capabilities.join(',') || 'none' : String(hast.capabilities ?? 'none');
				const hastLabel = `${Number(hast.schemaMajor ?? 0)}.${Number(hast.schemaMinor ?? 0)} ${capabilityLabel}${hast.semanticEligible === true ? ' semantic' : ' structural'}`;
				lines.push(`| ${escapeMarkdownCell(source.fileName)} | ${escapeMarkdownCell(String(parsed.status ?? 'unknown'))} | ${Number(parsed.targetCount ?? results.length)} | ${clean} | ${matched} | ${Number(parsed.totalFindings ?? 0)} | ${lossy} | ${escapeMarkdownCell(hastLabel)} | ${escapeMarkdownCell(signatureSets.map(hash => hash.slice(0, 12)).join(', ') || 'unbound')} |`);
			}
			lines.push('');
			const hqlFunctionRows = hqlArtifacts.flatMap(({ source, parsed }) => (parsed.results as unknown[])
				.map(rawResult => ({ source, result: asRecord(rawResult) }))
				.filter((row): row is { source: ReportSource; result: Record<string, any> } => Boolean(row.result)));
			const allSignatureSets = [...new Set(hqlFunctionRows.map(row => String(row.result.signatureSetSha256 ?? '')).filter(Boolean))];
			if (allSignatureSets.length > 1) {
				lines.push(`- Signature-set divergence: ${allSignatureSets.map(hash => `\`${hash}\``).join(', ')}`, '');
			}
			const cleanRows = hqlFunctionRows.filter(({ result }) => !result.error && result.status !== 'partial' && Array.isArray(result.findings) && result.findings.length === 0);
			if (cleanRows.length > 0) {
				lines.push('### HQL No-Match Results', '', 'No structural match is not proof of absence of a defect. Adapter coverage measures HAST conversion, not decompilation correctness.', '', '| Function | Address | AST nodes | Adapter coverage |', '|----------|---------|----------:|-----------------:|');
				for (const { result } of cleanRows.slice(0, 100)) {
					lines.push(`| ${escapeMarkdownCell(String(result.function ?? 'unknown'))} | ${escapeMarkdownCell(String(result.address ?? 'unknown'))} | ${Number(result.nodeCount ?? 0)} | ${Number(asRecord(result.adapterCoverage)?.coverage ?? 0).toFixed(3)} |`);
				}
				lines.push('');
			}
			const hqlErrors = hqlFunctionRows.filter(({ result }) => result.error || result.status === 'error');
			if (hqlErrors.length > 0) {
				lines.push('### HQL Target Errors', '', '| Requested target | Address | Error |', '|------------------|---------|-------|');
				for (const { result } of hqlErrors.slice(0, 100)) {
					lines.push(`| ${escapeMarkdownCell(String(result.requestedTarget ?? 'unknown'))} | ${escapeMarkdownCell(String(result.address ?? 'unknown'))} | ${escapeMarkdownCell(String(result.error ?? 'error without diagnostic'))} |`);
				}
				lines.push('');
			}
			const lossyRows = hqlFunctionRows.filter(({ result }) => Number(asRecord(result.adapterCoverage)?.lossyNodes ?? 0) > 0 || result.status === 'partial');
			if (lossyRows.length > 0) {
				lines.push('### HQL Adapter Loss And Budgets', '', '| Function | Address | Lossy nodes | Unsupported kinds | Truncation/errors |', '|----------|---------|------------:|-------------------|-------------------|');
				for (const { result } of lossyRows.slice(0, 100)) {
					const coverage = asRecord(result.adapterCoverage) ?? {};
					const unsupported = asRecord(coverage.unsupportedNodeCounts) ?? {};
					const reasons = [
						...(Array.isArray(result.partialReasons) ? result.partialReasons.map(String) : []),
						...(Array.isArray(result.truncationReasons) ? result.truncationReasons.map(String) : []),
					].join('; ');
					lines.push(`| ${escapeMarkdownCell(String(result.function ?? 'unknown'))} | ${escapeMarkdownCell(String(result.address ?? 'unknown'))} | ${Number(coverage.lossyNodes ?? 0)} | ${escapeMarkdownCell(Object.entries(unsupported).map(([kind, count]) => `${kind}:${count}`).join(', ') || 'none')} | ${escapeMarkdownCell(reasons || 'none')} |`);
				}
				lines.push('');
			}

			const findingRows = hqlArtifacts.flatMap(({ source, parsed }) => (parsed.results as unknown[]).flatMap(rawResult => {
				const result = asRecord(rawResult);
				if (!result || !Array.isArray(result.findings)) return [];
				return result.findings.map((rawFinding: unknown) => ({ source, result, finding: asRecord(rawFinding) })).filter(row => row.finding);
			}));
			if (findingRows.length > 0) {
				lines.push('### HQL Findings', '');
				lines.push('| Function | Address | Signature | Evidence | Structural | Adapter | Calibrated confidence |');
				lines.push('|----------|---------|-----------|----------|-----------:|--------:|----------------------:|');
				for (const { result, finding } of findingRows.slice(0, 100)) {
					const calibrated = typeof finding!.confidence === 'number' ? finding!.confidence.toFixed(3) : 'not calibrated';
					lines.push(`| ${escapeMarkdownCell(String(result.function ?? 'unknown'))} | ${escapeMarkdownCell(String(result.address ?? 'unknown'))} | ${escapeMarkdownCell(String(finding!.signatureId ?? 'unknown'))} | ${escapeMarkdownCell(String(finding!.evidenceLevel ?? 'signal'))} | ${Number(finding!.structuralCompleteness ?? 0).toFixed(3)} | ${Number(finding!.adapterCoverage ?? asRecord(result.adapterCoverage)?.coverage ?? 0).toFixed(3)} | ${calibrated} |`);
				}
				lines.push('');
			}
		}

		const semanticArtifacts = report.sources.flatMap(source => {
			if (!source.fileName.toLowerCase().endsWith('.json')) return [];
			try {
				const parsed = asRecord(JSON.parse(source.content));
				if (!parsed) return [];
				const runtime = asRecord(parsed.runtimeEvidence);
				const semantic = source.type.startsWith('semantic-') || runtime?.producer === 'hexcore-debugger:runtime-observations-r37';
				return semantic ? [{ source, parsed, runtime }] : [];
			} catch { return []; }
		});
		if (semanticArtifacts.length > 0) {
			lines.push('## Semantic Model Coverage', '');
			lines.push('| Artifact | Kind | Status | Types | Xrefs | Summaries | Conflicts | Barriers | Generation | Normalized identity |');
			lines.push('|----------|------|--------|------:|------:|----------:|----------:|---------:|------------|---------------------|');
			for (const { source, parsed, runtime } of semanticArtifacts) {
				const collection = asRecord(parsed.collection) ?? {};
				const run = asRecord(parsed.run) ?? {};
				const payload = asRecord(parsed.payload) ?? {};
				const propagation = asRecord(payload.propagation) ?? {};
				const recovery = asRecord(parsed.recovery) ?? {};
				const provider = asRecord(parsed.provider) ?? {};
				const typePayload = parsed.format === 'hexcore-type-manager-export' ? payload : {};
				const types = Array.isArray(typePayload.types) ? typePayload.types.length : Number(asRecord(parsed.types)?.typeCount ?? parsed.auxiliaryTypeCount ?? 0);
				const xrefs = Number(asRecord(parsed.references)?.edgesCollected ?? 0);
				const summaries = Array.isArray(run.summaries) ? run.summaries.length : Array.isArray(propagation.summaries) ? propagation.summaries.length : 0;
				const conflicts = (Array.isArray(run.summaries) ? run.summaries : Array.isArray(propagation.summaries) ? propagation.summaries : []).reduce((count: number, raw: unknown) => count + (Array.isArray(asRecord(raw)?.conflicts) ? asRecord(raw)!.conflicts.length : 0), 0);
				const barriers = Number(collection.barrierCount ?? 0) + (Array.isArray(recovery.groups) ? recovery.groups.filter((group: unknown) => asRecord(group)?.status !== 'promoted').length : 0);
				const identity = String(parsed.outputHash ?? parsed.contentHash ?? runtime?.normalizedIdentitySha256 ?? asRecord(parsed.identity)?.artifactSha256 ?? 'unbound');
				const kind = runtime ? 'runtime corroboration' : source.type.replace('semantic-', '');
				const status = String(parsed.semanticStatus ?? parsed.status ?? run.status ?? provider.status ?? 'ok');
				const generation = String(collection.analysisGeneration ?? run.generation ?? payload.analysisGeneration ?? 'n/a');
				lines.push(`| ${escapeMarkdownCell(source.fileName)} | ${escapeMarkdownCell(kind)} | ${escapeMarkdownCell(status)} | ${types} | ${xrefs} | ${summaries} | ${conflicts} | ${barriers} | ${escapeMarkdownCell(generation)} | ${escapeMarkdownCell(identity.slice(0, 16))} |`);
			}
			lines.push('');

			const providerRows = semanticArtifacts.flatMap(({ source, parsed }) => {
				const provider = asRecord(parsed.provider);
				if (provider) return [{ source, kind: 'debug', id: String(provider.providerVersion ?? 'pdb'), hash: String(provider.pdbSha256 ?? ''), status: String(provider.status ?? 'unknown'), facts: Number(parsed.prototypeCount ?? 0) }];
				if (parsed.command === 'hexcore.signatures.apply') return [{ source, kind: 'signature', id: String(parsed.providerId ?? 'unknown'), hash: String(parsed.storeHash ?? ''), status: String(parsed.status ?? 'unknown'), facts: Number(parsed.matchedCount ?? 0) }];
				return [];
			});
			if (providerRows.length > 0) {
				lines.push('### Semantic Providers', '', '| Provider | Class | Status | Facts | Hash |', '|----------|-------|--------|------:|------|');
				for (const row of providerRows) lines.push(`| ${escapeMarkdownCell(row.id)} | ${row.kind} | ${escapeMarkdownCell(row.status)} | ${row.facts} | ${escapeMarkdownCell(row.hash.slice(0, 16) || 'unbound')} |`);
				lines.push('');
			}

			const runtimeRows = semanticArtifacts.flatMap(({ source, runtime }) => runtime ? [{ source, runtime }] : []);
			if (runtimeRows.length > 0) {
				lines.push('### Runtime Corroboration', '', 'Runtime observations are bound to binary and input configuration. They corroborate but do not replace static proof.', '');
				lines.push('| Artifact | Binary | Input config | Trace config | Observations | Truncated |', '|----------|--------|--------------|--------------|-------------:|-----------|');
				for (const { source, runtime } of runtimeRows) {
					const target = asRecord(runtime.target) ?? {};
					lines.push(`| ${escapeMarkdownCell(source.fileName)} | ${escapeMarkdownCell(String(target.binarySha256 ?? '').slice(0, 16))} | ${escapeMarkdownCell(String(runtime.inputConfigurationSha256 ?? '').slice(0, 16))} | ${escapeMarkdownCell(String(runtime.traceConfigurationSha256 ?? '').slice(0, 16))} | ${Array.isArray(runtime.observations) ? runtime.observations.length : 0} | ${String(runtime.truncated === true)} |`);
				}
				lines.push('');
			}
		}

		const closureArtifacts = report.sources.flatMap(source => {
			if (!source.fileName.toLowerCase().endsWith('.json')) { return []; }
			try {
				const parsed = asRecord(JSON.parse(source.content));
				const closure = asRecord(parsed?.analysisClosure);
				return closure ? [{ source, parsed: parsed!, closure }] : [];
			} catch {
				return [];
			}
		});
		if (closureArtifacts.length > 0) {
			lines.push('## Investigation Closure', '');
			lines.push('| Artifact | Function | Closure | Audit universe changed | Semantic instructions | Engine generation | Session generation | Reason |');
			lines.push('|----------|----------|---------|------------------------|----------------------:|-------------------|--------------------|--------|');
			for (const { source, parsed, closure } of closureArtifacts) {
				const engineGeneration = `${String(closure.engineGenerationBefore ?? '?')} -> ${String(closure.engineGenerationAfter ?? '?')}`;
				const sessionGeneration = closure.sessionGenerationBefore !== undefined || closure.sessionGenerationAfter !== undefined
					? `${String(closure.sessionGenerationBefore ?? '?')} -> ${String(closure.sessionGenerationAfter ?? '?')}`
					: 'not persisted';
				lines.push(`| ${escapeMarkdownCell(source.fileName)} | ${escapeMarkdownCell(String(closure.functionAddress ?? 'unknown'))} | ${escapeMarkdownCell(String(closure.status ?? 'unknown'))} | ${String(closure.auditUniverseChanged === true)} | ${Number(parsed.semanticInstructionCount ?? 0)} | ${escapeMarkdownCell(engineGeneration)} | ${escapeMarkdownCell(sessionGeneration)} | ${escapeMarkdownCell(String(closure.reason ?? ''))} |`);
			}
			lines.push('');
		}

		const nativeExecutions = report.sources.flatMap(source => {
			if (!source.fileName.toLowerCase().endsWith('.json')) { return []; }
			try {
				const parsed = asRecord(JSON.parse(source.content));
				const execution = asRecord(parsed?.nativeExecution);
				return execution ? [{ source, execution }] : [];
			} catch { return []; }
		});
		if (nativeExecutions.length > 0) {
			lines.push('## Native Analysis Execution', '');
			lines.push('| Artifact | Isolation | Outcome | Worker PID | Duration | Last phase | Snapshot | Heartbeat |');
			lines.push('|----------|-----------|---------|-----------:|---------:|------------|---------:|-----------|');
			for (const { source, execution } of nativeExecutions) {
				const compressed = Number(execution.snapshotBytes ?? 0);
				const uncompressed = Number(execution.snapshotUncompressedBytes ?? 0);
				const snapshot = compressed > 0
					? `${compressed} B${uncompressed > 0 ? ` / ${uncompressed} B raw` : ''}`
					: 'none';
				lines.push(`| ${escapeMarkdownCell(source.fileName)} | ${escapeMarkdownCell(String(execution.isolation ?? 'unknown'))} | ${escapeMarkdownCell(String(execution.outcome ?? 'unknown'))} | ${Number(execution.workerPid ?? 0)} | ${Number(execution.durationMs ?? 0)} ms | ${escapeMarkdownCell(String(execution.lastPhase ?? 'unknown'))} | ${escapeMarkdownCell(snapshot)} | ${escapeMarkdownCell(String(execution.heartbeatPath ?? 'unavailable'))} |`);
			}
			lines.push('');
		}

		const replicaNames = new Set((report.replicatedSources ?? []).flatMap(group => group.replicas));
		const audits: Array<{ source: ReportSource; parsed: Record<string, any> }> = [];
		for (const source of report.sources) {
			if (source.type !== 'windows-filesystem-audit' || replicaNames.has(source.fileName)) { continue; }
			try {
				const parsed = asRecord(JSON.parse(source.content));
				if (parsed && Array.isArray(parsed.chain) && Array.isArray(parsed.candidateFunctions)) {
					audits.push({ source, parsed });
				}
			} catch { /* invalid audit remains in Source Summary */ }
		}
		const auditGroups = new Map<string, typeof audits>();
		for (const audit of audits) {
			const key = independenceKey(audit.source);
			const group = auditGroups.get(key) ?? [];
			group.push(audit);
			auditGroups.set(key, group);
		}
		for (const group of auditGroups.values()) {
			if (group.length > 1) {
				lines.push('## Windows Filesystem Audit Comparison', '');
				lines.push('| File | maxStringSignals | Pivots | Candidates | Related | Edges | Blocked/Missing |');
				lines.push('|------|-----------------:|-------:|-----------:|--------:|------:|----------------:|');
				for (const audit of group) {
					const config = asRecord(audit.parsed.auditConfiguration) ?? {};
					const unresolved = audit.parsed.chain.filter((edge: unknown) => {
						const status = asRecord(edge)?.status;
						return status === 'blocked' || status === 'missing';
					}).length;
					lines.push(`| ${escapeMarkdownCell(audit.source.fileName)} | ${Number(config.maxStringSignals ?? 0)} | ${Array.isArray(audit.parsed.stringPivots) ? audit.parsed.stringPivots.length : 0} | ${audit.parsed.candidateFunctions.length} | ${Array.isArray(audit.parsed.relatedFunctions) ? audit.parsed.relatedFunctions.length : 0} | ${Array.isArray(audit.parsed.candidateEdges) ? audit.parsed.candidateEdges.length : 0} | ${unresolved} |`);
				}
				lines.push('');
			}
			const detail = [...group].sort((left, right) => {
				const richness = (audit: typeof left) => audit.parsed.candidateFunctions.length +
					(Array.isArray(audit.parsed.stringPivots) ? audit.parsed.stringPivots.length : 0) +
					(Array.isArray(asRecord(audit.parsed.dataflow)?.facts) ? asRecord(audit.parsed.dataflow)!.facts.length : 0);
				return richness(right) - richness(left) || left.source.fileName.localeCompare(right.source.fileName);
			})[0];
			const { source, parsed } = detail;
			const principal = asRecord(parsed.principal) ?? {};
			const coverage = asRecord(parsed.coverage) ?? {};
			const capabilities = Array.isArray(parsed.capabilities) ? parsed.capabilities : [];
			const ownedCapabilities = capabilities.filter(capability => asRecord(capability)?.status === 'owned-callsite').length;
			lines.push('## Windows Filesystem Boundary Audit', '');
			lines.push(`- Representative: ${escapeMarkdownCell(source.fileName)}`);
			lines.push(`- Target: ${escapeMarkdownCell(String(parsed.target ?? 'unknown'))}`);
			lines.push(`- Verdict: ${escapeMarkdownCell(String(parsed.verdict ?? parsed.status ?? 'unknown'))}`);
			lines.push(`- Principal: ${escapeMarkdownCell(String(principal.requestedExecutionLevel ?? 'not assessed'))}; uiAccess=${String(principal.uiAccess ?? 'not assessed')}`);
			lines.push(`- Materialization: ${Number(coverage.materializedFunctions ?? 0)}/${Number(coverage.totalFunctions ?? 0)} (${(Number(coverage.materializedFunctionRatio ?? 0) * 100).toFixed(2)}%); lazy=${Number(coverage.lazyFunctions ?? 0)}`);
			lines.push(`- Capabilities: ${capabilities.length}; owned callsites=${ownedCapabilities}; import-only=${capabilities.length - ownedCapabilities}`);
			lines.push(`- Candidate functions: ${parsed.candidateFunctions.length}; related functions=${Array.isArray(parsed.relatedFunctions) ? parsed.relatedFunctions.length : 0}; graph edges=${Array.isArray(parsed.candidateEdges) ? parsed.candidateEdges.length : 0}`);
			const dataflow = asRecord(parsed.dataflow);
			const deepValueFlow = asRecord(dataflow?.deepValueFlow);
			const analysisContext = asRecord(parsed.analysisContext);
			if (analysisContext) {
				lines.push(`- Analysis context: engine generation=${String(analysisContext.engineGeneration ?? 'unknown')}; session generation=${String(analysisContext.sessionGeneration ?? 'unknown')}; materialized=${Number(analysisContext.materializedFunctions ?? 0)}; lazy=${Number(analysisContext.lazyFunctions ?? 0)}; universe=${String(analysisContext.universeSha256 ?? 'unbound')}`);
			}
			const normalization = asRecord(parsed.normalization);
			if (normalization) {
				lines.push(`- Normalized identity: ${String(normalization.algorithm ?? 'unknown')} ${String(normalization.sha256 ?? 'unavailable')}`);
			}
			if (dataflow) {
				const provenHandles = Array.isArray(dataflow.handleLifecycles)
					? dataflow.handleLifecycles.filter((item: unknown) => asRecord(item)?.sameHandleProven === true).length
					: 0;
				lines.push(`- Dataflow: ${Array.isArray(dataflow.facts) ? dataflow.facts.length : 0} facts; ${Array.isArray(dataflow.typedPaths) ? dataflow.typedPaths.length : 0} typed paths; ${Array.isArray(dataflow.handleLifecycles) ? dataflow.handleLifecycles.length : 0} handle lifecycles; proven handles=${provenHandles}`);
				lines.push(`- Deep value identity: ${Array.isArray(deepValueFlow?.callsites) ? deepValueFlow!.callsites.length : 0} callsites; ${Array.isArray(deepValueFlow?.proofs) ? deepValueFlow!.proofs.length : 0} proven identities; ${Array.isArray(deepValueFlow?.signals) ? deepValueFlow!.signals.length : 0} downgraded signals`);
			}
			lines.push('');
			lines.push('| Edge | Status | Evidence | Primary blocker |');
			lines.push('|------|--------|---------:|-----------------|');
			for (const rawEdge of parsed.chain) {
				const edge = asRecord(rawEdge);
				if (!edge) { continue; }
				const evidenceCount = Array.isArray(edge.evidence) ? edge.evidence.length : 0;
				const blocker = Array.isArray(edge.blockers) && edge.blockers.length > 0 ? String(edge.blockers[0]) : '';
				lines.push(`| ${escapeMarkdownCell(String(edge.kind ?? 'unknown'))} | ${escapeMarkdownCell(String(edge.status ?? 'unknown'))} | ${evidenceCount} | ${escapeMarkdownCell(blocker)} |`);
			}
			lines.push('');
			if (Array.isArray(deepValueFlow?.proofs) && deepValueFlow!.proofs.length > 0) {
				lines.push('### Deep Value Identity Proofs', '');
				lines.push('| Kind | Function | Canonical identity | Producer | Consumer |');
				lines.push('|------|----------|--------------------|----------|----------|');
				for (const rawProof of deepValueFlow!.proofs.slice(0, 50)) {
					const proof = asRecord(rawProof);
					const producer = asRecord(proof?.producer);
					const consumer = asRecord(proof?.consumer);
					if (!proof) { continue; }
					lines.push(`| ${escapeMarkdownCell(String(proof.kind ?? ''))} | ${escapeMarkdownCell(String(proof.functionAddress ?? ''))} | ${escapeMarkdownCell(String(proof.canonicalIdentity ?? ''))} | ${escapeMarkdownCell(`${String(producer?.api ?? '')}@${String(producer?.callSite ?? '')}`)} | ${escapeMarkdownCell(`${String(consumer?.api ?? '')}@${String(consumer?.callSite ?? '')}`)} |`);
				}
				lines.push('');
			}
			if (Array.isArray(deepValueFlow?.signals) && deepValueFlow!.signals.length > 0) {
				lines.push('### Deep Value Identity Signals', '');
				lines.push('| Kind | Function | Canonical identity | Producer | Consumer | Blocker |');
				lines.push('|------|----------|--------------------|----------|----------|---------|');
				for (const rawSignal of deepValueFlow!.signals.slice(0, 50)) {
					const signal = asRecord(rawSignal);
					const producer = asRecord(signal?.producer);
					const consumer = asRecord(signal?.consumer);
					const blocker = Array.isArray(signal?.blockers) ? String(signal!.blockers[0] ?? '') : '';
					if (!signal) { continue; }
					lines.push(`| ${escapeMarkdownCell(String(signal.kind ?? ''))} | ${escapeMarkdownCell(String(signal.functionAddress ?? ''))} | ${escapeMarkdownCell(String(signal.canonicalIdentity ?? ''))} | ${escapeMarkdownCell(`${String(producer?.api ?? '')}@${String(producer?.callSite ?? '')}`)} | ${escapeMarkdownCell(`${String(consumer?.api ?? '')}@${String(consumer?.callSite ?? '')}`)} | ${escapeMarkdownCell(blocker)} |`);
				}
				lines.push('');
			}
			if (Array.isArray(parsed.topCandidateChains) && parsed.topCandidateChains.length > 0) {
				const typedChains = parsed.topCandidateChains.filter((chain: unknown) => !String(asRecord(chain)?.kind ?? '').startsWith('product-'));
				const productRoutes = parsed.topCandidateChains.filter((chain: unknown) => String(asRecord(chain)?.kind ?? '').startsWith('product-'));
				lines.push('### Typed Candidate Chains', '');
				lines.push('| Kind | Status | Route | Score |');
				lines.push('|------|--------|-------|------:|');
				for (const rawChain of typedChains.slice(0, 12)) {
					const chain = asRecord(rawChain);
					if (!chain) { continue; }
					const route = Array.isArray(chain.functions) ? chain.functions.map((item: unknown) => String(asRecord(item)?.address ?? '')).filter(Boolean).join(' -> ') : '';
					lines.push(`| ${escapeMarkdownCell(String(chain.kind ?? 'unknown'))} | ${escapeMarkdownCell(String(chain.status ?? 'unknown'))} | ${escapeMarkdownCell(route)} | ${Number(chain.score ?? 0)} |`);
				}
				lines.push('');
				if (productRoutes.length > 0) {
					lines.push('### Product-Attributed Routes', '');
					lines.push('| Kind | Route | Score |');
					lines.push('|------|-------|------:|');
					for (const rawChain of productRoutes.slice(0, 30)) {
						const chain = asRecord(rawChain);
						if (!chain) { continue; }
						const route = Array.isArray(chain.functions) ? chain.functions.map((item: unknown) => String(asRecord(item)?.address ?? '')).filter(Boolean).join(' -> ') : '';
						lines.push(`| ${escapeMarkdownCell(String(chain.kind ?? 'unknown'))} | ${escapeMarkdownCell(route)} | ${Number(chain.score ?? 0)} |`);
					}
					lines.push('');
				}
			}
			if (Array.isArray(parsed.criticalHelpers) && parsed.criticalHelpers.length > 0) {
				lines.push('### Critical Helper Expansion', '');
				lines.push('| Depth | Address | Via | Product roots | Score |');
				lines.push('|------:|---------|-----|--------------:|------:|');
				const helpers = [
					...parsed.criticalHelpers.filter((helper: unknown) => Number(asRecord(helper)?.depth) === 1).slice(0, 20),
					...parsed.criticalHelpers.filter((helper: unknown) => Number(asRecord(helper)?.depth) === 2).slice(0, 20),
				];
				for (const rawHelper of helpers) {
					const helper = asRecord(rawHelper);
					if (!helper) { continue; }
					lines.push(`| ${Number(helper.depth ?? 0)} | ${escapeMarkdownCell(String(helper.address ?? ''))} | ${escapeMarkdownCell(String(helper.via ?? ''))} | ${Array.isArray(helper.sourceCandidates) ? helper.sourceCandidates.length : 0} | ${Number(helper.score ?? 0)} |`);
				}
				lines.push('');
			}
			const boundaryOwners = parsed.candidateFunctions
				.filter((candidate: unknown) => Number(asRecord(candidate)?.criticalApiWeight ?? 0) > 0)
				.sort((left: unknown, right: unknown) => Number(asRecord(right)?.criticalApiWeight ?? 0) - Number(asRecord(left)?.criticalApiWeight ?? 0) || Number(asRecord(right)?.rankScore ?? 0) - Number(asRecord(left)?.rankScore ?? 0));
			if (boundaryOwners.length > 0) {
				lines.push('### Boundary API Owners', '');
				lines.push('| Address | Roles | API weight | Rank |');
				lines.push('|---------|-------|-----------:|-----:|');
				for (const rawCandidate of boundaryOwners.slice(0, 25)) {
					const candidate = asRecord(rawCandidate)!;
					lines.push(`| ${escapeMarkdownCell(String(candidate.address ?? ''))} | ${escapeMarkdownCell(Array.isArray(candidate.roles) ? candidate.roles.join(', ') : '')} | ${Number(candidate.criticalApiWeight ?? 0)} | ${Number(candidate.rankScore ?? 0)} |`);
				}
				lines.push('');
			}
			lines.push('### Top Candidate Functions', '');
			lines.push('| Position | Address | Name | Roles | Score | Evidence |');
			lines.push('|---------:|---------|------|-------|------:|---------:|');
			for (const [position, rawCandidate] of parsed.candidateFunctions.slice(0, 30).entries()) {
				const candidate = asRecord(rawCandidate);
				if (!candidate) { continue; }
				const roles = Array.isArray(candidate.roles) ? candidate.roles.join(', ') : '';
				lines.push(`| ${position + 1} | ${escapeMarkdownCell(String(candidate.address ?? ''))} | ${escapeMarkdownCell(String(candidate.name ?? ''))} | ${escapeMarkdownCell(roles)} | ${Number(candidate.rankScore ?? candidate.evidenceCount ?? 0)} | ${Number(candidate.evidenceCount ?? 0)} |`);
			}
			lines.push('', `Raw evidence: [${escapeMarkdownCell(source.fileName)}](<${encodeURI(source.fileName)}>)`, '');
		}

		lines.push('## Source Summary', '');
		lines.push('| File | Type | Size | Highlights |');
		lines.push('|------|------|-----:|------------|');
		for (const source of report.sources.map(item => this.summarizeSource(item))) {
			const link = `[${escapeMarkdownCell(source.fileName)}](<${encodeURI(source.fileName)}>)`;
			const highlights = source.highlights.length > 0
				? source.highlights.slice(0, 3).map(escapeMarkdownCell).join('<br>')
				: 'No scalar summary fields; inspect attachment.';
			lines.push(`| ${link} | ${escapeMarkdownCell(source.type)} | ${source.bytes} B | ${highlights} |`);
		}
		lines.push('');
		return lines.join('\n');
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
			lines.push('Evidence level: signal. Repeated observations across analyzers do not establish independent corroboration.');
			lines.push('');
			lines.push('| Kind | Value | Sources | Offsets |');
			lines.push('|------|-------|---------|---------|');
			for (const f of report.crossModuleFindings) {
				const offsetsStr = f.offsets.length === 0
					? '—'
					: f.offsets.slice(0, 5).map(o => `0x${o.toString(16)}`).join(', ')
						+ (f.offsets.length > 5 ? ` (+${f.offsets.length - 5} more)` : '');
				// Markdown-escape every untrusted cell (`|` splits the cell and a
				// newline breaks the row).
				const safeValue = escapeMarkdownCell(f.value);
				const safeSources = f.sources.map(escapeMarkdownCell).join(', ');
				lines.push(`| ${escapeMarkdownCell(f.kind)} | \`${safeValue}\` | ${f.sources.length} (${safeSources}) | ${offsetsStr} |`);
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
			lines.push(`| ${i + 1} | ${escapeMarkdownCell(source.fileName)} | ${escapeMarkdownCell(source.type)} |`);
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

/*---------------------------------------------------------------------------------------------
 *  HexCore YARA Engine v2.1
 *  Real YARA rule parser + DefenderYara integration
 *  Supports hex patterns, string patterns, and weighted conditions
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';

// ── Interfaces ──────────────────────────────────────────────────────────────

export interface RuleMatch {
	ruleName: string;
	namespace: string;
	meta: Record<string, string>;
	strings: Array<{ identifier: string; offset: number; data: string }>;
	severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
	score: number;  // 0-100 threat score
}

export interface YaraRule {
	name: string;
	meta: Record<string, string>;
	strings: YaraString[];
	condition: string;
	source: string;
	category: string;       // Trojan, Backdoor, etc.
	platform: string;       // Win32, Win64, Linux, etc.
	family: string;         // Bladabindi, Emotet, etc.
}

export interface YaraString {
	identifier: string;       // $a_81_0
	type: 'text' | 'hex' | 'regex';
	value: string;            // raw value
	bytes?: Buffer;           // compiled hex bytes
	modifiers: string[];      // nocase, wide, ascii, base64
	weight: number;           // from condition scoring
	comment?: string;         // inline comment (DefenderYara has these)
}

export interface ScanResult {
	file: string;
	matches: RuleMatch[];
	threatScore: number;      // aggregate 0-100
	scanTime: number;         // ms
	fileSize: number;
	categories: Record<string, number>; // category -> match count
}

export interface RuleCatalogEntry {
	filePath: string;
	category: string;
	platform: string;
	family: string;
	ruleName: string;
	loaded: boolean;
}

// ── Severity mapping by category ────────────────────────────────────────────

const CATEGORY_SEVERITY: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
	'Trojan': 'critical',
	'TrojanDownloader': 'critical',
	'TrojanDropper': 'critical',
	'TrojanSpy': 'critical',
	'Ransom': 'critical',
	'Backdoor': 'critical',
	'Exploit': 'high',
	'PWS': 'high',            // Password stealer
	'RemoteAccess': 'high',
	'Worm': 'high',
	'Virus': 'high',
	'DDoS': 'high',
	'DoS': 'high',
	'HackTool': 'medium',
	'VirTool': 'medium',
	'Spyware': 'medium',
	'TrojanClicker': 'medium',
	'TrojanProxy': 'medium',
	'Adware': 'low',
	'PUA': 'low',
	'PUAMiner': 'low',
	'BrowserModifier': 'low',
	'SoftwareBundler': 'low',
	'Spammer': 'low',
	'Misleading': 'info',
	'Joke': 'info',
	'Tool': 'info',
	'MonitoringTool': 'info',
	'Program': 'info',
};

const SEVERITY_SCORE: Record<string, number> = {
	'critical': 95,
	'high': 75,
	'medium': 50,
	'low': 25,
	'info': 10,
};

// ── Built-in rules ──────────────────────────────────────────────────────────

const BUILTIN_RULES: YaraRule[] = [
	{
		name: 'UPX_Packed', meta: { description: 'Detects UPX packed files', author: 'HexCore' },
		strings: [
			{ identifier: '$upx0', type: 'text', value: 'UPX0', modifiers: [], weight: 1 },
			{ identifier: '$upx1', type: 'text', value: 'UPX1', modifiers: [], weight: 1 },
			{ identifier: '$upx2', type: 'text', value: 'UPX!', modifiers: [], weight: 1 },
		],
		condition: 'any of them', source: 'builtin', category: 'Packer', platform: 'Any', family: 'UPX'
	},
	{
		name: 'VMProtect', meta: { description: 'Detects VMProtect packed files' },
		strings: [
			{ identifier: '$vmp0', type: 'text', value: '.vmp0', modifiers: [], weight: 1 },
			{ identifier: '$vmp1', type: 'text', value: '.vmp1', modifiers: [], weight: 1 },
		],
		condition: 'any of them', source: 'builtin', category: 'Packer', platform: 'Any', family: 'VMProtect'
	},
	{
		name: 'Themida', meta: { description: 'Detects Themida packed files' },
		strings: [
			{ identifier: '$themida', type: 'text', value: '.themida', modifiers: [], weight: 1 },
		],
		condition: 'any of them', source: 'builtin', category: 'Packer', platform: 'Any', family: 'Themida'
	},
	{
		name: 'Suspicious_API', meta: { description: 'Detects suspicious API calls', severity: 'high' },
		strings: [
			{ identifier: '$api1', type: 'text', value: 'VirtualAlloc', modifiers: [], weight: 1 },
			{ identifier: '$api2', type: 'text', value: 'WriteProcessMemory', modifiers: [], weight: 1 },
			{ identifier: '$api3', type: 'text', value: 'CreateRemoteThread', modifiers: [], weight: 1 },
			{ identifier: '$api4', type: 'text', value: 'InternetOpen', modifiers: [], weight: 1 },
			{ identifier: '$api5', type: 'text', value: 'URLDownloadToFile', modifiers: [], weight: 1 },
		],
		condition: 'any of them', source: 'builtin', category: 'Behavior', platform: 'Win32', family: 'SuspiciousAPI'
	},
	{
		name: 'Base64_Executable', meta: { description: 'Detects base64 encoded executables' },
		strings: [
			{ identifier: '$mz_b64', type: 'text', value: 'TVqQAAMAAAAEAAAA', modifiers: [], weight: 1 },
		],
		condition: 'any of them', source: 'builtin', category: 'Behavior', platform: 'Any', family: 'Base64PE'
	},
	{
		name: 'Shellcode_Pattern', meta: { description: 'Detects common shellcode patterns', severity: 'critical' },
		strings: [
			{ identifier: '$sc1', type: 'hex', value: '31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 99 b0 0b cd 80', modifiers: [], weight: 1 },
			{ identifier: '$sc2', type: 'hex', value: '31 c0 50 68 63 61 6c 63 54 5b 50 53 b8', modifiers: [], weight: 1 },
		],
		condition: 'any of them', source: 'builtin', category: 'Behavior', platform: 'Any', family: 'Shellcode'
	},
	{
		name: 'PE_Reverse_Shell', meta: { description: 'Potential reverse shell indicator', severity: 'critical' },
		strings: [
			{ identifier: '$cmd1', type: 'text', value: 'cmd.exe /c', modifiers: [], weight: 1 },
			{ identifier: '$cmd2', type: 'text', value: 'powershell -e', modifiers: [], weight: 1 },
			{ identifier: '$cmd3', type: 'text', value: 'bash -i >& /dev/tcp/', modifiers: [], weight: 1 },
		],
		condition: 'any of them', source: 'builtin', category: 'Behavior', platform: 'Any', family: 'ReverseShell'
	},
];

// ── YARA Rule Parser ────────────────────────────────────────────────────────

export function parseYaraFile(content: string, filePath: string): YaraRule[] {
	const rules: YaraRule[] = [];
	// Extract category/platform/family from path: .../Category/Platform/Family/Rule.yar
	const parts = filePath.replace(/\\/g, '/').split('/');
	const fileName = parts[parts.length - 1] || '';
	let category = 'Unknown';
	let platform = 'Unknown';
	let family = 'Unknown';

	// DefenderYara format: DefenderYara-main/Trojan/Win32/Emotet/Trojan_Win32_Emotet_A.yar
	for (let i = parts.length - 1; i >= 0; i--) {
		if (parts[i] === 'DefenderYara-main' || parts[i] === 'rules') {
			if (i + 1 < parts.length) { category = parts[i + 1]; }
			if (i + 2 < parts.length) { platform = parts[i + 2]; }
			if (i + 3 < parts.length) { family = parts[i + 3]; }
			break;
		}
	}

	// Match rule blocks: rule Name { ... }
	const ruleRegex = /rule\s+(\w+)\s*\{([^]*?)^\}/gm;
	let match;

	while ((match = ruleRegex.exec(content)) !== null) {
		const ruleName = match[1];
		const ruleBody = match[2];

		const meta = parseMeta(ruleBody);
		const strings = parseStrings(ruleBody);
		const condition = parseCondition(ruleBody);

		// Apply weights from condition if it's a weighted format
		applyWeightsFromCondition(strings, condition);

		rules.push({
			name: ruleName,
			meta,
			strings,
			condition,
			source: filePath,
			category,
			platform,
			family
		});
	}

	return rules;
}

function parseMeta(ruleBody: string): Record<string, string> {
	const meta: Record<string, string> = {};
	const metaSection = ruleBody.match(/meta\s*:\s*\n([\s\S]*?)(?=\n\s*(?:strings|condition)\s*:)/);
	if (!metaSection) { return meta; }

	const lines = metaSection[1].split('\n');
	for (const line of lines) {
		const m = line.match(/(\w+)\s*=\s*"([^"]*)"/);
		if (m) {
			meta[m[1]] = m[2];
		}
	}
	return meta;
}

function parseStrings(ruleBody: string): YaraString[] {
	const strings: YaraString[] = [];
	const stringsSection = ruleBody.match(/strings\s*:\s*\n([\s\S]*?)(?=\n\s*condition\s*:)/);
	if (!stringsSection) { return strings; }

	const lines = stringsSection[1].split('\n');
	for (const line of lines) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith('//')) { continue; }

		// Extract inline comment
		const commentMatch = trimmed.match(/\/\/(.*)$/);
		const comment = commentMatch ? commentMatch[1].trim() : undefined;

		// Hex pattern: $id = { XX XX XX }
		const hexMatch = trimmed.match(/(\$\w+)\s*=\s*\{([^}]+)\}/);
		if (hexMatch) {
			const hexStr = hexMatch[2].trim();
			const cleanHex = hexStr.replace(/\s+/g, '');
			let bytes: Buffer | undefined;
			try {
				// Only compile if no wildcards (??)
				if (!cleanHex.includes('?')) {
					bytes = Buffer.from(cleanHex, 'hex');
				}
			} catch { /* wildcard or invalid hex */ }

			strings.push({
				identifier: hexMatch[1],
				type: 'hex',
				value: hexStr,
				bytes,
				modifiers: [],
				weight: 1,
				comment
			});
			continue;
		}

		// Text pattern: $id = "text" [modifiers]
		const textMatch = trimmed.match(/(\$\w+)\s*=\s*"([^"]*)"(.*?)(?:\/\/|$)/);
		if (textMatch) {
			const modifiers: string[] = [];
			const modStr = textMatch[3].trim();
			if (modStr.includes('nocase')) { modifiers.push('nocase'); }
			if (modStr.includes('wide')) { modifiers.push('wide'); }
			if (modStr.includes('ascii')) { modifiers.push('ascii'); }
			if (modStr.includes('base64')) { modifiers.push('base64'); }

			strings.push({
				identifier: textMatch[1],
				type: 'text',
				value: textMatch[2],
				modifiers,
				weight: 1,
				comment
			});
			continue;
		}

		// Regex pattern: $id = /regex/
		const regexMatch = trimmed.match(/(\$\w+)\s*=\s*\/(.+?)\//);
		if (regexMatch) {
			strings.push({
				identifier: regexMatch[1],
				type: 'regex',
				value: regexMatch[2],
				modifiers: [],
				weight: 1,
				comment
			});
		}
	}

	return strings;
}

function parseCondition(ruleBody: string): string {
	const condMatch = ruleBody.match(/condition\s*:\s*\n?\s*([\s\S]*?)$/);
	return condMatch ? condMatch[1].trim() : 'any of them';
}

function applyWeightsFromCondition(strings: YaraString[], condition: string): void {
	// DefenderYara uses weighted conditions like:
	// ((#a_81_0 & 1)*3 + (#a_81_1 & 1)*3 + ...) >= 21
	const weightRegex = /\(#(\w+)\s*&\s*1\)\s*\*\s*(\d+)/g;
	let wMatch;
	while ((wMatch = weightRegex.exec(condition)) !== null) {
		const id = '$' + wMatch[1];
		const weight = parseInt(wMatch[2], 10);
		const str = strings.find(s => s.identifier === id);
		if (str) {
			str.weight = weight;
		}
	}
}

// ── Hex Pattern Matcher (supports wildcards) ────────────────────────────────

function matchHexPattern(content: Buffer, hexPattern: string): number[] {
	const offsets: number[] = [];
	const cleanPattern = hexPattern.replace(/\s+/g, '');

	// Split into byte pairs
	const bytePatterns: Array<{ value: number; mask: boolean }> = [];
	for (let i = 0; i < cleanPattern.length; i += 2) {
		const pair = cleanPattern.substring(i, i + 2);
		if (pair === '??' || pair.includes('?')) {
			bytePatterns.push({ value: 0, mask: true }); // wildcard
		} else {
			bytePatterns.push({ value: parseInt(pair, 16), mask: false });
		}
	}

	if (bytePatterns.length === 0) { return offsets; }

	// Sliding window search
	const patLen = bytePatterns.length;
	for (let i = 0; i <= content.length - patLen; i++) {
		let matched = true;
		for (let j = 0; j < patLen; j++) {
			if (!bytePatterns[j].mask && content[i + j] !== bytePatterns[j].value) {
				matched = false;
				break;
			}
		}
		if (matched) {
			offsets.push(i);
			if (offsets.length >= 100) { break; } // cap at 100 matches per pattern
		}
	}

	return offsets;
}

function matchTextPattern(content: Buffer, text: string, modifiers: string[]): number[] {
	const offsets: number[] = [];
	const nocase = modifiers.includes('nocase');

	// ASCII search
	const searchBuf = Buffer.from(text);
	const contentStr = nocase ? content.toString('binary').toLowerCase() : content.toString('binary');
	const searchStr = nocase ? text.toLowerCase() : text;

	let pos = 0;
	while (pos < contentStr.length) {
		const idx = contentStr.indexOf(searchStr, pos);
		if (idx === -1) { break; }
		offsets.push(idx);
		pos = idx + 1;
		if (offsets.length >= 100) { break; }
	}

	// Wide string search (UTF-16LE)
	if (modifiers.includes('wide') || modifiers.length === 0) {
		const wideBytes: number[] = [];
		for (let i = 0; i < text.length; i++) {
			wideBytes.push(text.charCodeAt(i), 0);
		}
		const wideBuf = Buffer.from(wideBytes);
		let wPos = 0;
		while (wPos <= content.length - wideBuf.length) {
			const wIdx = content.indexOf(wideBuf, wPos);
			if (wIdx === -1) { break; }
			if (!offsets.includes(wIdx)) {
				offsets.push(wIdx);
			}
			wPos = wIdx + 1;
			if (offsets.length >= 100) { break; }
		}
	}

	return offsets;
}

// ── Main Engine ─────────────────────────────────────────────────────────────

export class YaraEngine {
	private builtinRules: YaraRule[] = [];
	private loadedRules: YaraRule[] = [];
	private catalog: RuleCatalogEntry[] = [];
	private defenderYaraPath: string = '';
	private indexedCatalogPath: string = '';
	private _onProgress: ((msg: string) => void) | undefined;

	constructor() {
		this.builtinRules = [...BUILTIN_RULES];
	}

	setProgressCallback(cb: (msg: string) => void): void {
		this._onProgress = cb;
	}

	private log(msg: string): void {
		this._onProgress?.(msg);
	}

	// ── Rule Loading ──────────────────────────────────────────────────────

	getAllRules(): YaraRule[] {
		return [...this.builtinRules, ...this.loadedRules];
	}

	getCatalog(): RuleCatalogEntry[] {
		return this.catalog;
	}

	getCatalogStats(): { total: number; loaded: number; categories: Record<string, number> } {
		const categories: Record<string, number> = {};
		for (const entry of this.catalog) {
			categories[entry.category] = (categories[entry.category] || 0) + 1;
		}
		return {
			total: this.catalog.length,
			loaded: this.catalog.filter(e => e.loaded).length,
			categories
		};
	}

	loadRuleString(namespace: string, source: string): number {
		const rules = parseYaraFile(source, namespace);
		this.loadedRules.push(...rules);
		return rules.length;
	}

	loadRulesFromDirectory(dirPath: string): number {
		if (!fs.existsSync(dirPath)) { return 0; }
		let count = 0;
		const files = fs.readdirSync(dirPath);
		for (const file of files) {
			if (file.endsWith('.yar') || file.endsWith('.yara')) {
				try {
					const content = fs.readFileSync(path.join(dirPath, file), 'utf-8');
					count += this.loadRuleString(path.join(dirPath, file), content);
				} catch { /* skip unreadable */ }
			}
		}
		return count;
	}

	// ── DefenderYara Integration ──────────────────────────────────────────

	/**
	 * Index DefenderYara directory — builds a catalog without loading all rules into memory.
	 * With 76k+ rules, we only load on-demand per category or platform.
	 */
	indexDefenderYara(basePath: string, forceReindex: boolean = false): number {
		const normalizedBasePath = this.normalizeCatalogPath(basePath);
		this.defenderYaraPath = basePath;

		if (!forceReindex && this.catalog.length > 0 && this.indexedCatalogPath === normalizedBasePath) {
			this.log(`DefenderYara catalog already indexed (${this.catalog.length} rules), skipping reindex`);
			return this.catalog.length;
		}

		if (!fs.existsSync(basePath)) {
			this.log(`DefenderYara not found at: ${basePath}`);
			return 0;
		}

		this.catalog = [];
		this.indexedCatalogPath = normalizedBasePath;
		this.log('Indexing DefenderYara rules...');
		const categories = fs.readdirSync(basePath, { withFileTypes: true })
			.filter(d => d.isDirectory() && !d.name.startsWith('#') && !d.name.startsWith('.'));

		let categoryIndex = 0;
		for (const cat of categories) {
			categoryIndex++;
			this.log(`Indexing category ${categoryIndex}/${categories.length}: ${cat.name}`);
			const catPath = path.join(basePath, cat.name);
			this.indexCategory(catPath, cat.name);
		}

		this.log(`Indexed ${this.catalog.length} rules across ${categories.length} categories`);
		return this.catalog.length;
	}

	private normalizeCatalogPath(basePath: string): string {
		const resolved = path.resolve(basePath);
		return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
	}

	private indexCategory(catPath: string, category: string): void {
		const platforms = fs.readdirSync(catPath, { withFileTypes: true })
			.filter(d => d.isDirectory());

		for (const plat of platforms) {
			const platPath = path.join(catPath, plat.name);
			const families = fs.readdirSync(platPath, { withFileTypes: true })
				.filter(d => d.isDirectory());

			for (const fam of families) {
				const famPath = path.join(platPath, fam.name);
				try {
					const files = fs.readdirSync(famPath)
						.filter(f => f.endsWith('.yar') || f.endsWith('.yara'));

					for (const file of files) {
						this.catalog.push({
							filePath: path.join(famPath, file),
							category,
							platform: plat.name,
							family: fam.name,
							ruleName: file.replace(/\.(yar|yara)$/, ''),
							loaded: false
						});
					}
				} catch { /* permission errors */ }
			}
		}
	}

	/**
	 * Load rules for specific categories (on-demand).
	 * Returns number of rules loaded.
	 */
	loadDefenderCategory(category: string): number {
		const entries = this.catalog.filter(e => e.category === category && !e.loaded);
		let count = 0;
		let processed = 0;

		this.log(`Loading ${entries.length} rules from category: ${category}`);

		for (const entry of entries) {
			processed++;
			try {
				const content = fs.readFileSync(entry.filePath, 'utf-8');
				const rules = parseYaraFile(content, entry.filePath);
				this.loadedRules.push(...rules);
				entry.loaded = true;
				count += rules.length;
			} catch { /* skip */ }

			if (processed % 500 === 0) {
				this.log(`Loaded ${processed}/${entries.length} files from ${category}...`);
			}
		}

		this.log(`Loaded ${count} rules from ${category}`);
		return count;
	}

	/**
	 * Load rules for specific platform (Win32, Win64, Linux).
	 */
	loadDefenderPlatform(platform: string): number {
		const entries = this.catalog.filter(e => e.platform === platform && !e.loaded);
		let count = 0;

		for (const entry of entries) {
			try {
				const content = fs.readFileSync(entry.filePath, 'utf-8');
				const rules = parseYaraFile(content, entry.filePath);
				this.loadedRules.push(...rules);
				entry.loaded = true;
				count += rules.length;
			} catch { /* skip */ }
		}

		return count;
	}

	/**
	 * Smart load — loads the most relevant categories for a PE binary scan.
	 * Prioritizes: Trojan, Backdoor, Ransom, Exploit, PWS (Password Stealer).
	 */
	loadDefenderEssentials(): number {
		const essentialCategories = [
			'Trojan', 'Backdoor', 'Ransom', 'Exploit', 'PWS',
			'TrojanDownloader', 'TrojanDropper', 'TrojanSpy',
			'Worm', 'Virus', 'HackTool'
		];

		let total = 0;
		for (const cat of essentialCategories) {
			const count = this.loadDefenderCategory(cat);
			total += count;
			if (total > 5000) {
				this.log(`Loaded ${total} essential rules (capped for performance)`);
				break;
			}
		}
		return total;
	}

	// ── Scanning ────────────────────────────────────────────────────────

	async scanFile(filePath: string): Promise<RuleMatch[]> {
		const startTime = Date.now();
		let content: Buffer;

		try {
			const stat = fs.statSync(filePath);
			// Cap at 50MB for performance
			if (stat.size > 50 * 1024 * 1024) {
				this.log(`File too large (${(stat.size / 1024 / 1024).toFixed(1)}MB), scanning first 50MB`);
				const fd = fs.openSync(filePath, 'r');
				content = Buffer.alloc(50 * 1024 * 1024);
				fs.readSync(fd, content, 0, content.length, 0);
				fs.closeSync(fd);
			} else {
				content = fs.readFileSync(filePath);
			}
		} catch (err) {
			this.log(`Cannot read file: ${filePath}`);
			return [];
		}

		const allRules = this.getAllRules();
		const matches: RuleMatch[] = [];

		this.log(`Scanning ${path.basename(filePath)} (${(content.length / 1024).toFixed(1)}KB) against ${allRules.length} rules...`);

		for (const rule of allRules) {
			const ruleMatch = this.evaluateRule(rule, content);
			if (ruleMatch) {
				matches.push(ruleMatch);
			}
		}

		const elapsed = Date.now() - startTime;
		this.log(`Scan complete: ${matches.length} matches in ${elapsed}ms`);

		return matches;
	}

	async scanFileWithResult(filePath: string): Promise<ScanResult> {
		const startTime = Date.now();
		const matches = await this.scanFile(filePath);

		const categories: Record<string, number> = {};
		let maxScore = 0;

		for (const m of matches) {
			categories[m.namespace] = (categories[m.namespace] || 0) + 1;
			if (m.score > maxScore) { maxScore = m.score; }
		}

		let stat: fs.Stats | null = null;
		try { stat = fs.statSync(filePath); } catch { /* */ }

		return {
			file: filePath,
			matches,
			threatScore: Math.min(100, maxScore + (matches.length > 5 ? 10 : 0)),
			scanTime: Date.now() - startTime,
			fileSize: stat?.size || 0,
			categories
		};
	}

	async scanDirectory(dirPath: string): Promise<Array<{ file: string; matches: RuleMatch[] }>> {
		const results: Array<{ file: string; matches: RuleMatch[] }> = [];

		const scanDir = async (dir: string) => {
			let entries: fs.Dirent[];
			try {
				entries = fs.readdirSync(dir, { withFileTypes: true });
			} catch { return; }

			for (const entry of entries) {
				const fullPath = path.join(dir, entry.name);
				if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
					await scanDir(fullPath);
				} else if (entry.isFile()) {
					const matches = await this.scanFile(fullPath);
					if (matches.length > 0) {
						results.push({ file: fullPath, matches });
					}
				}
			}
		};

		await scanDir(dirPath);
		return results;
	}

	// ── Rule Evaluation ─────────────────────────────────────────────────

	private evaluateRule(rule: YaraRule, content: Buffer): RuleMatch | null {
		const matchedStrings: Array<{ identifier: string; offset: number; data: string }> = [];
		const stringMatchCounts: Record<string, number> = {};

		for (const str of rule.strings) {
			let offsets: number[] = [];

			if (str.type === 'hex') {
				if (str.bytes) {
					// Pre-compiled (no wildcards) — fast path
					let pos = 0;
					while (pos <= content.length - str.bytes.length) {
						const idx = content.indexOf(str.bytes, pos);
						if (idx === -1) { break; }
						offsets.push(idx);
						pos = idx + 1;
						if (offsets.length >= 100) { break; }
					}
				} else {
					// Wildcard hex pattern — slow path
					offsets = matchHexPattern(content, str.value);
				}
			} else if (str.type === 'text') {
				offsets = matchTextPattern(content, str.value, str.modifiers);
			} else if (str.type === 'regex') {
				try {
					const re = new RegExp(str.value, 'g');
					const text = content.toString('binary');
					let reMatch;
					while ((reMatch = re.exec(text)) !== null && offsets.length < 100) {
						offsets.push(reMatch.index);
					}
				} catch { /* invalid regex */ }
			}

			if (offsets.length > 0) {
				stringMatchCounts[str.identifier] = offsets.length;
				// Keep first 10 match positions per string
				for (const offset of offsets.slice(0, 10)) {
					const dataSnippet = content.slice(offset, offset + Math.min(50, content.length - offset));
					matchedStrings.push({
						identifier: str.identifier,
						offset,
						data: str.comment || str.value.substring(0, 50)
					});
				}
			}
		}

		// Evaluate condition
		const conditionMet = this.evaluateCondition(rule, stringMatchCounts);
		if (!conditionMet || matchedStrings.length === 0) {
			return null;
		}

		const severity = (rule.meta.severity as any) || CATEGORY_SEVERITY[rule.category] || 'medium';
		const score = SEVERITY_SCORE[severity] || 50;

		return {
			ruleName: rule.name,
			namespace: rule.category,
			meta: {
				...rule.meta,
				platform: rule.platform,
				family: rule.family,
				severity
			},
			strings: matchedStrings,
			severity,
			score
		};
	}

	private evaluateCondition(rule: YaraRule, matchCounts: Record<string, number>): boolean {
		const cond = rule.condition.trim();

		// "any of them" — at least one string matched
		if (cond === 'any of them') {
			return Object.keys(matchCounts).length > 0;
		}

		// "all of them" — all strings matched
		if (cond === 'all of them') {
			return Object.keys(matchCounts).length === rule.strings.length;
		}

		// "N of them" — at least N strings matched
		const nOfThem = cond.match(/^(\d+)\s+of\s+them$/);
		if (nOfThem) {
			return Object.keys(matchCounts).length >= parseInt(nOfThem[1], 10);
		}

		// DefenderYara weighted condition: ((#a_81_0 & 1)*3 + ...) >= threshold
		const weightedMatch = cond.match(/>=\s*(\d+)\s*$/);
		if (weightedMatch && cond.includes('#')) {
			const threshold = parseInt(weightedMatch[1], 10);
			let totalScore = 0;
			for (const str of rule.strings) {
				const id = str.identifier.replace('$', '');
				const count = matchCounts[str.identifier] || 0;
				if (count > 0) {
					totalScore += str.weight;
				}
			}
			return totalScore >= threshold;
		}

		// Fallback: any match
		return Object.keys(matchCounts).length > 0;
	}

	// ── Rule Management ─────────────────────────────────────────────────

	async updateRules(): Promise<void> {
		this.loadedRules = [];
		// Reset catalog loaded flags
		for (const entry of this.catalog) {
			entry.loaded = false;
		}

		// Re-index if DefenderYara path is set
		if (this.defenderYaraPath) {
			this.indexDefenderYara(this.defenderYaraPath, true);
		}
	}

	clearResults(): void {
		this.loadedRules = [];
		for (const entry of this.catalog) {
			entry.loaded = false;
		}
	}

	createRuleFromString(name: string, content: string): string {
		const hexBytes = Buffer.from(content).toString('hex').match(/.{1,2}/g)?.join(' ') || '';

		return `rule ${name} {
    meta:
        description = "Auto-generated rule"
        author = "HexCore"
        date = "${new Date().toISOString().split('T')[0]}"
    strings:
        $s1 = "${content.replace(/"/g, '\\"')}"
        $h1 = { ${hexBytes} }
    condition:
        any of them
}`;
	}
}

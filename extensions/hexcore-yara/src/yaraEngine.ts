/*---------------------------------------------------------------------------------------------
 *  HexCore YARA Engine v2.1
 *  Real YARA rule parser + DefenderYara integration
 *  Supports hex patterns, string patterns, and weighted conditions
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import { RE2 } from 're2-wasm';

// ── Interfaces ──────────────────────────────────────────────────────────────

export interface RuleMatch {
	ruleName: string;
	namespace: string;
	meta: Record<string, string>;
	strings: Array<{
		identifier: string;
		offset: number;
		data: string;
		section?: string;
		executable?: boolean;
		virtualAddress?: string;
	}>;
	severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
	score: number;  // 0-100 threat score
	/**
	 * Set when the target is a .NET/managed assembly and this match comes from a
	 * native byte-pattern (non-.NET-aware) rule. Such matches land in managed
	 * metadata / IL / string-heap bytes, NOT native code, so they are reclassified
	 * as advisory: still reported (nothing is hidden) but excluded from the
	 * headline threat score. See GAP #3 / .NET false-positive fix.
	 */
	advisoryOnly?: boolean;
	advisoryReason?: string;
}

export interface BinaryScanSection {
	name: string;
	fileOffset: number;
	size: number;
	virtualAddress: bigint;
	executable: boolean;
}

export interface BinaryScanContext {
	format: 'pe' | 'elf' | 'unknown';
	architecture?: string;
	sections: BinaryScanSection[];
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
	binaryContext?: {
		format: 'pe' | 'elf' | 'unknown';
		architecture?: string;
		executableSectionCount: number;
	};
	heuristicAdvisory?: {
		suppressedRuleMatches: number;
		retainedRuleMatches: number;
		note: string;
	};
	/** Number of YARA rules loaded in the engine at scan time. Used to
	 * diagnose zero-match results (0 rules = packaging issue). */
	activeRules?: number;
	/** Which rule directories the engine tried, and which succeeded. */
	ruleLoadDiagnostics?: { triedPaths: string[]; loadedFrom: string | null };
	/**
	 * True when the scanned file is a .NET / managed assembly (CLR runtime header
	 * present). Native byte-pattern YARA rules are unreliable on managed code, so
	 * the headline `threatScore` is derived from .NET-aware rules only when this
	 * is set. See `dotNetAdvisory` for what was reclassified.
	 */
	isDotNet?: boolean;
	/**
	 * Present only for .NET targets. Records how many matched rules were
	 * reclassified as advisory (native byte-pattern rules matching managed
	 * metadata = false positives) vs retained (.NET-aware rules that still count
	 * toward the threat score). Makes the suppression transparent rather than
	 * silently dropping matches. See GAP #3 / .NET false-positive fix.
	 */
	dotNetAdvisory?: {
		suppressedRuleMatches: number;
		retainedRuleMatches: number;
		note: string;
	};
	/**
	 * Result of an on-demand DefenderYara category load triggered by the scan
	 * `categories` / `loadEssentials` options. Present only when such a load
	 * was requested. `unavailable` lists categories the catalog did not have
	 * (or all of them, when no catalog is indexed), so callers can tell apart
	 * "no DefenderYara present" from "scanned and clean".
	 */
	categoryLoad?: {
		requested: string[];
		loaded: string[];
		unavailable: string[];
		rulesLoaded: number;
		catalogIndexed: number;
	};
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
		name: 'Suspicious_API', meta: { description: 'Multiple generic APIs associated with suspicious behavior', severity: 'medium' },
		strings: [
			{ identifier: '$api1', type: 'text', value: 'VirtualAlloc', modifiers: [], weight: 1 },
			{ identifier: '$api2', type: 'text', value: 'WriteProcessMemory', modifiers: [], weight: 1 },
			{ identifier: '$api3', type: 'text', value: 'CreateRemoteThread', modifiers: [], weight: 1 },
			{ identifier: '$api4', type: 'text', value: 'InternetOpen', modifiers: [], weight: 1 },
			{ identifier: '$api5', type: 'text', value: 'URLDownloadToFile', modifiers: [], weight: 1 },
		],
		condition: '2 of them', source: 'builtin', category: 'Behavior', platform: 'Win32', family: 'SuspiciousAPI'
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
				// Fast-path compile only when the pattern contains NO wildcards of
				// any kind (full `??` or nibble-level `?A`/`A?`) AND no hex jumps
				// `[n-m]`. Any of those force the slow path via matchHexPattern
				// so nibble wildcards are evaluated with correct semantics (bug
				// fix v3.8.0: previously `3?` collapsed to `??`).
				if (!cleanHex.includes('?') && !hexStr.includes('[')) {
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

/**
 * Compile a YARA hex string into a per-byte match table.
 *
 * ref: https://yara.readthedocs.io/en/stable/writingrules.html#hexadecimal-strings
 *
 * YARA hex strings support three forms of nibble-level wildcards AND hex jumps:
 *   - `??`  — any byte (both nibbles unknown)
 *   - `A?`  — high nibble fixed, low nibble any  (matches 0xA0–0xAF)
 *   - `?A`  — high nibble any, low nibble fixed  (matches 0x0A, 0x1A, ... 0xFA)
 *   - `[n-m]` / `[n]` / `[n-]` — jump (variable gap) of n..m arbitrary bytes
 *
 * The previous implementation collapsed every `?`-containing pair into a full
 * byte wildcard, which silently broadens bundled rules (api-hashing.yar uses
 * `66 81 3? 4D 5A` — the `3?` was effectively `??` and produced false
 * positives on any 6-byte sequence ending with "MZ" preceded by the right
 * opcode pair).  The fix implements a mask/value pair per byte and linear
 * jump support with bounded backtracking.
 */
interface HexPatternToken {
	/** 'byte' = fixed byte or nibble wildcard. 'jump' = [n-m] skip of m..M bytes. */
	kind: 'byte' | 'jump';
	/** For 'byte': required bits after masking. */
	value: number;
	/** For 'byte': 1 bits = "must match", 0 bits = wildcard nibble. */
	mask: number;
	/** For 'jump': minimum bytes to skip (inclusive). */
	jumpMin: number;
	/** For 'jump': maximum bytes to skip (inclusive). Infinity allowed for `[n-]`. */
	jumpMax: number;
}

function parseHexToken(pair: string): HexPatternToken | null {
	if (pair.length !== 2) { return null; }
	const hi = pair[0];
	const lo = pair[1];
	const hiIsWild = hi === '?';
	const loIsWild = lo === '?';
	if (hiIsWild && loIsWild) {
		return { kind: 'byte', value: 0, mask: 0x00, jumpMin: 0, jumpMax: 0 };
	}
	if (hiIsWild) {
		const loVal = parseInt(lo, 16);
		if (Number.isNaN(loVal)) { return null; }
		// Low nibble fixed; high nibble any. mask = 0x0F, value = low nibble.
		return { kind: 'byte', value: loVal & 0x0F, mask: 0x0F, jumpMin: 0, jumpMax: 0 };
	}
	if (loIsWild) {
		const hiVal = parseInt(hi, 16);
		if (Number.isNaN(hiVal)) { return null; }
		// High nibble fixed; low nibble any. mask = 0xF0, value = high nibble shifted.
		return { kind: 'byte', value: (hiVal & 0x0F) << 4, mask: 0xF0, jumpMin: 0, jumpMax: 0 };
	}
	const v = parseInt(pair, 16);
	if (Number.isNaN(v)) { return null; }
	return { kind: 'byte', value: v, mask: 0xFF, jumpMin: 0, jumpMax: 0 };
}

function compileHexPattern(hexPattern: string): HexPatternToken[] {
	// Strip comments /* ... */ and whitespace but preserve brackets.
	const noComments = hexPattern.replace(/\/\*[\s\S]*?\*\//g, '');
	const stripped = noComments.replace(/\s+/g, '');
	const tokens: HexPatternToken[] = [];
	let i = 0;
	while (i < stripped.length) {
		const ch = stripped[i];
		// Hex jump `[n-m]`, `[n]`, or `[n-]`
		if (ch === '[') {
			const close = stripped.indexOf(']', i);
			if (close === -1) { return []; } // malformed — reject entire pattern
			const body = stripped.substring(i + 1, close);
			// Accept N | N-M | N-
			const jumpMatch = body.match(/^(\d+)(?:-(\d*))?$/);
			if (!jumpMatch) { return []; }
			const jumpMin = parseInt(jumpMatch[1], 10);
			const jumpMax = jumpMatch[2] === undefined
				? jumpMin
				: (jumpMatch[2] === '' ? Number.POSITIVE_INFINITY : parseInt(jumpMatch[2], 10));
			if (jumpMax < jumpMin) { return []; }
			tokens.push({ kind: 'jump', value: 0, mask: 0, jumpMin, jumpMax });
			i = close + 1;
			continue;
		}
		// Byte token (2 hex digits, each optionally '?')
		if (i + 1 >= stripped.length) { return []; } // odd nibble at end
		const tok = parseHexToken(stripped.substring(i, i + 2));
		if (!tok) { return []; }
		tokens.push(tok);
		i += 2;
	}
	return tokens;
}

function matchHexPattern(content: Buffer, hexPattern: string): number[] {
	const tokens = compileHexPattern(hexPattern);
	if (tokens.length === 0) { return []; }

	// Jumps must be bounded by byte tokens on both sides — a leading or trailing
	// jump is meaningless and we reject those patterns (legacy behaviour would
	// have matched everywhere). Also reject all-jump patterns.
	if (tokens[0].kind === 'jump' || tokens[tokens.length - 1].kind === 'jump') {
		return [];
	}

	const offsets: number[] = [];

	// Fast path: if there are no jumps, a simple linear slide is optimal.
	const hasJump = tokens.some(t => t.kind === 'jump');
	if (!hasJump) {
		const patLen = tokens.length;
		for (let i = 0; i + patLen <= content.length; i++) {
			let ok = true;
			for (let j = 0; j < patLen; j++) {
				const t = tokens[j];
				if ((content[i + j] & t.mask) !== t.value) { ok = false; break; }
			}
			if (ok) {
				offsets.push(i);
				if (offsets.length >= 100) { break; }
			}
		}
		return offsets;
	}

	// Jump path: match tokens sequentially. Each jump consumes jumpMin..jumpMax
	// bytes; since jumps are sandwiched between byte tokens, we can resolve
	// greedily by searching for the next required byte within the allowed gap
	// instead of full backtracking — YARA's semantics permit any-length gap,
	// and we cap jumpMax at a conservative 4KB when infinite to avoid pathological
	// scans in large files.
	const SAFE_JUMP_CAP = 4096;
	for (let start = 0; start < content.length; start++) {
		let cur = start;
		let ok = true;
		for (let k = 0; k < tokens.length; k++) {
			const t = tokens[k];
			if (t.kind === 'byte') {
				if (cur >= content.length) { ok = false; break; }
				if ((content[cur] & t.mask) !== t.value) { ok = false; break; }
				cur += 1;
			} else {
				// Jump: advance cur by jumpMin..min(jumpMax, SAFE_JUMP_CAP), then
				// expect the following byte token to match. Locate the smallest
				// valid cur that satisfies the next byte token — this is standard
				// non-backtracking greedy match for `[n-m] <byte>` sequences.
				const max = Math.min(
					Number.isFinite(t.jumpMax) ? t.jumpMax : SAFE_JUMP_CAP,
					content.length - cur,
				);
				if (t.jumpMin > max) { ok = false; break; }
				const next = tokens[k + 1];
				// Guaranteed by the leading/trailing check above.
				if (!next || next.kind !== 'byte') { ok = false; break; }
				let found = -1;
				for (let skip = t.jumpMin; skip <= max; skip++) {
					const p = cur + skip;
					if (p >= content.length) { break; }
					if ((content[p] & next.mask) === next.value) { found = skip; break; }
				}
				if (found === -1) { ok = false; break; }
				cur += found + 1;  // consume the skip AND the next byte token
				k += 1;            // we already matched tokens[k+1]
			}
		}
		if (ok) {
			offsets.push(start);
			if (offsets.length >= 100) { break; }
		}
	}
	return offsets;
}

function matchTextPattern(content: Buffer, text: string, modifiers: string[]): number[] {
	const offsets: number[] = [];
	const nocase = modifiers.includes('nocase');
	// ref: https://yara.readthedocs.io/en/stable/writingrules.html — text
	// strings are ASCII by default. `ascii` is assumed when no encoding
	// modifier is present; `wide` must be requested explicitly OR alongside
	// `ascii` to enable dual matching. Previously we ALWAYS searched wide,
	// which caused the bundled Suspicious_API rule to match "V.i.r.t.u.a.l.
	// A.l.l.o.c" in every Windows binary (benign and malicious) and inflate
	// threat scores. v3.8.0 bug fix.
	const wantsWide = modifiers.includes('wide');
	const wantsAscii = modifiers.includes('ascii') || !wantsWide;

	// ASCII search
	if (wantsAscii) {
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
	}

	// Wide string search (UTF-16LE) — only when requested.
	if (wantsWide) {
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

/**
 * Cheap static screen for the classic catastrophic-backtracking ("ReDoS") regex
 * shape: an unbounded quantifier applied to a group that itself contains an
 * unbounded quantifier -- e.g. (a+)+, (a*)*, ([a-z]+)*. YARA rule regexes come
 * from loaded / third-party rule packs (untrusted), and a single such pattern
 * run against scanned content hangs the engine. Real YARA byte-pattern regexes
 * are never nested-unbounded, so the false-positive risk is negligible. This is
 * a heuristic retained for diagnostics. Rule execution itself uses RE2 below,
 * so safety no longer depends on this pre-screen recognizing every shape.
 */
export function isLikelyCatastrophicRegex(pattern: string): boolean {
	return /\([^()]*(?:[*+]|\{\d+,\d*\})[^()]*\)(?:[*+]|\{\d+,\d*\})/.test(pattern);
}

/** Execute an untrusted YARA regex with RE2's linear-time matcher. */
export function matchRegexOffsets(pattern: string, text: string, limit: number = 100): number[] {
	const offsets: number[] = [];
	const regex = new RE2(pattern, 'gu');
	let match = regex.exec(text);
	while (offsets.length < limit && match !== null) {
		offsets.push(match.index);
		// Global RegExp semantics do not advance after an empty match.
		if ((match[0] ?? '').length === 0) {
			regex.lastIndex++;
		}
		match = regex.exec(text);
	}
	return offsets;
}

function readUInt16(buffer: Buffer, offset: number, littleEndian: boolean): number {
	return littleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
}

function readUInt32(buffer: Buffer, offset: number, littleEndian: boolean): number {
	return littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}

function readUInt64Number(buffer: Buffer, offset: number, littleEndian: boolean): number {
	const value = littleEndian ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset);
	return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : 0;
}

function readCString(buffer: Buffer, offset: number): string {
	if (offset < 0 || offset >= buffer.length) { return ''; }
	const end = buffer.indexOf(0, offset);
	return buffer.toString('utf8', offset, end === -1 ? buffer.length : end);
}

/** Parse enough PE/ELF metadata to qualify raw YARA byte matches. */
export function inspectBinaryScanContext(content: Buffer): BinaryScanContext {
	try {
		if (content.length >= 0x40 && content.readUInt16LE(0) === 0x5a4d) {
			const peOffset = content.readUInt32LE(0x3c);
			if (peOffset + 24 <= content.length && content.readUInt32LE(peOffset) === 0x00004550) {
				const sectionCount = content.readUInt16LE(peOffset + 6);
				const optionalSize = content.readUInt16LE(peOffset + 20);
				const machine = content.readUInt16LE(peOffset + 4);
				const architecture = new Map<number, string>([
					[0x14c, 'x86'], [0x1c0, 'arm'], [0x1c4, 'armv7'], [0x8664, 'x86_64'], [0xaa64, 'aarch64'],
				]).get(machine);
				const optionalOffset = peOffset + 24;
				const optionalMagic = optionalOffset + 2 <= content.length ? content.readUInt16LE(optionalOffset) : 0;
				const imageBase = optionalMagic === 0x20b && optionalOffset + 32 <= content.length
					? content.readBigUInt64LE(optionalOffset + 24)
					: optionalMagic === 0x10b && optionalOffset + 32 <= content.length
						? BigInt(content.readUInt32LE(optionalOffset + 28)) : 0n;
				const sections: BinaryScanSection[] = [];
				const sectionTable = optionalOffset + optionalSize;
				for (let i = 0; i < sectionCount; i++) {
					const offset = sectionTable + i * 40;
					if (offset + 40 > content.length) { break; }
					const rawName = content.subarray(offset, offset + 8);
					const nul = rawName.indexOf(0);
					const name = rawName.toString('ascii', 0, nul === -1 ? 8 : nul) || `section#${i}`;
					const virtualAddress = content.readUInt32LE(offset + 12);
					const size = content.readUInt32LE(offset + 16);
					const fileOffset = content.readUInt32LE(offset + 20);
					const characteristics = content.readUInt32LE(offset + 36);
					sections.push({
						name, fileOffset, size,
						virtualAddress: imageBase + BigInt(virtualAddress),
						executable: (characteristics & 0x20000000) !== 0,
					});
				}
				return { format: 'pe', ...(architecture ? { architecture } : {}), sections };
			}
		}

		if (content.length >= 64 && content[0] === 0x7f && content[1] === 0x45 && content[2] === 0x4c && content[3] === 0x46) {
			const is64 = content[4] === 2;
			const littleEndian = content[5] !== 2;
			const machine = readUInt16(content, 18, littleEndian);
			const architecture = new Map<number, string>([
				[3, 'x86'], [8, 'mips'], [40, 'arm'], [62, 'x86_64'], [183, 'aarch64'], [243, 'riscv'],
			]).get(machine);
			const sectionTable = is64
				? readUInt64Number(content, 40, littleEndian)
				: readUInt32(content, 32, littleEndian);
			const sectionEntrySize = readUInt16(content, is64 ? 58 : 46, littleEndian);
			const sectionCount = readUInt16(content, is64 ? 60 : 48, littleEndian);
			const stringTableIndex = readUInt16(content, is64 ? 62 : 50, littleEndian);
			let stringTable = content.subarray(0, 0);
			if (stringTableIndex < sectionCount && sectionEntrySize > 0) {
				const stringHeader = sectionTable + stringTableIndex * sectionEntrySize;
				if (stringHeader + sectionEntrySize <= content.length) {
					const stringOffset = is64
						? readUInt64Number(content, stringHeader + 24, littleEndian)
						: readUInt32(content, stringHeader + 16, littleEndian);
					const stringSize = is64
						? readUInt64Number(content, stringHeader + 32, littleEndian)
						: readUInt32(content, stringHeader + 20, littleEndian);
					if (stringOffset + stringSize <= content.length) {
						stringTable = content.subarray(stringOffset, stringOffset + stringSize);
					}
				}
			}
			const sections: BinaryScanSection[] = [];
			for (let i = 0; i < sectionCount && sectionEntrySize > 0; i++) {
				const offset = sectionTable + i * sectionEntrySize;
				if (offset + sectionEntrySize > content.length) { break; }
				const nameOffset = readUInt32(content, offset, littleEndian);
				const flags = is64
					? readUInt64Number(content, offset + 8, littleEndian)
					: readUInt32(content, offset + 8, littleEndian);
				const virtualAddress = is64
					? BigInt(readUInt64Number(content, offset + 16, littleEndian))
					: BigInt(readUInt32(content, offset + 12, littleEndian));
				const fileOffset = is64
					? readUInt64Number(content, offset + 24, littleEndian)
					: readUInt32(content, offset + 16, littleEndian);
				const size = is64
					? readUInt64Number(content, offset + 32, littleEndian)
					: readUInt32(content, offset + 20, littleEndian);
				sections.push({
					name: readCString(stringTable, nameOffset) || `section#${i}`,
					fileOffset, size, virtualAddress,
					executable: (flags & 0x4) !== 0,
				});
			}
			return { format: 'elf', ...(architecture ? { architecture } : {}), sections };
		}
	} catch {
		return { format: 'unknown', sections: [] };
	}
	return { format: 'unknown', sections: [] };
}

function architectureMatches(required: string, actual: string | undefined): boolean {
	if (!actual) { return true; }
	const normalized = required.toLowerCase();
	if (normalized === 'x86') { return actual === 'x86' || actual === 'x86_64'; }
	if (normalized === 'arm') { return actual === 'arm' || actual === 'armv7' || actual === 'aarch64'; }
	return normalized === actual.toLowerCase();
}

function qualifyMatch(match: RuleMatch, context: BinaryScanContext): void {
	for (const evidence of match.strings) {
		const section = context.sections.find(candidate =>
			evidence.offset >= candidate.fileOffset && evidence.offset < candidate.fileOffset + candidate.size);
		if (section) {
			evidence.section = section.name;
			evidence.executable = section.executable;
			evidence.virtualAddress = `0x${(section.virtualAddress + BigInt(evidence.offset - section.fileOffset)).toString(16)}`;
		}
	}

	const requiredArchitecture = match.meta.architecture;
	if (requiredArchitecture && !architectureMatches(requiredArchitecture, context.architecture)) {
		match.advisoryOnly = true;
		match.advisoryReason = `Rule requires ${requiredArchitecture}; binary architecture is ${context.architecture ?? 'unknown'}.`;
		return;
	}
	if (match.meta.requires_executable === 'true' && !match.strings.some(evidence => evidence.executable === true)) {
		match.advisoryOnly = true;
		match.advisoryReason = 'Opcode rule matched only outside executable sections.';
	}
}

export interface YaraConditionEvaluation {
	supported: boolean;
	result: boolean;
	error?: string;
}

type ConditionToken = { kind: 'word' | 'identifier' | 'count' | 'number' | 'operator' | 'punctuation'; value: string };

function tokenizeCondition(condition: string): ConditionToken[] {
	const normalized = condition.replace(/\/\/.*$/gm, ' ').replace(/\s+/g, ' ').trim();
	const tokens: ConditionToken[] = [];
	const tokenPattern = /\s*(>=|<=|==|!=|>|<|\(|\)|,|#[A-Za-z0-9_]+|\$[A-Za-z0-9_*]+|\d+|[A-Za-z_][A-Za-z0-9_]*)/gy;
	let offset = 0;
	while (offset < normalized.length) {
		tokenPattern.lastIndex = offset;
		const match = tokenPattern.exec(normalized);
		if (!match || match.index !== offset) {
			throw new Error(`unsupported token near ${JSON.stringify(normalized.slice(offset, offset + 24))}`);
		}
		const value = match[1];
		const kind: ConditionToken['kind'] = value.startsWith('$') ? 'identifier'
			: value.startsWith('#') ? 'count'
				: /^\d+$/.test(value) ? 'number'
					: /^(?:>=|<=|==|!=|>|<)$/.test(value) ? 'operator'
						: /^(?:\(|\)|,)$/.test(value) ? 'punctuation' : 'word';
		tokens.push({ kind, value });
		offset = tokenPattern.lastIndex;
	}
	return tokens;
}

/**
 * Evaluate the boolean/count subset used by the bundled rules. Unknown YARA
 * syntax is rejected instead of falling back to "any matched string".
 */
export function evaluateYaraCondition(
	condition: string,
	matchCounts: Readonly<Record<string, number>>,
	allIdentifiers: readonly string[],
): YaraConditionEvaluation {
	try {
		const tokens = tokenizeCondition(condition);
		let index = 0;
		const peek = (): ConditionToken | undefined => tokens[index];
		const consume = (value?: string): ConditionToken => {
			const token = tokens[index++];
			if (!token || (value !== undefined && token.value.toLowerCase() !== value)) {
				throw new Error(`expected ${value ?? 'token'} at token ${index}`);
			}
			return token;
		};
		const isWord = (value: string): boolean => peek()?.kind === 'word' && peek()!.value.toLowerCase() === value;
		const countFor = (identifier: string): number => matchCounts[identifier] || 0;
		const expand = (patterns: readonly string[]): string[] => {
			const expanded = new Set<string>();
			for (const pattern of patterns) {
				if (pattern.endsWith('*')) {
					const prefix = pattern.slice(0, -1);
					for (const identifier of allIdentifiers) {
						if (identifier.startsWith(prefix)) { expanded.add(identifier); }
					}
				} else {
					expanded.add(pattern);
				}
			}
			return [...expanded];
		};
		const parseGroup = (): string[] => {
			if (isWord('them')) {
				consume('them');
				return [...allIdentifiers];
			}
			consume('(');
			const patterns: string[] = [];
			while (true) {
				const token = consume();
				if (token.kind !== 'identifier') { throw new Error('expected identifier in of-group'); }
				patterns.push(token.value);
				if (peek()?.value === ',') { consume(','); continue; }
				break;
			}
			consume(')');
			return expand(patterns);
		};

		let parseOr: () => boolean;
		const parsePrimary = (): boolean => {
			if (peek()?.value === '(') {
				consume('(');
				const value = parseOr();
				consume(')');
				return value;
			}
			if (peek()?.kind === 'identifier') {
				return countFor(consume().value) > 0;
			}
			if (peek()?.kind === 'count') {
				const count = countFor(`$${consume().value.slice(1)}`);
				const operator = consume();
				const expected = consume();
				if (operator.kind !== 'operator' || expected.kind !== 'number') {
					throw new Error('count expression requires a comparison and integer');
				}
				const rhs = Number(expected.value);
				switch (operator.value) {
					case '>': return count > rhs;
					case '>=': return count >= rhs;
					case '<': return count < rhs;
					case '<=': return count <= rhs;
					case '==': return count === rhs;
					case '!=': return count !== rhs;
					default: throw new Error(`unsupported comparison ${operator.value}`);
				}
			}
			if (isWord('any') || isWord('all') || peek()?.kind === 'number') {
				const quantifier = consume().value.toLowerCase();
				consume('of');
				const identifiers = parseGroup();
				const matched = identifiers.filter(identifier => countFor(identifier) > 0).length;
				if (quantifier === 'any') { return matched > 0; }
				if (quantifier === 'all') { return identifiers.length > 0 && matched === identifiers.length; }
				return matched >= Number(quantifier);
			}
			throw new Error(`unsupported primary ${peek()?.value ?? '<eof>'}`);
		};
		const parseUnary = (): boolean => {
			if (isWord('not')) { consume('not'); return !parseUnary(); }
			return parsePrimary();
		};
		const parseAnd = (): boolean => {
			let value = parseUnary();
			while (isWord('and')) {
				consume('and');
				const rhs = parseUnary();
				value = value && rhs;
			}
			return value;
		};
		parseOr = (): boolean => {
			let value = parseAnd();
			while (isWord('or')) {
				consume('or');
				const rhs = parseAnd();
				value = value || rhs;
			}
			return value;
		};

		const result = parseOr();
		if (index !== tokens.length) {
			throw new Error(`unexpected trailing token ${tokens[index].value}`);
		}
		return { supported: true, result };
	} catch (error) {
		return { supported: false, result: false, error: error instanceof Error ? error.message : String(error) };
	}
}

export class YaraEngine {
	private builtinRules: YaraRule[] = [];
	private loadedRules: YaraRule[] = [];
	private catalog: RuleCatalogEntry[] = [];
	private defenderYaraPath: string = '';
	private indexedCatalogPath: string = '';
	private _onProgress: ((msg: string) => void) | undefined;
	// v3.8.0-nightly diagnostic: records the last set of paths tried when
	// loading rules and which one succeeded. Surfaced in scan output so
	// pipelines can diagnose "activeRules: 7" without touching the Output panel.
	private _loadDiagnostics: { triedPaths: string[]; loadedFrom: string | null } = { triedPaths: [], loadedFrom: null };
	// v3.8.0-nightly: directories that loaded successfully and should be
	// repopulated after updateRules() wipes loadedRules. Without this, the
	// activate() flow (load dir → autoUpdate → updateRules() → wipe) ends
	// with 0 bundled rules and threatScore=0 on every scan.
	private _persistentRuleDirs: Set<string> = new Set();

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
		this._loadDiagnostics.triedPaths.push(dirPath);
		if (!fs.existsSync(dirPath)) { return 0; }
		let count = 0;
		// v3.8.0-nightly: recursive walk so rules/Category/Subdir/*.yar works.
		// This matches the DefenderYara convention and lets the built-in
		// rules ship under rules/AntiAnalysis/*.yar etc.
		const walk = (current: string): void => {
			let entries: fs.Dirent[];
			try {
				entries = fs.readdirSync(current, { withFileTypes: true });
			} catch {
				return;
			}
			for (const entry of entries) {
				if (entry.name.startsWith('.') || entry.name.startsWith('#')) { continue; }
				const full = path.join(current, entry.name);
				if (entry.isDirectory()) {
					walk(full);
				} else if (entry.isFile() && (entry.name.endsWith('.yar') || entry.name.endsWith('.yara'))) {
					try {
						const content = fs.readFileSync(full, 'utf-8');
						count += this.loadRuleString(full, content);
					} catch { /* skip unreadable */ }
				}
			}
		};
		walk(dirPath);
		if (count > 0) {
			this._loadDiagnostics.loadedFrom = dirPath;
			this._persistentRuleDirs.add(dirPath);
		}
		return count;
	}

	/** v3.8.0-nightly diagnostic accessor for the scan output JSON. */
	getLoadDiagnostics(): { triedPaths: string[]; loadedFrom: string | null } {
		return { triedPaths: [...this._loadDiagnostics.triedPaths], loadedFrom: this._loadDiagnostics.loadedFrom };
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

	// ── .NET / managed-code awareness (GAP #3 false-positive fix) ─────────

	/**
	 * Detect whether `buf` is a .NET / managed PE by reading the COM descriptor
	 * (CLR Runtime Header) data directory, index 14 of the optional header. A
	 * nonzero VA+size there is the canonical "this is a managed assembly" marker.
	 *
	 * Only the PE headers are needed, so callers may pass just the first few KB.
	 * Returns false for non-PE input, truncated headers, or native-only PEs.
	 */
	detectDotNet(buf: Buffer): boolean {
		try {
			if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d /* MZ */) { return false; }
			const lfanew = buf.readUInt32LE(0x3c);
			if (lfanew <= 0 || lfanew + 24 + 0x70 > buf.length) { return false; }
			if (buf.readUInt32LE(lfanew) !== 0x00004550 /* "PE\0\0" */) { return false; }
			const optHeader = lfanew + 24;
			const magic = buf.readUInt16LE(optHeader);
			// Data directories start after the optional-header standard+windows
			// fields: 96 bytes in for PE32 (0x10b), 112 for PE32+ (0x20b).
			const ddBase = magic === 0x20b ? optHeader + 112 : optHeader + 96;
			const clrDir = ddBase + 14 * 8; // index 14 = CLR Runtime Header
			if (clrDir + 8 > buf.length) { return false; }
			const clrVA = buf.readUInt32LE(clrDir);
			const clrSize = buf.readUInt32LE(clrDir + 4);
			return clrVA !== 0 && clrSize !== 0;
		} catch {
			return false;
		}
	}

	/**
	 * Whether a matched rule is reliable on managed code. .NET-aware rules
	 * (DefenderYara MSIL platform, or rules that name MSIL/.NET) interpret the
	 * managed metadata correctly and keep full weight on a .NET target; every
	 * other rule is a native byte-pattern heuristic whose hits inside metadata /
	 * IL / string-heap bytes are false positives.
	 */
	private isManagedAwareMatch(m: RuleMatch): boolean {
		const hay = `${m.meta.platform || ''} ${m.namespace} ${(m.meta.family || '')} ${m.ruleName}`;
		return /\bMSIL\b|\.NET|dotnet|AnyCPU/i.test(hay);
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
		let binaryContext: BinaryScanContext = { format: 'unknown', sections: [] };
		try {
			binaryContext = inspectBinaryScanContext(fs.readFileSync(filePath));
		} catch { /* unreadable target already produces an empty scan */ }
		for (const match of matches) {
			qualifyMatch(match, binaryContext);
		}

		// GAP #3: detect a .NET / managed assembly so native byte-pattern rules
		// don't inflate the threat score against metadata/IL bytes. Reading the
		// PE headers (first 4KB) is enough; the data directories live there.
		let isDotNet = false;
		try {
			const fd = fs.openSync(filePath, 'r');
			const header = Buffer.alloc(Math.min(4096, fs.fstatSync(fd).size));
			fs.readSync(fd, header, 0, header.length, 0);
			fs.closeSync(fd);
			isDotNet = this.detectDotNet(header);
		} catch { /* unreadable -> treat as native, no suppression */ }

		const categories: Record<string, number> = {};
		let maxScore = 0;
		let scoredMatches = 0;       // matches that count toward the headline score
		const heuristicSuppressed = matches.filter(match => match.advisoryOnly).length;
		let managedSuppressed = 0;

		for (const m of matches) {
			categories[m.namespace] = (categories[m.namespace] || 0) + 1;
			if (m.advisoryOnly) {
				continue;
			}
			// On a .NET target, only .NET-aware rules are reliable. Native
			// byte-pattern matches are flagged advisory and excluded from the
			// score (but still reported in `matches`).
			if (isDotNet && !this.isManagedAwareMatch(m)) {
				m.advisoryOnly = true;
				m.advisoryReason = 'Native byte-pattern rule is not managed-code aware.';
				managedSuppressed++;
				continue;
			}
			scoredMatches++;
			if (m.score > maxScore) { maxScore = m.score; }
		}

		let stat: fs.Stats | null = null;
		try { stat = fs.statSync(filePath); } catch { /* */ }

		const result: ScanResult = {
			file: filePath,
			matches,
			// Correlated rules frequently describe the same primitive. Counting
			// their quantity as an automatic +10 promoted normal runtimes to a
			// higher severity; headline score now reflects the strongest retained
			// evidence while matchCount preserves breadth.
			threatScore: Math.min(100, maxScore),
			scanTime: Date.now() - startTime,
			fileSize: stat?.size || 0,
			categories,
			binaryContext: {
				format: binaryContext.format,
				...(binaryContext.architecture ? { architecture: binaryContext.architecture } : {}),
				executableSectionCount: binaryContext.sections.filter(section => section.executable).length,
			},
			// v3.8.0-nightly diagnostic: surface how many rules the engine had
			// active during this scan. `threatScore: 0` + `activeRules: 0` is
			// a packaging/activation issue, not a miss; `activeRules > 0` + 0
			// score means the binary legitimately didn't match anything.
			activeRules: this.getAllRules().length,
			ruleLoadDiagnostics: this.getLoadDiagnostics()
		};

		if (heuristicSuppressed > 0) {
			result.heuristicAdvisory = {
				suppressedRuleMatches: heuristicSuppressed,
				retainedRuleMatches: scoredMatches,
				note: `${heuristicSuppressed} rule match(es) were retained as advisory evidence but excluded from threatScore because architecture or executable-section requirements were not met.`,
			};
		}

		if (isDotNet) {
			result.isDotNet = true;
			result.dotNetAdvisory = {
				suppressedRuleMatches: managedSuppressed,
				retainedRuleMatches: scoredMatches,
				note: managedSuppressed > 0
					? `.NET/managed assembly: ${managedSuppressed} native byte-pattern match(es) reclassified as advisory ` +
					  `(they hit managed metadata/IL, not native code) and excluded from the threat score. ` +
					  `Score reflects ${scoredMatches} .NET-aware match(es).`
					: `.NET/managed assembly: threat score derived from .NET-aware rules only.`
			};
		}

		return result;
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
					offsets = matchRegexOffsets(str.value, content.toString('binary'));
				} catch (error) {
					this.log(`[yara] skipped unsupported or invalid regex in rule "${rule.name}" (${str.identifier}): ${(error as Error).message}`);
				}
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

		// DefenderYara weighted condition: ((#a_81_0 & 1)*3 + ...) >= threshold
		const weightedMatch = cond.match(/>=\s*(\d+)\s*$/);
		if (weightedMatch && /#[A-Za-z0-9_]+\s*&\s*1/.test(cond)) {
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

		const evaluation = evaluateYaraCondition(
			cond,
			matchCounts,
			rule.strings.map(item => item.identifier),
		);
		if (!evaluation.supported) {
			this.log(`[yara] condition for rule "${rule.name}" was not evaluated: ${evaluation.error}`);
		}
		return evaluation.result;
	}

	// ── Rule Management ─────────────────────────────────────────────────

	async updateRules(): Promise<void> {
		this.loadedRules = [];
		// Reset catalog loaded flags
		for (const entry of this.catalog) {
			entry.loaded = false;
		}

		// v3.8.0-nightly: re-load persistent bundled rule directories so
		// `updateRules()` doesn't drop the anti-analysis ruleset the extension
		// loaded at activation. Without this, autoUpdate wipes the 44 bundled
		// rules and every scan comes back with only the 7 built-ins.
		for (const dir of this._persistentRuleDirs) {
			try { this.loadRulesFromDirectory(dir); } catch { /* best-effort */ }
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
		// v3.8.0-nightly: same reasoning as updateRules() — keep bundled rules
		// reachable after a results clear. Without re-loading, the next scan
		// has only the 7 built-in rules.
		for (const dir of this._persistentRuleDirs) {
			try { this.loadRulesFromDirectory(dir); } catch { /* best-effort */ }
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

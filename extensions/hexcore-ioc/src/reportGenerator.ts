/*---------------------------------------------------------------------------------------------
 *  HexCore IOC Extractor v1.1.0
 *  Markdown report generator
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import type { IOCCategory, IOCExtractionResult, IOCMatch } from './types';

/** Human-readable labels for each IOC category. */
const CATEGORY_LABELS: Record<IOCCategory, string> = {
	ipv4: 'IPv4 Addresses',
	ipv6: 'IPv6 Addresses',
	url: 'URLs',
	domain: 'Domains',
	email: 'Email Addresses',
	hash: 'Hashes (MD5 / SHA-1 / SHA-256)',
	filePath: 'File Paths',
	registryKey: 'Registry Keys',
	namedPipe: 'Named Pipes',
	mutex: 'Mutexes / GUIDs',
	userAgent: 'User Agents',
	cryptoWallet: 'Crypto Wallets',
};

/** Priority order for report sections — network indicators first. */
const CATEGORY_PRIORITY: IOCCategory[] = [
	'url', 'ipv4', 'ipv6', 'domain', 'email',
	'hash', 'cryptoWallet', 'namedPipe', 'registryKey',
	'filePath', 'mutex', 'userAgent',
];

/** Severity tag per category for quick triage. */
const SEVERITY_TAG: Record<IOCCategory, string> = {
	url: '🔴 HIGH',
	ipv4: '🔴 HIGH',
	ipv6: '🟡 MEDIUM',
	domain: '🔴 HIGH',
	email: '🟡 MEDIUM',
	hash: '🟡 MEDIUM',
	cryptoWallet: '🔴 HIGH',
	namedPipe: '🔴 HIGH',
	registryKey: '🟡 MEDIUM',
	filePath: '🟢 LOW',
	mutex: '🟡 MEDIUM',
	userAgent: '🟡 MEDIUM',
};

/**
 * Risk level badge for Markdown reports.
 * Uses colored emoji indicators as Markdown-compatible badges.
 */
type RiskLevel = 'danger' | 'warning' | 'safe';

const RISK_BADGE: Record<RiskLevel, string> = {
	danger: '🔴',
	warning: '🟡',
	safe: '🟢',
};

/** Map IOC category to risk level for badge rendering. */
const CATEGORY_RISK: Record<IOCCategory, RiskLevel> = {
	url: 'danger',
	ipv4: 'danger',
	ipv6: 'warning',
	domain: 'danger',
	email: 'warning',
	hash: 'warning',
	cryptoWallet: 'danger',
	namedPipe: 'danger',
	registryKey: 'warning',
	filePath: 'safe',
	mutex: 'warning',
	userAgent: 'warning',
};

export function generateIOCReport(result: IOCExtractionResult): string {
	const lines: string[] = [];

	// Header
	lines.push('# HexCore IOC Extraction Report');
	lines.push('');
	lines.push('## File Information');
	lines.push('');
	lines.push('| Property | Value |');
	lines.push('|----------|-------|');
	lines.push(`| **File Name** | \`${result.fileName}\` |`);
	lines.push(`| **File Path** | \`${result.filePath}\` |`);
	lines.push(`| **File Size** | ${formatBytes(result.fileSize)} |`);
	lines.push(`| **Storage Backend** | ${result.storageBackend} |`);
	lines.push(`| **Unique IOCs** | ${result.summary.uniqueIndicators} |`);
	lines.push(`| **Truncated** | ${result.summary.truncated ? 'Yes (max match limit reached)' : 'No'} |`);
	lines.push('');

	// Category overview
	lines.push('---');
	lines.push('');
	lines.push('## IOC Summary');
	lines.push('');
	lines.push('| Category | Count | Severity |');
	lines.push('|----------|-------|----------|');

	let hasAny = false;
	for (const cat of CATEGORY_PRIORITY) {
		const count = result.summary.categoryCounts[cat] ?? 0;
		if (count > 0) {
			hasAny = true;
			lines.push(`| **${CATEGORY_LABELS[cat]}** | ${count} | ${SEVERITY_TAG[cat]} |`);
		}
	}
	if (!hasAny) {
		lines.push('| *No indicators found* | 0 | — |');
	}
	lines.push('');

	// Threat assessment
	if (hasAny) {
		lines.push('---');
		lines.push('');
		lines.push('## Threat Assessment');
		lines.push('');
		const threats = assessThreats(result);
		if (threats.length > 0) {
			for (const threat of threats) {
				lines.push(`- ${threat}`);
			}
		} else {
			lines.push(`- ${RISK_BADGE.safe} No high-confidence threat indicators detected.`);
		}
		lines.push('');

		// Risk summary badges
		lines.push('### Risk Summary');
		lines.push('');
		const dangerCount = CATEGORY_PRIORITY.filter(c =>
			CATEGORY_RISK[c] === 'danger' && (result.summary.categoryCounts[c] ?? 0) > 0
		).length;
		const warningCount = CATEGORY_PRIORITY.filter(c =>
			CATEGORY_RISK[c] === 'warning' && (result.summary.categoryCounts[c] ?? 0) > 0
		).length;
		const safeCount = CATEGORY_PRIORITY.filter(c =>
			CATEGORY_RISK[c] === 'safe' && (result.summary.categoryCounts[c] ?? 0) > 0
		).length;
		lines.push(`| Risk Level | Badge | Categories |`);
		lines.push(`|------------|-------|------------|`);
		if (dangerCount > 0) {
			lines.push(`| **HIGH** | ${RISK_BADGE.danger} | ${dangerCount} categor${dangerCount === 1 ? 'y' : 'ies'} |`);
		}
		if (warningCount > 0) {
			lines.push(`| **MEDIUM** | ${RISK_BADGE.warning} | ${warningCount} categor${warningCount === 1 ? 'y' : 'ies'} |`);
		}
		if (safeCount > 0) {
			lines.push(`| **LOW** | ${RISK_BADGE.safe} | ${safeCount} categor${safeCount === 1 ? 'y' : 'ies'} |`);
		}
		lines.push('');
	}

	// Per-category detail tables
	for (const cat of CATEGORY_PRIORITY) {
		const matches = result.indicators[cat];
		if (!matches || matches.length === 0) { continue; }

		lines.push('---');
		lines.push('');
		lines.push(`## ${CATEGORY_LABELS[cat]} (${matches.length})`);
		lines.push('');
		lines.push('| # | Value | Encoding | Offset | Context |');
		lines.push('|---|-------|----------|--------|---------|');

		const displayMax = 100;
		const sliced = matches.slice(0, displayMax);
		for (let i = 0; i < sliced.length; i++) {
			const m = sliced[i];
			const escaped = escapeMarkdown(m.value).substring(0, 80);
			const ctxEscaped = escapeMarkdown(m.context).substring(0, 40);
			const offsetHex = `0x${m.offset.toString(16).toUpperCase().padStart(8, '0')}`;
			lines.push(`| ${i + 1} | \`${escaped}\` | ${m.encoding} | ${offsetHex} | \`${ctxEscaped}\` |`);
		}

		if (matches.length > displayMax) {
			lines.push(`| ... | *${matches.length - displayMax} more* | — | — | — |`);
		}
		lines.push('');
	}

	// Footer
	lines.push('---');
	lines.push(`*Generated by HexCore IOC Extractor v1.1.0 at ${new Date().toISOString()}*`);
	lines.push('');

	return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Threat Assessment
// ---------------------------------------------------------------------------

function assessThreats(result: IOCExtractionResult): string[] {
	const threats: string[] = [];

	const urls = result.indicators.url ?? [];
	const ips = result.indicators.ipv4 ?? [];
	const pipes = result.indicators.namedPipe ?? [];
	const wallets = result.indicators.cryptoWallet ?? [];
	const agents = result.indicators.userAgent ?? [];
	const registry = result.indicators.registryKey ?? [];
	const hashes = result.indicators.hash ?? [];

	if (urls.length > 0) {
		const suspicious = urls.filter(u => hasSuspiciousURLPattern(u.value));
		if (suspicious.length > 0) {
			threats.push(`⚠️ **${suspicious.length} suspicious URL(s)** detected (raw IP hosts, non-standard ports, encoded paths).`);
		}
	}

	if (ips.length > 0) {
		threats.push(`🌐 **${ips.length} unique IPv4 address(es)** found — potential C2 or exfiltration endpoints.`);
	}

	if (pipes.length > 0) {
		threats.push(`🔧 **${pipes.length} named pipe(s)** found — common IPC mechanism for malware components.`);
	}

	if (wallets.length > 0) {
		threats.push(`💰 **${wallets.length} cryptocurrency wallet address(es)** found — possible ransomware payment target.`);
	}

	if (agents.length > 0) {
		threats.push(`🕵️ **${agents.length} user agent string(s)** found — custom HTTP client fingerprint.`);
	}

	if (hashes.length > 0) {
		threats.push(`🔑 **${hashes.length} cryptographic hash(es)** found — possible file integrity checks or known-malware references.`);
	}

	if (registry.length > 0) {
		const persistence = registry.filter(r =>
			/\\Run\\|\\RunOnce\\|\\Services\\|\\CurrentVersion\\Explorer/i.test(r.value)
		);
		if (persistence.length > 0) {
			threats.push(`🔑 **${persistence.length} registry key(s)** associated with persistence mechanisms.`);
		}
	}

	return threats;
}

function hasSuspiciousURLPattern(url: string): boolean {
	try {
		const parsed = new URL(url);
		// Raw IP as host
		if (/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname)) { return true; }
		// Non-standard port
		if (parsed.port && parsed.port !== '80' && parsed.port !== '443') { return true; }
		// URL-encoded path segments
		if (/%[0-9a-f]{2}/i.test(parsed.pathname)) { return true; }
		// Common C2 path indicators
		if (/\/gate|\/panel|\/bot|\/cmd|\/shell/i.test(parsed.pathname)) { return true; }
		return false;
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function escapeMarkdown(text: string): string {
	return text
		.replace(/\|/g, '\\|')
		.replace(/\n/g, ' ')
		.replace(/\r/g, '');
}

function formatBytes(bytes: number): string {
	if (!Number.isFinite(bytes) || bytes <= 0) { return '0 B'; }
	const k = 1024;
	const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

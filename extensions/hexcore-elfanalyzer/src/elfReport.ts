/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { ELFAnalysis } from './elfParser';

/**
 * Format a file size into a human-readable string.
 */
function formatFileSize(bytes: number): string {
	if (bytes < 1024) {
		return `${bytes.toLocaleString()} bytes`;
	}
	if (bytes < 1024 * 1024) {
		return `${(bytes / 1024).toFixed(1)} KB`;
	}
	return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Return a colored badge descriptor for an ELF security feature.
 *
 * The mapping follows the unified HexCore risk palette:
 * - RELRO: Full → green, Partial → yellow, None → red
 * - NX / PIE / Stack Canary: Enabled/Present → green, Disabled/Absent → red
 *
 * @param feature - Security feature name (e.g. "RELRO", "NX", "PIE", "Stack Canary")
 * @param state   - Current state string (e.g. "full", "partial", "none", "enabled", "disabled", "present", "absent")
 * @returns Object with `color` (hex string) and `label` (human-readable text)
 */
export function elfSecurityBadge(feature: string, state: string): { color: string; label: string } {
	const s = state.toLowerCase();

	// RELRO has three states
	if (feature.toLowerCase() === 'relro') {
		switch (s) {
			case 'full':
				return { color: '#4ec9b0', label: 'Full RELRO' };
			case 'partial':
				return { color: '#dcdcaa', label: 'Partial RELRO' };
			default:
				return { color: '#f44747', label: 'No RELRO' };
		}
	}

	// Boolean features: enabled/present → green, disabled/absent → red
	const positive = s === 'enabled' || s === 'present' || s === 'true' || s === 'yes';
	if (positive) {
		return { color: '#4ec9b0', label: `${feature} Enabled` };
	}
	return { color: '#f44747', label: `${feature} Disabled` };
}

/**
 * Escape pipe characters in Markdown table cells.
 */
function escapeCell(value: string): string {
	return value.replace(/\|/g, '\\|');
}

/**
 * Build a complete Markdown report from an ELF analysis result.
 *
 * Follows the PE Analyzer report pattern with tables for sections,
 * segments, symbols, dynamic entries, imports, and security mitigations.
 */
export function buildMarkdownReport(analysis: ELFAnalysis): string {
	const lines: string[] = [];

	lines.push(`# ELF Analysis Report: ${escapeCell(analysis.fileName)}`);
	lines.push('');

	// Handle non-ELF files early
	if (!analysis.isELF) {
		lines.push(`**Error:** ${analysis.error || 'File is not a valid ELF binary.'}`);
		lines.push('');
		lines.push(`- File: \`${analysis.filePath}\``);
		lines.push(`- Size: ${formatFileSize(analysis.fileSize)}`);
		lines.push('');
		return lines.join('\n');
	}

	// Summary table
	lines.push('## Summary');
	lines.push('');
	lines.push('| Property | Value |');
	lines.push('|---|---|');
	lines.push(`| File | \`${escapeCell(analysis.filePath)}\` |`);
	lines.push(`| Size | ${formatFileSize(analysis.fileSize)} |`);
	lines.push(`| Class | ${analysis.elfClass} |`);
	lines.push(`| Endianness | ${analysis.endianness} |`);
	lines.push(`| OS/ABI | ${escapeCell(analysis.osABI)} |`);
	lines.push(`| Type | ${escapeCell(analysis.type)} |`);
	lines.push(`| Machine | ${escapeCell(analysis.machine)} |`);
	lines.push(`| Entry Point | \`${analysis.entryPoint}\` |`);
	lines.push('');

	// Headers (ELF header details)
	lines.push('## Headers');
	lines.push('');
	lines.push('### ELF Header');
	lines.push('');
	lines.push('| Field | Value |');
	lines.push('|---|---|');
	lines.push(`| Class | ${analysis.elfClass} |`);
	lines.push(`| Data | ${analysis.endianness === 'little' ? '2\'s complement, little endian' : '2\'s complement, big endian'} |`);
	lines.push(`| OS/ABI | ${escapeCell(analysis.osABI)} |`);
	lines.push(`| Type | ${escapeCell(analysis.type)} |`);
	lines.push(`| Machine | ${escapeCell(analysis.machine)} |`);
	lines.push(`| Entry Point | \`${analysis.entryPoint}\` |`);
	lines.push(`| Section Headers | ${analysis.sections.length} entries |`);
	lines.push(`| Program Headers | ${analysis.segments.length} entries |`);
	lines.push('');

	// Security mitigations with colored badges
	lines.push('## Security Mitigations');
	lines.push('');
	const relroBadge = elfSecurityBadge('RELRO', analysis.security.relro);
	const canaryBadge = elfSecurityBadge('Stack Canary', analysis.security.stackCanary ? 'enabled' : 'disabled');
	const nxBadge = elfSecurityBadge('NX', analysis.security.nx ? 'enabled' : 'disabled');
	const pieBadge = elfSecurityBadge('PIE', analysis.security.pie ? 'enabled' : 'disabled');
	lines.push('| Mitigation | Status | Badge |');
	lines.push('|---|---|---|');
	lines.push(`| RELRO | ${formatRelro(analysis.security.relro)} | 🔵 ${relroBadge.label} |`);
	lines.push(`| Stack Canary | ${analysis.security.stackCanary ? '✅ Enabled' : '❌ Disabled'} | 🔵 ${canaryBadge.label} |`);
	lines.push(`| NX | ${analysis.security.nx ? '✅ Enabled' : '❌ Disabled'} | 🔵 ${nxBadge.label} |`);
	lines.push(`| PIE | ${analysis.security.pie ? '✅ Enabled' : '❌ Disabled'} | 🔵 ${pieBadge.label} |`);
	lines.push('');

	// Sections
	lines.push('## Sections');
	lines.push('');
	if (analysis.sections.length === 0) {
		lines.push('No sections found.');
	} else {
		lines.push('| Name | Type | Address | Offset | Size | Flags | Entropy |');
		lines.push('|---|---|---:|---:|---:|---|---:|');
		for (const s of analysis.sections) {
			lines.push(
				`| ${escapeCell(s.name)} | ${escapeCell(s.type)} | ${s.address} | ${s.offset} | ${s.size} | ${escapeCell(s.flags.join(', '))} | ${s.entropy.toFixed(2)} |`
			);
		}
	}
	lines.push('');

	// Segments
	lines.push('## Segments');
	lines.push('');
	if (analysis.segments.length === 0) {
		lines.push('No segments found.');
	} else {
		lines.push('| Type | Offset | Virtual Addr | Physical Addr | File Size | Mem Size | Flags | Alignment |');
		lines.push('|---|---:|---|---|---:|---:|---|---:|');
		for (const seg of analysis.segments) {
			lines.push(
				`| ${escapeCell(seg.type)} | ${seg.offset} | ${seg.virtualAddress} | ${seg.physicalAddress} | ${seg.fileSize} | ${seg.memorySize} | ${escapeCell(seg.flags.join(', '))} | ${seg.alignment} |`
			);
		}
	}
	lines.push('');

	// Symbols (limited to first 100)
	lines.push('## Symbols');
	lines.push('');
	if (analysis.symbols.length === 0) {
		lines.push('No symbols found.');
	} else {
		const total = analysis.symbols.length;
		const displayed = Math.min(total, 100);
		lines.push(`Showing ${displayed} of ${total} symbols.`);
		lines.push('');
		lines.push('| Name | Value | Size | Type | Binding | Section |');
		lines.push('|---|---|---:|---|---|---|');
		for (const sym of analysis.symbols.slice(0, 100)) {
			lines.push(
				`| ${escapeCell(sym.name)} | ${sym.value} | ${sym.size} | ${escapeCell(sym.type)} | ${escapeCell(sym.binding)} | ${escapeCell(sym.section)} |`
			);
		}
	}
	lines.push('');

	// Dynamic entries
	lines.push('## Dynamic Entries');
	lines.push('');
	if (analysis.dynamicEntries.length === 0) {
		lines.push('No dynamic entries found.');
	} else {
		lines.push('| Tag | Value |');
		lines.push('|---|---|');
		for (const dyn of analysis.dynamicEntries) {
			lines.push(`| ${escapeCell(dyn.tag)} | ${escapeCell(dyn.value)} |`);
		}
	}
	lines.push('');

	// Imports
	lines.push('## Imports');
	lines.push('');
	if (analysis.imports.length === 0) {
		lines.push('No imports found.');
	} else {
		lines.push('| Name | Library |');
		lines.push('|---|---|');
		for (const imp of analysis.imports) {
			lines.push(`| ${escapeCell(imp.name)} | ${escapeCell(imp.library)} |`);
		}
	}
	lines.push('');

	// Footer
	lines.push('---');
	lines.push('');
	lines.push(`*Report generated at ${new Date().toISOString()}*`);
	lines.push('');

	return lines.join('\n');
}

/**
 * Format RELRO status with icon.
 */
function formatRelro(relro: 'full' | 'partial' | 'none'): string {
	switch (relro) {
		case 'full': return '✅ Full';
		case 'partial': return '⚠️ Partial';
		case 'none': return '❌ None';
	}
}

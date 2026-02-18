/*---------------------------------------------------------------------------------------------
 *  HexCore Minidump Parser v1.0.0
 *  Markdown report generator
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import type { MinidumpAnalysisResult, ModuleInfo, MemoryRegion, ThreadExInfo } from './types';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function generateMinidumpReport(result: MinidumpAnalysisResult): string {
	const l: string[] = [];

	l.push('# HexCore Minidump Analysis Report');
	l.push('');

	// File info
	l.push('## File Information');
	l.push('');
	l.push('| Property | Value |');
	l.push('|----------|-------|');
	l.push(`| **File Name** | \`${result.fileName}\` |`);
	l.push(`| **File Path** | \`${result.filePath}\` |`);
	l.push(`| **File Size** | ${formatBytes(result.fileSize)} |`);
	l.push(`| **Dump Timestamp** | ${formatTimestamp(result.header.timestamp)} |`);
	l.push(`| **Stream Count** | ${result.streamDirectory.length} |`);
	l.push(`| **Flags** | 0x${result.header.flags.toString(16).toUpperCase()} |`);
	l.push('');

	// System info
	if (result.systemInfo) {
		const si = result.systemInfo;
		l.push('## System Information');
		l.push('');
		l.push('| Property | Value |');
		l.push('|----------|-------|');
		l.push(`| **OS** | ${si.osVersionString} |`);
		l.push(`| **Architecture** | ${si.processorArchitectureName} |`);
		l.push(`| **Processor Count** | ${si.numberOfProcessors} |`);
		l.push(`| **Processor Level** | ${si.processorLevel} |`);
		l.push('');
	}

	// Threat summary
	const t = result.threats;
	const threatCount = t.rwxRegions.length + t.nonSystemModules.length +
		t.recentThreads.length + t.suspiciousStartAddresses.length;

	if (threatCount > 0) {
		l.push('---');
		l.push('');
		l.push('## ⚠️ Threat Indicators');
		l.push('');
		if (t.rwxRegions.length > 0) {
			l.push(`- 🔴 **${t.rwxRegions.length} RWX memory region(s)** — PAGE_EXECUTE_READWRITE in private committed memory (likely shellcode/injection)`);
		}
		if (t.suspiciousStartAddresses.length > 0) {
			l.push(`- 🔴 **${t.suspiciousStartAddresses.length} thread(s) with non-image start address** — thread entry point not in any loaded module (hijacking/hollowing)`);
		}
		if (t.recentThreads.length > 0) {
			l.push(`- 🟡 **${t.recentThreads.length} recently created thread(s)** — created within 60s of dump (possible injection activity)`);
		}
		if (t.nonSystemModules.length > 0) {
			l.push(`- 🟡 **${t.nonSystemModules.length} non-system module(s)** loaded from outside system directories`);
		}
		l.push('');
	}

	// Threads
	if (result.threads.length > 0) {
		l.push('---');
		l.push('');
		l.push(`## Threads (${result.threads.length})`);
		l.push('');
		l.push('| # | Thread ID | Suspend | Priority | TEB | Stack Size |');
		l.push('|---|-----------|---------|----------|-----|------------|');
		for (let i = 0; i < result.threads.length; i++) {
			const th = result.threads[i];
			l.push(`| ${i + 1} | ${th.threadId} | ${th.suspendCount} | ${th.priority} | 0x${th.teb.toString(16).toUpperCase()} | ${formatBytes(th.stackDataSize)} |`);
		}
		l.push('');
	}

	// Thread extended info
	if (result.threadExInfo.length > 0) {
		l.push('---');
		l.push('');
		l.push(`## Thread Timing (${result.threadExInfo.length})`);
		l.push('');
		l.push('| # | Thread ID | Created | Start Address | Flag |');
		l.push('|---|-----------|---------|---------------|------|');
		for (let i = 0; i < result.threadExInfo.length; i++) {
			const tex = result.threadExInfo[i];
			const created = tex.createTime !== 0n ? formatFileTime(tex.createTime) : '—';
			const addr = tex.startAddress !== 0n ? `0x${tex.startAddress.toString(16).toUpperCase()}` : '—';
			const flag = getThreadFlags(tex, result);
			l.push(`| ${i + 1} | ${tex.threadId} | ${created} | ${addr} | ${flag} |`);
		}
		l.push('');
	}

	// Modules
	if (result.modules.length > 0) {
		l.push('---');
		l.push('');
		l.push(`## Loaded Modules (${result.modules.length})`);
		l.push('');
		l.push('| # | Name | Base Address | Size | Flag |');
		l.push('|---|------|-------------|------|------|');
		for (let i = 0; i < result.modules.length; i++) {
			const m = result.modules[i];
			const shortName = getFileName(m.name);
			const addr = `0x${m.baseAddress.toString(16).toUpperCase()}`;
			const flag = getModuleFlag(m);
			l.push(`| ${i + 1} | \`${shortName}\` | ${addr} | ${formatBytes(m.size)} | ${flag} |`);
		}
		l.push('');
	}

	// Memory regions (only suspicious + summary)
	if (result.memoryRegions.length > 0) {
		l.push('---');
		l.push('');
		const suspicious = result.memoryRegions.filter(r => r.isSuspicious);
		const committed = result.memoryRegions.filter(r => r.stateName === 'MEM_COMMIT');

		l.push(`## Memory Regions (${result.memoryRegions.length} total, ${committed.length} committed)`);
		l.push('');

		if (suspicious.length > 0) {
			l.push(`### 🔴 Suspicious Regions (${suspicious.length})`);
			l.push('');
			l.push('| # | Base Address | Size | Protection | Type |');
			l.push('|---|-------------|------|------------|------|');
			for (let i = 0; i < suspicious.length; i++) {
				const r = suspicious[i];
				l.push(`| ${i + 1} | 0x${r.baseAddress.toString(16).toUpperCase().padStart(16, '0')} | ${formatBytes(Number(r.regionSize))} | ${r.protectName} | ${r.typeName} |`);
			}
			l.push('');
		}

		// Protection distribution
		l.push('### Protection Distribution');
		l.push('');
		const protectionMap = new Map<string, number>();
		for (const r of committed) {
			const key = r.protectName;
			protectionMap.set(key, (protectionMap.get(key) ?? 0) + 1);
		}
		l.push('| Protection | Count |');
		l.push('|------------|-------|');
		for (const [prot, count] of [...protectionMap.entries()].sort((a, b) => b[1] - a[1])) {
			l.push(`| ${prot} | ${count} |`);
		}
		l.push('');
	}

	// Exception info
	if (result.exception) {
		const ex = result.exception;
		l.push('---');
		l.push('');
		l.push('## 🔴 Exception Info');
		l.push('');
		l.push('| Property | Value |');
		l.push('|----------|-------|');
		l.push(`| **Exception Code** | 0x${ex.exceptionCode.toString(16).toUpperCase().padStart(8, '0')} (\`${ex.exceptionName}\`) |`);
		l.push(`| **Exception Address** | 0x${ex.exceptionAddress.toString(16).toUpperCase()} |`);
		l.push(`| **Faulting Thread** | ${ex.threadId} |`);
		l.push(`| **Exception Flags** | 0x${ex.exceptionFlags.toString(16).toUpperCase()} ${ex.exceptionFlags !== 0 ? '(non-continuable)' : '(continuable)'} |`);
		if (ex.numberOfParameters > 0) {
			l.push(`| **Parameters** | ${ex.numberOfParameters} |`);
			for (let i = 0; i < ex.numberOfParameters; i++) {
				l.push(`| **Parameter[${i}]** | 0x${ex.parameters[i].toString(16).toUpperCase()} |`);
			}
		}
		l.push('');

		// Cross-reference faulting thread with thread list
		const faultingThread = result.threads.find(t => t.threadId === ex.threadId);
		if (faultingThread) {
			l.push(`> **Faulting Thread Details:** TEB=0x${faultingThread.teb.toString(16).toUpperCase()}, Stack Size=${formatBytes(faultingThread.stackDataSize)}, Priority=${faultingThread.priority}`);
			l.push('');
		}

		// Cross-reference exception address with loaded modules
		const faultingModule = result.modules.find(m => {
			const base = m.baseAddress;
			const end = base + BigInt(m.size);
			return ex.exceptionAddress >= base && ex.exceptionAddress < end;
		});
		if (faultingModule) {
			const offset = ex.exceptionAddress - faultingModule.baseAddress;
			l.push(`> **Faulting Module:** \`${getFileName(faultingModule.name)}\` (base=0x${faultingModule.baseAddress.toString(16).toUpperCase()}, offset=+0x${offset.toString(16).toUpperCase()})`);
		} else {
			l.push('> ⚠️ **Exception address does not belong to any loaded module** — possible shellcode or JIT code');
		}
		l.push('');
	}

	// Footer
	l.push('---');
	l.push(`*Generated by HexCore Minidump Parser v1.0.0 at ${new Date().toISOString()}*`);
	l.push('');

	return l.join('\n');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getThreadFlags(tex: ThreadExInfo, result: MinidumpAnalysisResult): string {
	const flags: string[] = [];
	if (result.threats.recentThreads.some(t => t.threadId === tex.threadId)) {
		flags.push('🟡 RECENT');
	}
	if (result.threats.suspiciousStartAddresses.some(t => t.threadId === tex.threadId)) {
		flags.push('🔴 NON-IMAGE');
	}
	return flags.length > 0 ? flags.join(' ') : '—';
}

function getModuleFlag(m: ModuleInfo): string {
	const lower = m.name.toLowerCase();
	const systemPrefixes = ['c:\\windows\\', 'c:\\program files\\', 'c:\\program files (x86)\\'];
	if (!systemPrefixes.some(p => lower.startsWith(p))) {
		return '🟡 NON-SYSTEM';
	}
	return '—';
}

function getFileName(fullPath: string): string {
	const lastSlash = Math.max(fullPath.lastIndexOf('\\'), fullPath.lastIndexOf('/'));
	return lastSlash >= 0 ? fullPath.substring(lastSlash + 1) : fullPath;
}

function formatBytes(bytes: number): string {
	if (!Number.isFinite(bytes) || bytes <= 0) { return '0 B'; }
	const k = 1024;
	const sizes = ['B', 'KB', 'MB', 'GB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatTimestamp(unixTimestamp: number): string {
	return new Date(unixTimestamp * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC');
}

/**
 * Convert Windows FILETIME (100ns since 1601-01-01) to ISO string.
 */
function formatFileTime(ft: bigint): string {
	if (ft === 0n) { return '—'; }
	const EPOCH_DIFF = BigInt(116444736000000000);
	const unixNs = ft - EPOCH_DIFF;
	const unixMs = Number(unixNs / BigInt(10_000));
	try {
		return new Date(unixMs).toISOString().replace('T', ' ').replace('Z', '');
	} catch {
		return `0x${ft.toString(16)}`;
	}
}

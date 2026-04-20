/*---------------------------------------------------------------------------------------------
 *  HexCore PDB Function Boundary Loader (v3.8.1)
 *
 *  Extracts function entry/size info from a Windows PDB (Program Database)
 *  by spawning `llvm-pdbutil.exe` and parsing its textual dump output.
 *
 *  Motivation: `.pdata` only covers non-leaf functions (those with SEH unwind
 *  info). Leaf functions and some linker-generated stubs have no `.pdata`
 *  entry, which leaves Pathfinder blind to them. PDB's `DBI` stream + `globals`
 *  stream expose ALL function symbols — S_GPROC32 (global) and S_LPROC32
 *  (module-local) — regardless of whether they have unwind info.
 *
 *  Output format matches DWARF's FunctionBoundaryInfo so Pathfinder's
 *  extractPE64Context can consume both sources identically.
 *
 *  Graceful degradation:
 *    - If llvm-pdbutil is not available, returns []
 *    - If PDB file is missing/mismatched, returns []
 *    - If output format changes (future llvm-pdbutil versions), returns
 *      whatever partial data parsed cleanly
 *---------------------------------------------------------------------------------------------*/

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import type { FunctionBoundaryInfo } from './elfBtfLoader';

/** Candidate locations for llvm-pdbutil.exe, tried in order. */
const DEFAULT_PDBUTIL_CANDIDATES = [
	'llvm-pdbutil.exe',  // PATH
	'C:/Users/Mazum/Desktop/caps/llvm-build/build-mlir/bin/llvm-pdbutil.exe',
	'C:/Program Files/LLVM/bin/llvm-pdbutil.exe',
];

/** Discover a working llvm-pdbutil binary. Returns null if none found. */
function findPdbutil(): string | null {
	const override = process.env.HEXCORE_PDBUTIL;
	const candidates = override
		? [override, ...DEFAULT_PDBUTIL_CANDIDATES]
		: DEFAULT_PDBUTIL_CANDIDATES;

	for (const candidate of candidates) {
		try {
			const result = spawnSync(candidate, ['--version'], {
				encoding: 'utf-8',
				timeout: 5000,
			});
			if (result.status === 0 || result.status === 1) {
				// --version exits 0 on modern llvm-pdbutil; some versions
				// don't recognize --version and exit 1 but still prove the
				// binary is loadable. Either way it's usable.
				return candidate;
			}
		} catch {
			// candidate not found / not runnable — try next
		}
	}
	return null;
}

/** Parse the section-headers dump to build a sectionIndex -> VA map. */
function parseSectionHeaders(output: string): Map<number, number> {
	const result = new Map<number, number>();
	const sectionRe = /SECTION HEADER #(\d+)/g;
	const virtAddrRe = /^\s*([0-9A-Fa-f]+)\s+virtual address\s*$/m;

	let match: RegExpExecArray | null;
	while ((match = sectionRe.exec(output)) !== null) {
		const idx = parseInt(match[1], 10);
		// Grab the next ~15 lines after the SECTION HEADER line and search
		// for "virtual address" — the section body is short.
		const blockStart = match.index;
		const blockEnd = Math.min(output.length, blockStart + 800);
		const block = output.substring(blockStart, blockEnd);
		const vaMatch = virtAddrRe.exec(block);
		if (vaMatch) {
			result.set(idx, parseInt(vaMatch[1], 16));
		}
	}
	return result;
}

/** Parse S_GPROC32 / S_LPROC32 function records from --symbols output. */
function parseSymbols(
	output: string,
	sectionVAs: Map<number, number>,
	imageBase: number,
): FunctionBoundaryInfo[] {
	// A PROC32 entry spans 2 lines:
	//    428 | S_GPROC32 [size = 64] `__security_check_cookie`
	//          parent = 0, end = 544, addr = 0001:3456, code size = 30
	const lines = output.split(/\r?\n/);
	const procHeaderRe = /\bS_(?:GPROC32|LPROC32)\b.*`([^`]+)`/;
	const addrRe = /addr\s*=\s*([0-9]+)\s*:\s*([0-9A-Fa-f]+)\s*,\s*code size\s*=\s*(\d+)/;

	const result: FunctionBoundaryInfo[] = [];
	const seen = new Set<number>();

	for (let i = 0; i < lines.length; i++) {
		const header = procHeaderRe.exec(lines[i]);
		if (!header) { continue; }

		const name = header[1];

		// The addr line follows immediately. Tolerate blank lines or 1-2
		// line slack in case llvm-pdbutil's output format shifts minor.
		let addrMatch: RegExpExecArray | null = null;
		for (let j = 1; j <= 3 && i + j < lines.length; j++) {
			const m = addrRe.exec(lines[i + j]);
			if (m) { addrMatch = m; break; }
		}
		if (!addrMatch) { continue; }

		const sectionIdx = parseInt(addrMatch[1], 10);
		const offset = parseInt(addrMatch[2], 16);
		const codeSize = parseInt(addrMatch[3], 10);
		if (codeSize === 0) { continue; }

		const sectionVA = sectionVAs.get(sectionIdx);
		if (sectionVA === undefined) { continue; }

		const va = imageBase + sectionVA + offset;
		if (seen.has(va)) { continue; }
		seen.add(va);

		result.push({
			name,
			lowPc: va,
			highPc: va + codeSize,
		});
	}
	return result;
}

/**
 * Load function boundaries from a PDB via llvm-pdbutil.
 *
 * @param pdbPath     Absolute path to the .pdb file
 * @param imageBase   PE image base (e.g. 0x140000000 for typical x64 DLLs)
 * @returns           Array of function boundaries (lowPc = VA of first byte,
 *                    highPc = VA of first byte AFTER function). Empty array
 *                    if pdbutil missing, PDB unreadable, or no functions found.
 */
export async function loadPdbFunctionBoundaries(
	pdbPath: string,
	imageBase: number,
): Promise<FunctionBoundaryInfo[]> {
	if (!fs.existsSync(pdbPath)) { return []; }

	const tool = findPdbutil();
	if (!tool) {
		console.warn(`[pdbLoader] llvm-pdbutil not found; set HEXCORE_PDBUTIL or add to PATH`);
		return [];
	}

	// Dump section headers (needed for section-offset -> RVA conversion)
	const sectionsResult = spawnSync(tool, ['dump', '--section-headers', pdbPath], {
		encoding: 'utf-8',
		maxBuffer: 64 * 1024 * 1024, // 64 MB
		timeout: 60_000,
	});
	if (sectionsResult.status !== 0) {
		console.warn(`[pdbLoader] --section-headers failed: ${sectionsResult.stderr?.slice(0, 200) ?? 'no stderr'}`);
		return [];
	}
	const sectionVAs = parseSectionHeaders(sectionsResult.stdout);
	if (sectionVAs.size === 0) {
		console.warn(`[pdbLoader] no section headers parsed from PDB`);
		return [];
	}

	// Dump all function symbols
	const symbolsResult = spawnSync(tool, ['dump', '--symbols', pdbPath], {
		encoding: 'utf-8',
		maxBuffer: 256 * 1024 * 1024, // 256 MB (large PDBs)
		timeout: 120_000,
	});
	if (symbolsResult.status !== 0) {
		console.warn(`[pdbLoader] --symbols failed: ${symbolsResult.stderr?.slice(0, 200) ?? 'no stderr'}`);
		return [];
	}

	const boundaries = parseSymbols(symbolsResult.stdout, sectionVAs, imageBase);
	console.log(`[pdbLoader] parsed ${boundaries.length} function boundaries from ${pdbPath}`);
	return boundaries;
}

/**
 * Heuristic PDB-path discovery: look for a .pdb next to the PE at the same
 * base name, then fall back to the path embedded in the CodeView debug entry
 * (if the caller supplied it).
 */
export function discoverPdbPath(peFilePath: string, codeViewPdbPath?: string): string | null {
	// 1. Same-directory .pdb with same base name (most common for debug builds)
	const dot = peFilePath.lastIndexOf('.');
	const stem = dot > 0 ? peFilePath.substring(0, dot) : peFilePath;
	const sidecar = stem + '.pdb';
	if (fs.existsSync(sidecar)) { return sidecar; }

	// 2. The path embedded in the PE's CodeView record (absolute path from
	// the machine that built the binary). Useful when the PDB was copied
	// alongside at build time but with a different base name.
	if (codeViewPdbPath && fs.existsSync(codeViewPdbPath)) {
		return codeViewPdbPath;
	}

	return null;
}

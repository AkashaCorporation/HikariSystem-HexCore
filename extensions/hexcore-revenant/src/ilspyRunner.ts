/*---------------------------------------------------------------------------------------------
 *  HexCore Revenant -- managed (.NET / CIL) decompiler backend
 *
 *  Phase 1 (this file): shell out to `ilspycmd`, the command-line front-end of
 *  ILSpy's MIT-licensed ICSharpCode.Decompiler engine. The native Remill->Helix
 *  pipeline cannot read managed code (it lifts CIL .text as x86 -> a fake stub);
 *  Revenant resurrects the real C# / IL instead. This closes the "Better" tier of
 *  issue #32 (the "Minimum" honesty short-circuit already ships in hexcore-disassembler).
 *
 *  Phase 2 (planned): replace this shell-out with a bundled, self-contained C#
 *  wrapper (`dotnet publish -r <rid> --self-contained -p:PublishSingleFile=true`)
 *  that links ICSharpCode.Decompiler directly and emits structured JSON (entry-point
 *  method token, per-type IL, metadata, obfuscation markers) -- removing the .NET
 *  runtime dependency on the user's machine. The extension command surface stays
 *  identical; only this backend swaps.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFile } from 'child_process';

export type RevenantMode = 'csharp' | 'il';

export interface RevenantOptions {
	/** 'csharp' (default) decompiles to C#; 'il' disassembles to CIL. */
	mode?: RevenantMode;
	/** Optional fully-qualified type name to decompile just one type. */
	type?: string;
	/** Override the ilspycmd path (else auto-located). */
	ilspyPath?: string;
	/** Abort after this many ms (default 120000). */
	timeoutMs?: number;
	/** Extra assembly-reference search directories passed to ilspycmd (-r). */
	referencePaths?: string[];
}

export interface RevenantResult {
	ok: boolean;
	mode: RevenantMode;
	/** Decompiled C# or IL on success; empty on failure. */
	code: string;
	/** Whether the input was detected as a managed (.NET) PE. */
	isDotNet: boolean;
	/** Resolved ilspycmd path actually used (null if none found). */
	tool: string | null;
	toolVersion?: string;
	error?: string;
	elapsedMs: number;
}

/**
 * Lightweight .NET detection: a nonzero CLR Runtime Header (PE optional-header
 * data directory index 14). Only the PE headers are read, so a few KB suffice.
 * Mirrors the detector in hexcore-disassembler / hexcore-yara / hexcore-strings
 * so all four agree on what "managed" means.
 */
export function detectDotNet(buf: Buffer): boolean {
	try {
		if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d /* MZ */) { return false; }
		const lfanew = buf.readUInt32LE(0x3c);
		if (lfanew <= 0 || lfanew + 24 + 0x70 > buf.length) { return false; }
		if (buf.readUInt32LE(lfanew) !== 0x00004550 /* "PE\0\0" */) { return false; }
		const opt = lfanew + 24;
		const magic = buf.readUInt16LE(opt);
		const ddBase = magic === 0x20b ? opt + 112 : opt + 96;
		const clrDir = ddBase + 14 * 8;
		if (clrDir + 8 > buf.length) { return false; }
		return buf.readUInt32LE(clrDir) !== 0 && buf.readUInt32LE(clrDir + 4) !== 0;
	} catch {
		return false;
	}
}

/** Read just the PE headers of a file and test for a CLR header. */
export function isDotNetFile(filePath: string): boolean {
	let fd = -1;
	try {
		fd = fs.openSync(filePath, 'r');
		const header = Buffer.alloc(Math.min(4096, fs.fstatSync(fd).size));
		fs.readSync(fd, header, 0, header.length, 0);
		return detectDotNet(header);
	} catch {
		return false;
	} finally {
		if (fd >= 0) { try { fs.closeSync(fd); } catch { /* */ } }
	}
}

/**
 * Resolve a concrete ilspycmd executable path: explicit override, then the
 * dotnet global-tools directory, then a PATH scan. Returns null if not found.
 * A concrete path lets us spawn without a shell (no injection surface).
 */
export function locateIlspy(override?: string): string | null {
	const exe = process.platform === 'win32' ? 'ilspycmd.exe' : 'ilspycmd';
	const candidates: string[] = [];
	if (override && override.trim()) { candidates.push(override.trim()); }
	candidates.push(path.join(os.homedir(), '.dotnet', 'tools', exe));
	for (const dir of (process.env.PATH || '').split(path.delimiter)) {
		if (dir) { candidates.push(path.join(dir, exe)); }
	}
	for (const c of candidates) {
		try { if (fs.existsSync(c) && fs.statSync(c).isFile()) { return c; } } catch { /* */ }
	}
	return null;
}

function run(cmd: string, args: string[], timeoutMs: number): Promise<{ stdout: string; stderr: string; error?: Error }> {
	return new Promise(resolve => {
		execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024, windowsHide: true }, (error, stdout, stderr) => {
			resolve({ stdout: stdout || '', stderr: stderr || '', error: error || undefined });
		});
	});
}

/** Best-effort ilspycmd version string (for diagnostics / the report header). */
export async function getIlspyVersion(cmd: string, timeoutMs = 15000): Promise<string | undefined> {
	const { stdout, error } = await run(cmd, ['--version'], timeoutMs);
	if (error) { return undefined; }
	// ilspycmd prints e.g. "ilspycmd: 8.2.0.7535\nICSharpCode.Decompiler: 8.2.0.7535"
	const m = stdout.match(/ilspycmd:\s*([0-9][0-9.]*)/i);
	return m ? m[1] : stdout.split(/\r?\n/)[0].trim() || undefined;
}

/**
 * Decompile a managed assembly to C# (or disassemble to IL). Never throws --
 * every failure mode (not .NET, ilspycmd missing, tool error, timeout) returns a
 * structured result with `ok:false` and a human-readable `error`.
 */
export async function decompile(filePath: string, options: RevenantOptions = {}): Promise<RevenantResult> {
	const startedAt = Date.now();
	const mode: RevenantMode = options.mode === 'il' ? 'il' : 'csharp';
	const timeoutMs = options.timeoutMs && options.timeoutMs > 0 ? options.timeoutMs : 120000;
	const base: RevenantResult = { ok: false, mode, code: '', isDotNet: false, tool: null, elapsedMs: 0 };

	if (!fs.existsSync(filePath)) {
		return { ...base, error: `file not found: ${filePath}`, elapsedMs: Date.now() - startedAt };
	}
	const isDotNet = isDotNetFile(filePath);
	if (!isDotNet) {
		return { ...base, isDotNet: false, error: 'not a managed .NET assembly (no CLR runtime header) -- native target, use the native decompiler', elapsedMs: Date.now() - startedAt };
	}

	const tool = locateIlspy(options.ilspyPath);
	if (!tool) {
		return { ...base, isDotNet: true, error: "ilspycmd not found. Install it with 'dotnet tool install -g ilspycmd', or set hexcore.revenant.ilspyPath.", elapsedMs: Date.now() - startedAt };
	}

	// ilspycmd: positional <assembly> + flags (System.CommandLine, order-independent).
	// IL mode is --ilcode; -t selects a single type; -r adds reference dirs.
	const args: string[] = [filePath];
	if (mode === 'il') { args.push('--ilcode'); }
	if (options.type && options.type.trim()) { args.push('-t', options.type.trim()); }
	for (const r of options.referencePaths || []) { if (r) { args.push('-r', r); } }

	const toolVersion = await getIlspyVersion(tool);
	const { stdout, stderr, error } = await run(tool, args, timeoutMs);
	const elapsedMs = Date.now() - startedAt;

	if (error) {
		const reason = (error as NodeJS.ErrnoException).code === 'ETIMEDOUT'
			? `decompile timed out after ${timeoutMs}ms`
			: (stderr.trim() || error.message);
		return { ...base, isDotNet: true, tool, toolVersion, error: reason, elapsedMs };
	}
	if (!stdout.trim()) {
		return { ...base, isDotNet: true, tool, toolVersion, error: stderr.trim() || 'ilspycmd produced no output', elapsedMs };
	}
	return { ok: true, mode, code: stdout, isDotNet: true, tool, toolVersion, elapsedMs };
}

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
	/** Whether the input was detected as a managed PE or .NET single-file bundle. */
	isDotNet: boolean;
	/** Resolved backend path actually used (null if none found). */
	tool: string | null;
	/** Which backend resolved: the bundled self-contained engine (Phase 2),
	 *  a system ilspycmd (Phase 1 / dev), or an explicit config override. */
	backend?: 'override' | 'bundled' | 'ilspycmd';
	toolVersion?: string;
	error?: string;
	elapsedMs: number;
}

const SINGLE_FILE_BUNDLE_SIGNATURE = Buffer.from([
	0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
	0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
	0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
	0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
]);
// The marker lives in the native apphost image, not in the appended payload.
// Bound the synchronous IDE probe so a multi-gigabyte native file cannot stall
// the extension host merely because it lacks a CLR header.
const MAX_SINGLE_FILE_PROBE_BYTES = 64 * 1024 * 1024;

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

/** Detect the .NET apphost bundle marker and validate its manifest offset. */
export function detectSingleFileBundle(buf: Buffer, fileSize = buf.length): boolean {
	let marker = buf.indexOf(SINGLE_FILE_BUNDLE_SIGNATURE);
	while (marker >= 0) {
		if (marker >= 8) {
			const headerOffset = buf.readBigInt64LE(marker - 8);
			if (headerOffset > 0n && headerOffset < BigInt(fileSize)) { return true; }
		}
		marker = buf.indexOf(SINGLE_FILE_BUNDLE_SIGNATURE, marker + 1);
	}
	return false;
}

/** Scan a file in bounded chunks for the .NET single-file bundle marker. */
export function isSingleFileBundle(filePath: string): boolean {
	let fd = -1;
	try {
		fd = fs.openSync(filePath, 'r');
		const fileSize = fs.fstatSync(fd).size;
		if (fileSize < SINGLE_FILE_BUNDLE_SIGNATURE.length + 8) { return false; }
		const scanSize = Math.min(fileSize, MAX_SINGLE_FILE_PROBE_BYTES);

		const chunkSize = 1024 * 1024;
		const overlapSize = SINGLE_FILE_BUNDLE_SIGNATURE.length + 7;
		let overlap = Buffer.alloc(0);
		let position = 0;
		while (position < scanSize) {
			const count = Math.min(chunkSize, scanSize - position);
			const chunk = Buffer.allocUnsafe(count);
			const bytesRead = fs.readSync(fd, chunk, 0, count, position);
			if (bytesRead <= 0) { break; }
			const window = overlap.length > 0
				? Buffer.concat([overlap, chunk.subarray(0, bytesRead)])
				: chunk.subarray(0, bytesRead);
			if (detectSingleFileBundle(window, fileSize)) { return true; }
			overlap = Buffer.from(window.subarray(Math.max(0, window.length - overlapSize)));
			position += bytesRead;
		}
		return false;
	} catch {
		return false;
	} finally {
		if (fd >= 0) { try { fs.closeSync(fd); } catch { /* */ } }
	}
}

/** Test for either a CLR-header assembly or a native .NET single-file apphost. */
export function isDotNetFile(filePath: string): boolean {
	let fd = -1;
	try {
		fd = fs.openSync(filePath, 'r');
		const header = Buffer.alloc(Math.min(4096, fs.fstatSync(fd).size));
		fs.readSync(fd, header, 0, header.length, 0);
		return detectDotNet(header) || isSingleFileBundle(filePath);
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

/** Platform/arch folder for the bundled engine, e.g. win-x64 / linux-x64 / osx-arm64. */
export function platformDir(): string {
	const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
	const o = process.platform === 'win32' ? 'win' : process.platform === 'darwin' ? 'osx' : 'linux';
	return `${o}-${arch}`;
}

/**
 * Locate the bundled self-contained Revenant engine (Phase 2) -- the portable
 * binary shipped with the extension so the user needs no .NET install and no
 * downloads. Looked up under the extension's `bin/<plat>/` (sibling of `out/`).
 * Returns null if not shipped (then we fall back to a system ilspycmd in dev).
 */
export function locateBundledEngine(): string | null {
	const exe = process.platform === 'win32' ? 'revenant-engine.exe' : 'revenant-engine';
	const candidates = [
		path.join(__dirname, '..', 'bin', platformDir(), exe),
		path.join(__dirname, '..', 'bin', exe),
	];
	for (const c of candidates) {
		try { if (fs.existsSync(c) && fs.statSync(c).isFile()) { return c; } } catch { /* */ }
	}
	return null;
}

/**
 * Resolve the decompiler backend in priority order: explicit config override ->
 * bundled self-contained engine (Phase 2) -> system ilspycmd (Phase 1 / dev).
 * Both binaries take the same CLI, so callers build args identically.
 */
export function locateBackend(override?: string): { path: string; kind: 'override' | 'bundled' | 'ilspycmd' } | null {
	if (override && override.trim()) {
		const o = override.trim();
		try { if (fs.existsSync(o) && fs.statSync(o).isFile()) { return { path: o, kind: 'override' }; } } catch { /* */ }
	}
	const bundled = locateBundledEngine();
	if (bundled) { return { path: bundled, kind: 'bundled' }; }
	const ilspy = locateIlspy();
	if (ilspy) { return { path: ilspy, kind: 'ilspycmd' }; }
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
	// Both backends print a "<name>: <ver>" line:
	//   ilspycmd:        "ilspycmd: 8.2.0.7535\nICSharpCode.Decompiler: 8.2.0.7535"
	//   bundled engine:  "revenant-engine: 0.4.0\nICSharpCode.Decompiler: 10.1.0.8386"
	const m = stdout.match(/(?:revenant-engine|ilspycmd|ICSharpCode\.Decompiler):\s*([0-9][0-9.]*)/i);
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
		return { ...base, isDotNet: false, error: 'not a managed .NET assembly or single-file bundle -- native target, use the native decompiler', elapsedMs: Date.now() - startedAt };
	}

	const backend = locateBackend(options.ilspyPath);
	if (!backend) {
		return { ...base, isDotNet: true, error: "no decompiler backend found. Ship the bundled revenant-engine binary, install ilspycmd ('dotnet tool install -g ilspycmd'), or set hexcore.revenant.ilspyPath.", elapsedMs: Date.now() - startedAt };
	}
	const tool = backend.path;
	if (backend.kind === 'ilspycmd' && !detectDotNet(readFileHeader(filePath))) {
		return { ...base, isDotNet: true, tool, backend: backend.kind, error: 'single-file bundles require the bundled Revenant engine (the ilspycmd fallback cannot decompile the apphost directly)', elapsedMs: Date.now() - startedAt };
	}

	// Both backends share the same CLI: positional <assembly> + flags. IL mode is
	// --ilcode; -t selects a single type; -r adds reference dirs.
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
		return { ...base, isDotNet: true, tool, backend: backend.kind, toolVersion, error: reason, elapsedMs };
	}
	if (!stdout.trim()) {
		return { ...base, isDotNet: true, tool, backend: backend.kind, toolVersion, error: stderr.trim() || 'decompiler produced no output', elapsedMs };
	}
	return { ok: true, mode, code: stdout, isDotNet: true, tool, backend: backend.kind, toolVersion, elapsedMs };
}

function readFileHeader(filePath: string): Buffer {
	let fd = -1;
	try {
		fd = fs.openSync(filePath, 'r');
		const header = Buffer.alloc(Math.min(4096, fs.fstatSync(fd).size));
		fs.readSync(fd, header, 0, header.length, 0);
		return header;
	} catch {
		return Buffer.alloc(0);
	} finally {
		if (fd >= 0) { try { fs.closeSync(fd); } catch { /* */ } }
	}
}

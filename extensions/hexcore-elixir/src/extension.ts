import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as cp from 'child_process';

interface EmulatorConfig {
	arch: 'x86_64';
	maxInstructions: number;
	verbose?: boolean;
}

interface StopReason {
	kind: 'Exit' | 'InsnLimit' | 'Error' | 'User';
	address: bigint;
	instructionsExecuted: number;
	message: string;
}

interface ApiCall {
	address: bigint;
	name: string;
	module: string;
	returnValue: bigint;
	arguments: bigint[];
}

interface ElixirNative {
	getVersion(): string;
	isAvailable?: boolean;
	loadError?: string;
	Emulator: new (config: EmulatorConfig) => {
		load(data: Buffer): bigint;
		run(start: bigint, end: bigint): StopReason;
		stop(): void;
		getApiCalls(): ApiCall[];
		getApiCallCount(): number;
		stalkerFollow(): void;
		stalkerUnfollow(): void;
		stalkerBlockCount(): number;
		stalkerExportDrcov(): Buffer;
		snapshotSave(): Buffer;
		snapshotRestore(blob: Buffer): void;
		dispose(): void;
		readonly isDisposed: boolean;
	};
}

let elixir: ElixirNative | null = null;
let loadError: Error | null = null;
let output: vscode.OutputChannel;

function loadNative(): ElixirNative | null {
	if (elixir) {
		return elixir;
	}
	try {
		elixir = require(path.join(__dirname, '..', 'index.js'));
		return elixir;
	} catch (err) {
		loadError = err as Error;
		return null;
	}
}

function requireNative(): ElixirNative {
	const n = loadNative();
	if (!n || n.isAvailable === false || !n.Emulator) {
		throw new Error(
			`HexCore Elixir native binding unavailable: ${loadError?.message ?? n?.loadError ?? 'Emulator class missing'}`
		);
	}
	return n;
}

function bigintToString(v: bigint): string {
	return '0x' + v.toString(16);
}

const PE_MACHINE_LABELS: Record<number, string> = {
	0x014c: 'x86 (PE32, IMAGE_FILE_MACHINE_I386)',
	0x0200: 'ia64 (IMAGE_FILE_MACHINE_IA64)',
	0x8664: 'x86_64 (PE32+, IMAGE_FILE_MACHINE_AMD64)',
	0x01c0: 'ARM (IMAGE_FILE_MACHINE_ARM)',
	0xaa64: 'ARM64 (IMAGE_FILE_MACHINE_ARM64)',
	0x01c4: 'ARM Thumb-2 (IMAGE_FILE_MACHINE_ARMNT)'
};

// Matches the preflight in worker/emulateWorker.js — duplicated intentionally
// for the in-process paths (snapshotRoundTripHeadless etc) that don't fork.
function preflightPeMachine(data: Buffer, binaryPath: string): void {
	if (data.length < 0x40) {
		throw new Error(`Binary too small to be a PE (${data.length} bytes): ${binaryPath}`);
	}
	if (data[0] !== 0x4d || data[1] !== 0x5a) {
		throw new Error(`Not a PE file (missing MZ magic): ${binaryPath}`);
	}
	const lfanew = data.readUInt32LE(0x3c);
	if (lfanew + 24 > data.length) {
		throw new Error(`Invalid PE header offset 0x${lfanew.toString(16)}: ${binaryPath}`);
	}
	if (data.readUInt32LE(lfanew) !== 0x00004550) {
		throw new Error(`Not a PE file (missing PE\\0\\0 signature): ${binaryPath}`);
	}
	const machine = data.readUInt16LE(lfanew + 4);
	if (machine !== 0x8664) {
		const label = PE_MACHINE_LABELS[machine] ?? `unknown (0x${machine.toString(16)})`;
		throw new Error(
			`Elixir requires x86_64 (PE32+, IMAGE_FILE_MACHINE_AMD64=0x8664); ` +
			`got ${label} — ${path.basename(binaryPath)}. ` +
			`Rebuild the binary as 64-bit or use the legacy debugger (hexcore.emulator="debugger").`
		);
	}
}

/**
 * Locate a system Node.js binary without ACG (Arbitrary Code Guard) in its PE header.
 *
 * The VS Code / Electron Extension Host has ACG enabled, which blocks
 * VirtualAlloc(PAGE_EXECUTE_READWRITE). Unicorn's TCG JIT needs RWX pages
 * to emit generated machine code — calling uc_emu_start in the host
 * crashes with STATUS_ACCESS_VIOLATION (0xC0000005). System Node.exe
 * binaries (installed via nvm, nodejs.org installer, etc.) do NOT have ACG,
 * so forking the emulation worker through one of them works.
 *
 * Same pattern hexcore-debugger uses for pe32WorkerClient.ts — see that file
 * for the original implementation this was copied from.
 */
function findSystemNode(): string | null {
	const candidates: string[] = [];

	const nvmHome = process.env.NVM_HOME;
	if (nvmHome) {
		try {
			const dirs = fs.readdirSync(nvmHome).filter(d => {
				try { return fs.statSync(path.join(nvmHome, d, 'node.exe')).isFile(); } catch { return false; }
			});
			for (const d of dirs) {
				candidates.push(path.join(nvmHome, d, 'node.exe'));
			}
		} catch { /* ignore */ }
	}

	const nvmSymlink = process.env.NVM_SYMLINK;
	if (nvmSymlink) {
		candidates.push(path.join(nvmSymlink, 'node.exe'));
	}

	candidates.push('C:\\Program Files\\nodejs\\node.exe');
	candidates.push('C:\\Program Files (x86)\\nodejs\\node.exe');

	const binaryNames = process.platform === 'win32' ? ['node.exe'] : ['node'];
	const pathDirs = (process.env.PATH || '').split(path.delimiter);
	for (const dir of pathDirs) {
		if (!dir) continue;
		for (const name of binaryNames) {
			const candidate = path.join(dir, name);
			if (!candidates.includes(candidate)) {
				candidates.push(candidate);
			}
		}
	}

	if (process.platform !== 'win32') {
		candidates.push(
			'/usr/local/bin/node',
			'/usr/bin/node',
			'/opt/homebrew/bin/node', // macOS Apple Silicon Homebrew
		);
	}

	for (const candidate of candidates) {
		try {
			if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
				if (path.resolve(candidate) !== path.resolve(process.execPath)) {
					return candidate;
				}
			}
		} catch { /* ignore */ }
	}

	return null;
}

interface WorkerEmulateResult {
	ok: true;
	kind: 'emulate';
	entry: string;
	stopReason: { kind: string; address: string; instructionsExecuted: number; message: string };
	apiCallCount: number;
	apiCalls: Array<{ address: string | null; name: string | null; module: string | null; returnValue: string | null }>;
	apiCallsPath?: string | null;
	apiCallsTotal?: number;
}

interface WorkerStalkerResult {
	ok: true;
	kind: 'stalker';
	entry: string;
	stopReason: { kind: string; address: string; instructionsExecuted: number; message: string };
	blockCount: number;
	drcovBase64: string;
}

interface WorkerFailure {
	ok: false;
	error: string;
}

type WorkerResult = WorkerEmulateResult | WorkerStalkerResult | WorkerFailure;

// Oracle Hook opaque config shape — passed through to the worker verbatim.
interface OracleWorkerConfig {
	pythiaRepoPath: string;
	pythiaNodeBin?: string;
	pythiaSpawnArgs?: string[];
	pauseTimeoutMs?: number;
	triggers: Array<{ kind: string; value: string; reason?: string }>;
}

function runInWorker(
	op: 'emulate' | 'stalker' | 'oracle',
	binaryPath: string,
	maxInstructions: number,
	verbose: boolean,
	timeoutMs: number,
	apiCallsOverflowPath?: string,
	apiCallsOverflowDir?: string,
	oracle?: OracleWorkerConfig,
): Promise<WorkerResult> {
	return new Promise((resolve, reject) => {
		const workerPath = path.join(__dirname, '..', 'worker', 'emulateWorker.js');
		if (!fs.existsSync(workerPath)) {
			reject(new Error(`Worker script not found: ${workerPath}`));
			return;
		}

		const systemNode = findSystemNode();
		const spawnExecPath = systemNode ?? process.execPath;
		const env = { ...process.env };
		if (!systemNode) {
			env.ELECTRON_RUN_AS_NODE = '1';
			if (process.platform === 'win32') {
				output.appendLine('[elixir] WARNING: no system Node.exe found — falling back to Electron with ELECTRON_RUN_AS_NODE=1. Emulation may crash due to ACG. Install Node.js from nodejs.org to fix.');
			} else {
				output.appendLine('[elixir] INFO: no system Node binary found — falling back to Electron with ELECTRON_RUN_AS_NODE=1.');
			}
		} else {
			output.appendLine(`[elixir] spawning worker via system Node: ${systemNode}`);
		}

		const spawnStart = Date.now();
		output.appendLine(`[elixir] cp.fork ${workerPath} execPath=${spawnExecPath}`);
		const worker = cp.fork(workerPath, [], {
			stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
			execPath: spawnExecPath,
			env,
			cwd: path.join(__dirname, '..')
		});
		output.appendLine(`[elixir] cp.fork returned pid=${worker.pid ?? 'unknown'} connected=${worker.connected} after ${Date.now() - spawnStart}ms`);

		let result: WorkerResult | null = null;
		let settled = false;

		const timer = setTimeout(() => {
			if (settled) return;
			settled = true;
			output.appendLine(`[elixir] worker timed out after ${timeoutMs}ms — killing`);
			try { worker.kill('SIGTERM'); } catch { /* ignore */ }
			reject(new Error(`Elixir worker timed out after ${timeoutMs}ms`));
		}, timeoutMs);
		(timer as unknown as { unref?: () => void }).unref?.();

		worker.on('message', (msg) => {
			result = msg as WorkerResult;
		});

		worker.stderr?.on('data', (data: Buffer) => {
			const lines = data.toString().split('\n').filter(l => l.trim());
			for (const line of lines) {
				output.appendLine(`[elixir-worker] ${line}`);
			}
		});

		worker.stdout?.on('data', (data: Buffer) => {
			const lines = data.toString().split('\n').filter(l => l.trim());
			for (const line of lines) {
				output.appendLine(`[elixir-worker/stdout] ${line}`);
			}
		});

		worker.on('exit', (code, signal) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			output.appendLine(`[elixir] worker exited code=${code} signal=${signal}`);
			if (result && result.ok) {
				resolve(result);
			} else if (result && !result.ok) {
				reject(new Error(`Elixir worker reported failure: ${result.error}`));
			} else if (code === 0) {
				reject(new Error('Elixir worker exited cleanly but sent no result'));
			} else {
				reject(new Error(`Elixir worker died without result: code=${code} signal=${signal}`));
			}
		});

		worker.on('error', (err) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			output.appendLine(`[elixir] worker spawn error: ${err.message}\n  stack: ${err.stack ?? '(no stack)'}`);
			reject(err);
		});
		worker.on('disconnect', () => {
			output.appendLine(`[elixir] worker IPC channel DISCONNECTED at ${Date.now() - spawnStart}ms (pid=${worker.pid ?? 'unknown'})`);
		});

		// worker.send is async — pass a callback so we can observe the actual
		// delivery. The 10s timeout in the worker fires if no message lands in
		// its process.on('message') listener, which can happen when the IPC
		// channel is silently broken (stale child from prior run, etc.).
		const sendMessage = { op, binaryPath, maxInstructions, verbose, apiCallsOverflowPath, apiCallsOverflowDir, oracle };
		const sendResult = worker.send(sendMessage, undefined, {}, (err) => {
			if (err) {
				output.appendLine(`[elixir] worker.send CALLBACK error: ${err.message}`);
			} else {
				output.appendLine(`[elixir] worker.send delivered after ${Date.now() - spawnStart}ms (pid=${worker.pid ?? 'unknown'})`);
			}
		});
		output.appendLine(`[elixir] worker.send() synchronous returned=${sendResult} connected=${worker.connected} killed=${worker.killed}`);
	});
}

function serializeApiCall(c: ApiCall & { args?: bigint[] }) {
	const argList: bigint[] | undefined = c.arguments ?? c.args;
	return {
		address: c.address !== undefined ? bigintToString(c.address) : null,
		name: c.name,
		module: c.module,
		returnValue: c.returnValue !== undefined ? bigintToString(c.returnValue) : null,
		arguments: argList ? argList.map(bigintToString) : []
	};
}

function serializeStopReason(r: StopReason) {
	return {
		kind: r.kind,
		address: bigintToString(r.address),
		instructionsExecuted: r.instructionsExecuted,
		message: r.message
	};
}

export function activate(context: vscode.ExtensionContext): void {
	output = vscode.window.createOutputChannel('HexCore Elixir');
	context.subscriptions.push(output);

	const emulator = vscode.workspace.getConfiguration('hexcore').get<string>('emulator', 'azoth');
	if (emulator !== 'azoth' && emulator !== 'both') {
		output.appendLine(`[elixir] activation skipped — hexcore.emulator="${emulator}" (set hexcore.emulator="azoth" or "both" to enable Project Azoth)`);
		context.subscriptions.push(
			vscode.workspace.onDidChangeConfiguration((e) => {
				if (e.affectsConfiguration('hexcore.emulator')) {
					vscode.window.showInformationMessage(
						'HexCore emulator setting changed. Reload the window to apply.',
						'Reload Window'
					).then((choice) => {
						if (choice === 'Reload Window') {
							vscode.commands.executeCommand('workbench.action.reloadWindow');
						}
					});
				}
			})
		);
		return;
	}

	context.subscriptions.push(
		vscode.workspace.onDidChangeConfiguration((e) => {
			if (e.affectsConfiguration('hexcore.emulator')) {
				vscode.window.showInformationMessage(
					'HexCore emulator setting changed. Reload the window to apply.',
					'Reload Window'
				).then((choice) => {
					if (choice === 'Reload Window') {
						vscode.commands.executeCommand('workbench.action.reloadWindow');
					}
				});
			}
		})
	);

	const native = loadNative();
	if (native && native.isAvailable !== false && native.Emulator) {
		output.appendLine(`[elixir] native binding loaded — engine version ${native.getVersion()}`);
	} else {
		output.appendLine(
			`[elixir] native binding unavailable: ${loadError?.message ?? native?.loadError ?? 'unknown'}`
		);
	}

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.elixir.version', () => {
			const n = loadNative();
			if (!n || n.isAvailable === false) {
				vscode.window.showErrorMessage(
					`HexCore Elixir: native binding unavailable (${loadError?.message ?? n?.loadError ?? 'unknown'})`
				);
				return;
			}
			const v = n.getVersion();
			vscode.window.showInformationMessage(`HexCore Elixir v${v} — Project Azoth native bridge online.`);
			output.appendLine(`[elixir] getVersion() → ${v}`);
			output.show(true);
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.elixir.smokeTestHeadless', (args: HeadlessArgs = {}) => {
			const n = loadNative();
			const result = {
				ok: !!(n && n.isAvailable !== false && n.Emulator),
				version: n && n.isAvailable !== false ? n.getVersion() : null,
				loadError: loadError?.message ?? n?.loadError ?? null,
				platform: process.platform,
				arch: process.arch,
				codename: 'Project Azoth',
				surface: n && n.Emulator
					? ['getVersion', 'Emulator', 'Interceptor', 'Stalker', 'snapshotSave', 'snapshotRestore']
					: ['getVersion']
			};
			writeJsonResult(args, result);
			return result;
		})
	);

	function writeJsonResult(opts: HeadlessArgs, result: unknown): void {
		const outPath = opts?.output?.path;
		if (!outPath) {
			return;
		}
		fs.mkdirSync(path.dirname(outPath), { recursive: true });
		fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
		output.appendLine(`[elixir] wrote ${outPath}`);
	}

	function resolveBinary(args: HeadlessArgs, command: string): string {
		const file = args?.file ?? args?.binaryPath;
		if (!file || typeof file !== 'string') {
			throw new Error(`${command}: requires a "file" argument (binary path)`);
		}
		return file;
	}

	context.subscriptions.push(
		vscode.commands.registerCommand(
			'hexcore.elixir.emulateHeadless',
			async (args: HeadlessArgs = {}) => {
				// Must run in a forked system Node.exe worker — see findSystemNode() comment
				// above for the ACG-reasoning. In-host execution of uc_emu_start crashes
				// the Extension Host with STATUS_ACCESS_VIOLATION.
				const file = resolveBinary(args, 'hexcore.elixir.emulateHeadless');
				const maxInstructions = args.maxInstructions ?? 1_000_000;
				const outPath = args?.output?.path;
				// Containment layer 1 (host): derive the apiCalls companion strictly
				// inside the same directory as outPath, stripping any path
				// components a job file could smuggle via output.path. The basename
				// is re-extracted so traversal attempts like
				// output.path="/safe/../../etc/passwd" collapse to /etc/passwd's
				// basename "passwd" inside /safe/.. resolved root. CWE-22.
				let overflowPath: string | undefined;
				let overflowDir: string | undefined;
				if (outPath) {
					const resolvedOut = path.resolve(outPath);
					overflowDir = path.dirname(resolvedOut);
					const base = path.basename(resolvedOut).replace(/\.json$/i, '');
					const candidate = path.resolve(overflowDir, base + '.apicalls.json');
					// Defense-in-depth: the resolved companion MUST sit inside
					// overflowDir. path.resolve normalizes "..", so a candidate
					// that doesn't start with overflowDir + sep means something
					// rewrote the basename to escape (shouldn't happen with
					// basename(), but we guard anyway).
					const sep = path.sep;
					if (candidate === overflowDir || candidate.startsWith(overflowDir + sep)) {
						overflowPath = candidate;
					} else {
						throw new Error(
							`apiCalls overflow path escapes output directory: ${candidate} not under ${overflowDir}`
						);
					}
				}
				// Project Pythia Oracle Hook (v3.9.0-preview.oracle.azoth). When
				// args.oracle is provided, the worker delegates to oracleAdapter
				// which spawns Pythia, registers breakpoints, drives the pause/
				// resume loop against the live Elixir engine, and returns a
				// session summary alongside the usual emulation result.
				const oracleArg = (args as HeadlessArgs & { oracle?: OracleWorkerConfig }).oracle;
				const workerOp: 'emulate' | 'oracle' = oracleArg && Array.isArray(oracleArg.triggers) && oracleArg.pythiaRepoPath
					? 'oracle'
					: 'emulate';

				output.appendLine(
					`[elixir] emulateHeadless ${path.basename(file)} — delegating to worker ` +
					`(op=${workerOp}, maxInstructions=${maxInstructions}` +
					(workerOp === 'oracle' ? `, triggers=${oracleArg!.triggers.length}` : '') +
					`)`,
				);
				const workerResult = await runInWorker(workerOp, file, maxInstructions, !!args.verbose, 600_000, overflowPath, overflowDir, oracleArg);
				if (!workerResult.ok) {
					throw new Error(`Elixir emulation failed: ${workerResult.error}`);
				}
				if (workerOp === 'emulate') {
					if (workerResult.kind !== 'emulate') {
						throw new Error('Unexpected worker result kind for emulate op');
					}
					const emuResult = workerResult as WorkerEmulateResult;
					const result = {
						file,
						entry: emuResult.entry,
						stopReason: emuResult.stopReason,
						apiCallCount: emuResult.apiCallCount,
						apiCalls: emuResult.apiCalls,
						apiCallsPath: emuResult.apiCallsPath ?? null,
						apiCallsTotal: emuResult.apiCallsTotal ?? emuResult.apiCalls.length,
					};
					output.appendLine(
						`[elixir] run → ${result.stopReason.kind} @${result.stopReason.address} ` +
						`(${result.stopReason.instructionsExecuted} insns, ${result.apiCallCount} api calls)`,
					);
					writeJsonResult(args, result);
					return result;
				}
				// Oracle variant — worker result kind is 'oracle' with the oracle block.
				const oracleResult = workerResult as unknown as {
					ok: true;
					kind: 'oracle';
					entry: string;
					stopReason: { kind: string; address: string; instructionsExecuted: number; message: string };
					oracle: {
						pauseCount: number;
						patchesApplied: number;
						totalCostUsd: number;
						decisions: unknown[];
					};
					apiCallCount: number;
					apiCalls: unknown[];
					apiCallsTotal: number;
				};
				const result = {
					file,
					entry: oracleResult.entry,
					stopReason: oracleResult.stopReason,
					apiCallCount: oracleResult.apiCallCount,
					apiCalls: oracleResult.apiCalls,
					apiCallsTotal: oracleResult.apiCallsTotal,
					oracle: oracleResult.oracle,
				};
				output.appendLine(
					`[elixir] oracle run → pauses=${oracleResult.oracle.pauseCount} ` +
					`patches=${oracleResult.oracle.patchesApplied} ` +
					`cost=$${oracleResult.oracle.totalCostUsd.toFixed(4)} ` +
					`(${result.apiCallCount} api calls)`,
				);
				writeJsonResult(args, result);
				return result;
			}
		)
	);

	context.subscriptions.push(
		vscode.commands.registerCommand(
			'hexcore.elixir.stalkerDrcovHeadless',
			async (args: HeadlessArgs = {}) => {
				const file = resolveBinary(args, 'hexcore.elixir.stalkerDrcovHeadless');
				const maxInstructions = args.maxInstructions ?? 1_000_000;
				output.appendLine(`[elixir] stalkerDrcovHeadless ${path.basename(file)} — delegating to worker`);
				const workerResult = await runInWorker('stalker', file, maxInstructions, false, 600_000);
				if (!workerResult.ok) {
					throw new Error(`Elixir stalker failed: ${workerResult.error}`);
				}
				if (workerResult.kind !== 'stalker') {
					throw new Error('Unexpected worker result kind for stalker op');
				}
				const drcov = Buffer.from(workerResult.drcovBase64, 'base64');
				if (args.output?.path) {
					const drcovOut = args.output.path.endsWith('.drcov')
						? args.output.path
						: args.output.path.replace(/\.json$/i, '.drcov');
					fs.mkdirSync(path.dirname(drcovOut), { recursive: true });
					fs.writeFileSync(drcovOut, drcov);
					output.appendLine(`[elixir] wrote ${drcovOut}`);
				}
				const result = {
					file,
					entry: workerResult.entry,
					stopReason: workerResult.stopReason,
					blockCount: workerResult.blockCount,
					drcovBytes: drcov.length
				};
				output.appendLine(
					`[elixir] stalker → ${result.blockCount} blocks, ${result.drcovBytes} bytes drcov`
				);
				writeJsonResult(args, result);
				return result;
			}
		)
	);

	context.subscriptions.push(
		vscode.commands.registerCommand(
			'hexcore.elixir.snapshotRoundTripHeadless',
			(args: HeadlessArgs = {}) => {
				const n = requireNative();
				const file = resolveBinary(args, 'hexcore.elixir.snapshotRoundTripHeadless');
				const data = fs.readFileSync(file);
				preflightPeMachine(data, file);
				const emu = new n.Emulator({ arch: 'x86_64', maxInstructions: 100_000, verbose: false });
				try {
					const entry = emu.load(data);
					const blob = emu.snapshotSave();
					emu.snapshotRestore(blob);
					output.appendLine(`[elixir] snapshotRoundTripHeadless — ${blob.length} bytes, entry=${bigintToString(entry)}`);
					const result = {
						file,
						entry: bigintToString(entry),
						snapshotBytes: blob.length,
						restored: true
					};
					writeJsonResult(args, result);
					return result;
				} finally {
					emu.dispose();
				}
			}
		)
	);
}

interface HeadlessArgs {
	file?: string;
	binaryPath?: string;
	output?: { path?: string };
	maxInstructions?: number;
	verbose?: boolean;
	quiet?: boolean;
}

export function deactivate(): void {
	elixir = null;
}

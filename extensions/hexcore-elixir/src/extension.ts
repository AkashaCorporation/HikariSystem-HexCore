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

	const pathDirs = (process.env.PATH || '').split(path.delimiter);
	for (const dir of pathDirs) {
		if (!dir) continue;
		const candidate = path.join(dir, 'node.exe');
		if (!candidates.includes(candidate)) {
			candidates.push(candidate);
		}
	}

	candidates.push('/usr/local/bin/node', '/usr/bin/node');

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

function runInWorker(op: 'emulate' | 'stalker', binaryPath: string, maxInstructions: number, verbose: boolean, timeoutMs: number): Promise<WorkerResult> {
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
			output.appendLine('[elixir] WARNING: no system Node.exe found — falling back to Electron with ELECTRON_RUN_AS_NODE=1. Emulation may crash due to ACG. Install Node.js from nodejs.org to fix.');
		} else {
			output.appendLine(`[elixir] spawning worker via system Node: ${systemNode}`);
		}

		const worker = cp.fork(workerPath, [], {
			stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
			execPath: spawnExecPath,
			env,
			cwd: path.join(__dirname, '..')
		});

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
			output.appendLine(`[elixir] worker spawn error: ${err.message}`);
			reject(err);
		});

		worker.send({ op, binaryPath, maxInstructions, verbose });
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
	if (emulator !== 'azoth') {
		output.appendLine(`[elixir] activation skipped — hexcore.emulator="${emulator}" (set hexcore.emulator="azoth" to enable Project Azoth)`);
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
		vscode.commands.registerCommand('hexcore.elixir.smokeTestHeadless', () => {
			const n = loadNative();
			return {
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
				output.appendLine(`[elixir] emulateHeadless ${path.basename(file)} — delegating to worker (maxInstructions=${maxInstructions})`);
				const workerResult = await runInWorker('emulate', file, maxInstructions, !!args.verbose, 600_000);
				if (!workerResult.ok) {
					throw new Error(`Elixir emulation failed: ${workerResult.error}`);
				}
				if (workerResult.kind !== 'emulate') {
					throw new Error('Unexpected worker result kind for emulate op');
				}
				const emuResult = workerResult as WorkerEmulateResult;
				const result = {
					file,
					entry: emuResult.entry,
					stopReason: emuResult.stopReason,
					apiCallCount: emuResult.apiCallCount,
					apiCalls: emuResult.apiCalls
				};
				output.appendLine(
					`[elixir] run → ${result.stopReason.kind} @${result.stopReason.address} ` +
					`(${result.stopReason.instructionsExecuted} insns, ${result.apiCallCount} api calls)`
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

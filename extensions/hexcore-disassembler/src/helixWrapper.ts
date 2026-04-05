/*---------------------------------------------------------------------------------------------
 *  HexCore Helix Wrapper
 *  TypeScript wrapper para o módulo nativo hexcore-helix (NAPI-RS).
 *  Segue o padrão dos wrappers Remill/Rellic (v3.7.0).
 *---------------------------------------------------------------------------------------------*/

import * as path from 'path';
import { Worker } from 'worker_threads';
import { loadNativeModule } from 'hexcore-common';
import type { ArchitectureConfig } from './capstoneWrapper';
import { mapCapstoneToHelix, isHelixArchSupported, HelixArch, type HelixArchValue } from './helixArchMapper';

// ---------------------------------------------------------------------------
// Interfaces do módulo nativo hexcore-helix
// ---------------------------------------------------------------------------

interface HelixDecompileResult {
	source: string;
	functionName: string;
	entryAddress: string;
	blockCount: number;
	instructionCount: number;
	cfgBuffer: Buffer | null;
	astBuffer: Buffer | null;
}

interface PipelineMetricsNative {
	totalMs: number;
	instructionsDecoded: number;
	functionsRecovered: number;
	throughput: number;
	warningCount: number;
}

interface HelixEngineInstance {
	version(): string;
	architecture(): string;
	decompileIr(irText: string): HelixDecompileResult;
	decompileIrWithMetrics(irText: string): [HelixDecompileResult, PipelineMetricsNative];
	decompile(data: Buffer, baseAddress: bigint, entryAddress: bigint): HelixDecompileResult;
	dispose(): void;
	readonly isDisposed: boolean;
	/** v3.7.5 P3: Set variable rename in the C AST pipeline (old → new).
	 *  Applied during CAstOptimizer walk, before CAstPrinter serialization. */
	addVariableRename?(oldName: string, newName: string): void;
	/** v3.7.5 P3: Clear all variable renames from the engine. */
	clearVariableRenames?(): void;
}

interface HelixModule {
	HelixEngine: new (arch: number) => HelixEngineInstance;
	Architecture: Record<string, number>;
}

// ---------------------------------------------------------------------------
// Interfaces exportadas
// ---------------------------------------------------------------------------

/** Resultado normalizado exposto para o resto da extensão */
export interface HelixResult {
	success: boolean;
	source: string;
	functionName: string;
	entryAddress: string;
	blockCount: number;
	instructionCount: number;
	cfgBuffer: Buffer | null;
	astBuffer: Buffer | null;
	error: string;
}

/** Pipeline performance metrics */
export interface PipelineMetrics {
	totalMs: number;
	instructionsDecoded: number;
	functionsRecovered: number;
	throughput: number;
	warningCount: number;
}

/** Resultado com métricas de pipeline */
export interface HelixResultWithMetrics {
	result: HelixResult;
	metrics: PipelineMetrics;
}

/** Threshold em bytes acima do qual usamos worker thread */
const ASYNC_THRESHOLD = 65536; // 64KB

/**
 * Wrapper para o módulo nativo hexcore-helix.
 *
 * Gerencia o ciclo de vida do HelixEngine (criação sob demanda,
 * reutilização por arquitetura, cleanup no dispose) e expõe uma
 * API simplificada para decompilação.
 *
 * Degrada graciosamente quando o módulo nativo não está disponível.
 */
export class HelixWrapper {
	private module?: HelixModule;
	private engine?: HelixEngineInstance;
	private currentArch?: HelixArchValue;
	private available: boolean = false;
	private lastError?: string;
	private modulePaths: string[] = [];

	constructor() {
		this.tryLoad();
	}

	private tryLoad(): void {
		this.modulePaths = [
			path.join(__dirname, '..', '..', 'hexcore-helix'),
			path.join(__dirname, '..', '..', '..', 'hexcore-helix'),
		];

		const result = loadNativeModule<HelixModule>({
			moduleName: 'hexcore-helix',
			candidatePaths: this.modulePaths,
		});

		if (result.module) {
			this.module = result.module;
			this.available = true;
		} else {
			this.lastError = result.errorMessage;
			this.available = false;
			console.warn('hexcore-helix not available:', this.lastError);
		}
	}

	isAvailable(): boolean {
		return this.available;
	}

	getVersion(): string | undefined {
		return this.engine?.version() ?? (this.available ? this.ensureEngine()?.version() : undefined);
	}

	getLastError(): string | undefined {
		return this.lastError;
	}

	/**
	 * v3.7.5 P3: Check if the native module supports addVariableRename.
	 * Returns true when the C++ side has the rename map + AST walk pass.
	 */
	supportsVariableRenames(): boolean {
		if (!this.available) { return false; }
		try {
			const engine = this.ensureEngine();
			return !!engine && typeof engine.addVariableRename === 'function';
		} catch {
			return false;
		}
	}

	/**
	 * Verifica se uma arquitetura Capstone é suportada pelo Helix.
	 */
	isArchSupported(arch: ArchitectureConfig): boolean {
		return isHelixArchSupported(arch);
	}

	/**
	 * Garante que existe uma instância do engine para a arquitetura dada.
	 * Reutiliza a instância existente se a arquitetura não mudou.
	 * Fecha a instância anterior se a arquitetura mudou.
	 */
	private ensureEngine(arch: HelixArchValue = HelixArch.X86_64): HelixEngineInstance | undefined {
		if (!this.module) { return undefined; }

		if (this.engine && !this.engine.isDisposed && this.currentArch === arch) {
			return this.engine;
		}

		// Fechar instância anterior se existir
		if (this.engine && !this.engine.isDisposed) {
			this.engine.dispose();
		}

		this.engine = new this.module.HelixEngine(arch);
		this.currentArch = arch;
		return this.engine;
	}

	/**
	 * Decompila LLVM IR text para pseudo-C usando o engine Helix.
	 * Usa worker thread para IR > 64KB para não bloquear a UI.
	 *
	 * Note: For IR decompilation, x86 (32-bit) is promoted to x86_64
	 * because Remill IR already encodes the architecture in the IR text,
	 * and the Helix engine uses x86_64 backend for both x86 variants.
	 */
	async decompileIr(irText: string, arch: ArchitectureConfig = 'x64', options?: { optimizeIR?: boolean; useCastLayer?: boolean; variableRenames?: Array<{ oldName: string; newName: string }> }): Promise<HelixResult> {
		if (!this.available || !this.module) {
			return this.errorResult('hexcore-helix is not available');
		}

		// Promote x86 → x64 for IR decompilation (Remill IR is arch-agnostic)
		const effectiveArch: ArchitectureConfig = arch === 'x86' ? 'x64' : arch;
		const mapping = mapCapstoneToHelix(effectiveArch);
		if (!mapping.supported) {
			return this.errorResult(`Architecture '${arch}' is not supported by Helix.`);
		}

		// Apply optimizeIR flag if the native module supports it (BUG-HELIX-003)
		const skipOpt = options?.optimizeIR === false;
		if (skipOpt) {
			try {
				const engine = this.ensureEngine(mapping.helixArch);
				if (engine && typeof (engine as any).setSkipOptimization === 'function') {
					(engine as any).setSkipOptimization(true);
				}
			} catch { /* Native module doesn't support this yet — silently proceed */ }
		}

		// Apply useCastLayer flag — enables C AST pipeline (v3.7.4)
		// Must be set BEFORE decompileIr() as it's an engine config, not a decompile param
		const castLayer = options?.useCastLayer === true;
		if (castLayer) {
			try {
				const engine = this.ensureEngine(mapping.helixArch);
				if (engine && typeof (engine as any).setUseCastLayer === 'function') {
					(engine as any).setUseCastLayer(true);
				}
			} catch { /* Native module doesn't support this yet — silently proceed */ }
		}

		// v3.7.5 P3: Apply variable renames to the engine before decompilation.
		// The C AST optimizer will walk CVarRefExpr nodes and substitute names.
		const renames = options?.variableRenames;
		if (renames && renames.length > 0) {
			try {
				const engine = this.ensureEngine(mapping.helixArch);
				if (engine) {
					if (typeof engine.clearVariableRenames === 'function') {
						engine.clearVariableRenames();
					}
					if (typeof engine.addVariableRename === 'function') {
						for (const { oldName, newName } of renames) {
							engine.addVariableRename(oldName, newName);
						}
					}
				}
			} catch { /* Native module doesn't support renames yet — fallback to string replace */ }
		}

		let result: HelixResult;
		if (irText.length > ASYNC_THRESHOLD) {
			// v3.7.4: Pass engine flags to worker — worker creates its own engine
			// so flags set on the main-thread engine don't propagate automatically
			result = await this.decompileIrAsync(irText, mapping.helixArch, {
				skipOptimization: skipOpt,
				useCastLayer: castLayer,
				variableRenames: renames,
			});
		} else {
			result = this.decompileIrSync(irText, mapping.helixArch);
		}

		// Reset optimization flag for next call (sync path only — worker disposes its own engine)
		if (skipOpt) {
			try {
				const engine = this.ensureEngine(mapping.helixArch);
				if (engine && typeof (engine as any).setSkipOptimization === 'function') {
					(engine as any).setSkipOptimization(false);
				}
			} catch { /* ignore */ }
		}

		// Reset castLayer flag for next call (sync path only)
		if (castLayer) {
			try {
				const engine = this.ensureEngine(mapping.helixArch);
				if (engine && typeof (engine as any).setUseCastLayer === 'function') {
					(engine as any).setUseCastLayer(false);
				}
			} catch { /* ignore */ }
		}

		// v3.7.5 P3: Clear variable renames after decompilation (sync path only)
		if (renames && renames.length > 0) {
			try {
				const engine = this.ensureEngine(mapping.helixArch);
				if (engine && typeof engine.clearVariableRenames === 'function') {
					engine.clearVariableRenames();
				}
			} catch { /* ignore */ }
		}

		return result;
	}

	/**
	 * Decompila LLVM IR e retorna métricas de pipeline.
	 */
	async decompileIrWithMetrics(irText: string, arch: ArchitectureConfig = 'x64'): Promise<HelixResultWithMetrics> {
		if (!this.available || !this.module) {
			return { result: this.errorResult('hexcore-helix is not available'), metrics: this.emptyMetrics() };
		}

		const effectiveArch: ArchitectureConfig = arch === 'x86' ? 'x64' : arch;
		const mapping = mapCapstoneToHelix(effectiveArch);
		if (!mapping.supported) {
			return { result: this.errorResult(`Architecture '${arch}' is not supported by Helix.`), metrics: this.emptyMetrics() };
		}

		try {
			const engine = this.ensureEngine(mapping.helixArch);
			if (!engine) {
				return { result: this.errorResult('Failed to create HelixEngine instance'), metrics: this.emptyMetrics() };
			}

			const [raw, metrics] = engine.decompileIrWithMetrics(irText);
			return {
				result: this.wrapResult(raw),
				metrics,
			};
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : String(err);
			return { result: this.errorResult(`Helix native error: ${msg}`), metrics: this.emptyMetrics() };
		}
	}

	/**
	 * Decompila binário diretamente (sem passar pelo Remill).
	 */
	async decompile(data: Buffer, baseAddress: bigint, entryAddress: bigint, arch: ArchitectureConfig = 'x64'): Promise<HelixResult> {
		if (!this.available || !this.module) {
			return this.errorResult('hexcore-helix is not available');
		}

		const mapping = mapCapstoneToHelix(arch);
		if (!mapping.supported) {
			return this.errorResult(`Architecture '${arch}' is not supported by Helix.`);
		}

		try {
			const engine = this.ensureEngine(mapping.helixArch);
			if (!engine) {
				return this.errorResult('Failed to create HelixEngine instance');
			}

			const raw = engine.decompile(data, baseAddress, entryAddress);
			return this.wrapResult(raw);
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : String(err);
			return this.errorResult(`Helix native error: ${msg}`);
		}
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	private decompileIrSync(irText: string, arch: HelixArchValue): HelixResult {
		try {
			const engine = this.ensureEngine(arch);
			if (!engine) {
				return this.errorResult('Failed to create HelixEngine instance');
			}
			return this.wrapResult(engine.decompileIr(irText));
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : String(err);
			return this.errorResult(`Helix native error: ${msg}`);
		}
	}

	/**
	 * Offload decompileIr para worker thread (o .node não tem async nativo).
	 * Evita bloquear a UI do VS Code em funções grandes.
	 */
	private decompileIrAsync(
		irText: string,
		arch: HelixArchValue,
		flags?: { skipOptimization?: boolean; useCastLayer?: boolean; variableRenames?: Array<{ oldName: string; newName: string }> },
	): Promise<HelixResult> {
		return new Promise<HelixResult>((resolve) => {
			const workerCode = `
				const { parentPort, workerData } = require('worker_threads');
				const path = require('path');

				let binding;
				for (const p of workerData.modulePaths) {
					try { binding = require(path.join(p, 'index.js')); break; } catch (_) {}
					try { binding = require(p); break; } catch (_) {}
				}

				if (!binding) {
					parentPort.postMessage({ error: 'Failed to load hexcore-helix in worker' });
				} else {
					try {
						const engine = new binding.HelixEngine(workerData.arch);

						// v3.7.4: Apply engine flags forwarded from the main thread
						if (workerData.skipOptimization && typeof engine.setSkipOptimization === 'function') {
							engine.setSkipOptimization(true);
						}
						if (workerData.useCastLayer && typeof engine.setUseCastLayer === 'function') {
							engine.setUseCastLayer(true);
						}

						// v3.7.5 P3: Apply variable renames before decompilation
						if (workerData.variableRenames && workerData.variableRenames.length > 0) {
							if (typeof engine.clearVariableRenames === 'function') {
								engine.clearVariableRenames();
							}
							if (typeof engine.addVariableRename === 'function') {
								for (const r of workerData.variableRenames) {
									engine.addVariableRename(r.oldName, r.newName);
								}
							}
						}

						const result = engine.decompileIr(workerData.irText);
						engine.dispose();
						parentPort.postMessage({ result });
					} catch (err) {
						parentPort.postMessage({ error: err.message || String(err) });
					}
				}
			`;

			const worker = new Worker(workerCode, {
				eval: true,
				workerData: {
					irText,
					arch,
					modulePaths: this.modulePaths,
					skipOptimization: flags?.skipOptimization ?? false,
					useCastLayer: flags?.useCastLayer ?? false,
					variableRenames: flags?.variableRenames ?? [],
				},
			});

			worker.on('message', (msg: { result?: HelixDecompileResult; error?: string }) => {
				if (msg.error) {
					resolve(this.errorResult(`Helix worker error: ${msg.error}`));
				} else if (msg.result) {
					resolve(this.wrapResult(msg.result));
				} else {
					resolve(this.errorResult('Helix worker returned empty response'));
				}
			});

			worker.on('error', (err) => {
				resolve(this.errorResult(`Helix worker thread error: ${err.message}`));
			});
		});
	}

	private wrapResult(raw: HelixDecompileResult): HelixResult {
		return {
			success: true,
			source: raw.source,
			functionName: raw.functionName,
			entryAddress: raw.entryAddress,
			blockCount: raw.blockCount,
			instructionCount: raw.instructionCount,
			cfgBuffer: raw.cfgBuffer,
			astBuffer: raw.astBuffer,
			error: '',
		};
	}

	private errorResult(error: string): HelixResult {
		return {
			success: false,
			source: '',
			functionName: '',
			entryAddress: '',
			blockCount: 0,
			instructionCount: 0,
			cfgBuffer: null,
			astBuffer: null,
			error,
		};
	}

	private emptyMetrics(): PipelineMetrics {
		return { totalMs: 0, instructionsDecoded: 0, functionsRecovered: 0, throughput: 0, warningCount: 0 };
	}

	/**
	 * Libera recursos nativos do engine.
	 * Idempotente — pode ser chamado múltiplas vezes sem erro.
	 */
	dispose(): void {
		if (this.engine && !this.engine.isDisposed) {
			this.engine.dispose();
			this.engine = undefined;
		}
		this.currentArch = undefined;
	}
}

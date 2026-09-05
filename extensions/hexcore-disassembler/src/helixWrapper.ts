/*---------------------------------------------------------------------------------------------
 *  HexCore Helix Wrapper
 *  TypeScript wrapper para o módulo nativo hexcore-helix (NAPI-RS).
 *  Segue o padrão dos wrappers Remill/Rellic (v3.7.0).
 *---------------------------------------------------------------------------------------------*/

import * as path from 'path';
import { fork } from 'child_process';
import { Worker } from 'worker_threads';
import { loadNativeModule } from 'hexcore-common';
import type { ArchitectureConfig } from './capstoneWrapper';
import { mapCapstoneToHelix, isHelixArchSupported, HelixArch, type HelixArchValue } from './helixArchMapper';
import type { StructInfoJson } from './elfBtfLoader';
import { applyStructFieldNames, type PostProcessResult } from './structFieldPostProcessor';
import { cleanupHelixSource, type CleanupOptions } from './helixCleanupPostProcessor';
import {
	createHelixDebugTypeEnvelope,
	type HelixAnalysisContext,
} from './helixAnalysisContext';

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
	/** Register raw bytes for a virtual-address range so RecoverSwitchTables
	 *  can read jump tables / vtables / string literals from the original
	 *  binary.  Without at least one section, the pass skips itself and
	 *  every `switch (...)` collapses to `goto default`. */
	addDataSection?(vaStart: bigint, bytes: Buffer): void;
	/** Drop all registered data sections. */
	clearDataSections?(): void;
	/** vX: the COMPLETE function-start table (analyzeAll discovery) as VAs.
	 *  Makes the Helix function table authoritative so the D2 callee gate
	 *  (out-of-table target -> honest indirect) and the #30 registry-miss
	 *  honesty path fire.  Full table or omitted; a partial table wrongly
	 *  flips the engine authoritative and mis-gates valid calls to indirect. */
	setFunctionStarts?(starts: number[]): void;
	/** Versioned DWARF/BTF/PDB signatures and nominal struct layouts. */
	setDebugTypeInfoJson?(json: string): void;
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

interface ActiveDecompile {
	cancel(): void;
}

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
	private readonly activeDecompiles = new Map<ActiveDecompile, string | undefined>();

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
	async decompileIr(irText: string, arch: ArchitectureConfig = 'x64', options?: {
		optimizeIR?: boolean;
		useCastLayer?: boolean;
		variableRenames?: Array<{ oldName: string; newName: string }>;
		/** v3.8.0: Struct field info from BTF/DWARF/PDB for field naming */
		structInfo?: StructInfoJson;
		/** Immutable Disassembler evidence captured for this exact function. */
		semanticContext?: HelixAnalysisContext;
		/** Function name for param type resolution against structInfo */
		functionName?: string;
		/**
		 * v3.8.0: Safe text-level cleanup of Helix output (cast stripping,
		 * intrinsic normalization, logical-op fixes, dead-decl pruning).
		 * Pass `false` to disable. Pass a partial object to enable a subset.
		 * Default: enabled with all transformations on.
		 */
		cleanup?: boolean | CleanupOptions;
		/**
		 * v3.9.0: Raw bytes of the binary's data sections (`.rdata` for PE,
		 * `.rodata` for ELF), keyed by virtual address.  Required for switch
		 * table recovery — without it, RecoverSwitchTables skips itself and
		 * every `switch (...)` in the source binary collapses to
		 * `goto default` in the decompiled output.
		 */
		dataSections?: Array<{ vaStart: bigint; bytes: Buffer }>;
		/**
		 * vX: the COMPLETE function-start table (every entry from the
		 * disassembler analyzeAll discovery, as virtual addresses).  Makes
		 * Helix authoritative so the D2 callee gate and the #30 registry-miss
		 * honesty path fire.  Full table or omitted -- a partial table wrongly
		 * flips the engine authoritative and mis-gates valid in-binary calls.
		 */
		functionStarts?: number[];
		/**
		 * FIX-QUALITY-002b: force the main-thread sync decompile path even when
		 * IR > 64KB. Headless/pipeline jobs should set this — Electron
		 * worker_threads + native .node double-load has been a silent quality
		 * risk (partial C bodies). Interactive UI may keep the worker so the
		 * editor stays responsive.
		 */
		forceSync?: boolean;
		/** Force a fresh worker even for small IR. Used by cancellable live-memory jobs. */
		forceWorker?: boolean;
		/** Force a separate OS process. Required when a native call must be killable safely. */
		forceProcess?: boolean;
		/** Hard deadline for an isolated worker. Ignored by the synchronous path. */
		workerTimeoutMs?: number;
		/** Optional cancellation group for scoped cancellation commands. */
		workerGroup?: string;
	}): Promise<HelixResult> {
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
		{
			try {
				const engine = this.ensureEngine(mapping.helixArch);
				if (engine) {
					if (typeof engine.clearVariableRenames === 'function') {
						engine.clearVariableRenames();
					}
					if (renames && typeof engine.addVariableRename === 'function') {
						for (const { oldName, newName } of renames) {
							engine.addVariableRename(oldName, newName);
						}
					}
				}
			} catch { /* Native module doesn't support renames yet — fallback to string replace */ }
		}

		// v3.9.0: Feed the binary's data sections so RecoverSwitchTables can
		// resolve jump tables.  Without this the pass auto-skips and every
		// `switch (...)` in the source collapses to `goto default`.
		const dataSections = options?.dataSections;
		{
			try {
				const engine = this.ensureEngine(mapping.helixArch);
				if (engine) {
					if (typeof engine.clearDataSections === 'function') {
						engine.clearDataSections();
					}
					if (dataSections && typeof engine.addDataSection === 'function') {
						for (const { vaStart, bytes } of dataSections) {
							engine.addDataSection(vaStart, bytes);
						}
					}
				}
			} catch { /* Native module too old — proceed without sections */ }
		}

		// vX: feed the COMPLETE function-start table so the Helix function table
		// is authoritative -- the D2 callee gate and the #30 registry-miss path
		// only fire under an authoritative table.  Set AFTER setSkipOptimization
		// / setUseCastLayer (the engine rebuilds its pipeline on those, which
		// would discard an earlier table) and right before the decompile.  Full
		// table or nothing (a partial table mis-gates valid calls to indirect).
		const functionStarts = options?.functionStarts;
		{
			try {
				const engine = this.ensureEngine(mapping.helixArch);
				if (engine && typeof (engine as any).setFunctionStarts === 'function') {
					(engine as any).setFunctionStarts(functionStarts ?? []);
				}
			} catch { /* Native module too old -- proceed without authoritative table */ }
		}

		// FIX-121: seed nominal debug types inside the MLIR pipeline. Always
		// replace (including empty) because engine instances are reused.
		const debugTypeInfoJson = options?.semanticContext
			? JSON.stringify(createHelixDebugTypeEnvelope(options.semanticContext, options.structInfo))
			: options?.structInfo ? JSON.stringify(options.structInfo) : '';
		try {
			const engine = this.ensureEngine(mapping.helixArch);
			if (engine && typeof engine.setDebugTypeInfoJson === 'function') {
				engine.setDebugTypeInfoJson(debugTypeInfoJson);
			}
		} catch { /* Native module too old -- text post-processor remains fallback */ }

		let result: HelixResult;
		// FIX-QUALITY-002b: headless/pipeline prefers sync (forceSync) so the
		// same engine instance that received setUseCastLayer / dataSections /
		// functionStarts actually runs decompileIr. Worker path still used for
		// large interactive decompiles to keep the UI responsive.
		const forcedModes = [options?.forceSync, options?.forceWorker, options?.forceProcess]
			.filter(value => value === true).length;
		if (forcedModes > 1) {
			return this.errorResult('forceSync, forceWorker and forceProcess are mutually exclusive');
		}
		const useProcess = options?.forceProcess === true;
		const useWorker = !useProcess && (options?.forceWorker === true
			|| (irText.length > ASYNC_THRESHOLD && options?.forceSync !== true));
		if (useProcess) {
			result = await this.decompileIrInProcess(irText, mapping.helixArch, {
				skipOptimization: skipOpt,
				useCastLayer: castLayer,
				variableRenames: renames,
				functionStarts,
				dataSections,
				debugTypeInfoJson,
			}, options?.workerTimeoutMs, options?.workerGroup);
		} else if (useWorker) {
			// v3.7.4: Pass engine flags to worker — worker creates its own engine
			// so flags set on the main-thread engine don't propagate automatically
			result = await this.decompileIrAsync(irText, mapping.helixArch, {
				skipOptimization: skipOpt,
				useCastLayer: castLayer,
				variableRenames: renames,
				functionStarts,
				dataSections,
				debugTypeInfoJson,
			}, options?.workerTimeoutMs, options?.workerGroup);
		} else {
			if (irText.length > ASYNC_THRESHOLD) {
				console.log(
					`[helix] FIX-QUALITY-002b: forceSync decompile on main thread ` +
					`(IR ${irText.length} bytes > ${ASYNC_THRESHOLD})`
				);
			}
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

		if (!useWorker && !useProcess && debugTypeInfoJson) {
			try {
				const engine = this.ensureEngine(mapping.helixArch);
				if (engine && typeof engine.setDebugTypeInfoJson === 'function') {
					engine.setDebugTypeInfoJson('');
				}
			} catch { /* ignore */ }
		}

		// v3.8.0: Apply struct field naming from BTF/DWARF/PDB debug info
		if (result.success && options?.structInfo) {
			try {
				const postResult = applyStructFieldNames(
					result.source,
					options.structInfo,
					options.functionName,
				);
				if (postResult.totalRenames > 0) {
					result = { ...result, source: postResult.source };
					console.log(`[helix-struct] Applied ${postResult.totalRenames} renames (${postResult.fieldRenames.length} fields, ${postResult.paramRenames.length} params)`);
				}
			} catch (err) {
				console.warn('[helix-struct] Post-processing failed:', err);
				// Don't fail the decompilation — return unmodified result
			}
		}

		// v3.8.0: Safe text-level cleanup of residual emitter artifacts
		// (literal casts, intrinsic prefixes, bitwise-on-bool, dead regs).
		// Runs AFTER struct renaming so dead-decl pruning sees the final names.
		if (result.success && options?.cleanup !== false) {
			try {
				const cleanupOpts: CleanupOptions | undefined =
					typeof options?.cleanup === 'object' ? options.cleanup : undefined;
				const cleaned = cleanupHelixSource(result.source, cleanupOpts);
				if (cleaned.stats.totalRewrites > 0) {
					result = { ...result, source: cleaned.source };
					const s = cleaned.stats;
					console.log(
						`[helix-cleanup] Applied ${s.totalRewrites} rewrites ` +
						`(casts=${s.redundantCasts}, intrinsics=${s.intrinsicsNormalized}, ` +
						`logicOps=${s.logicalOpsFixed}, deadDecls=${s.deadDeclarations})`,
					);
				}
			} catch (err) {
				console.warn('[helix-cleanup] Post-processing failed:', err);
				// Non-fatal: return the un-cleaned source
			}
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
		flags?: { skipOptimization?: boolean; useCastLayer?: boolean; variableRenames?: Array<{ oldName: string; newName: string }>; functionStarts?: number[]; dataSections?: Array<{ vaStart: bigint; bytes: Buffer }>; debugTypeInfoJson?: string },
		timeoutMs?: number,
		workerGroup?: string,
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

						// vX: authoritative function-start table (mirrors main thread)
						if (workerData.functionStarts && workerData.functionStarts.length > 0 && typeof engine.setFunctionStarts === 'function') {
							engine.setFunctionStarts(workerData.functionStarts);
						}
						if (typeof engine.setDebugTypeInfoJson === 'function') {
							engine.setDebugTypeInfoJson(workerData.debugTypeInfoJson || '');
						}

						// Switch-table recovery needs the binary's data sections; the main
						// thread set them on its own engine, but this worker builds a fresh
						// one, so they must be forwarded (previously dropped on the >64KB
						// path -> every switch collapsed to goto default in large functions).
						if (workerData.dataSections && workerData.dataSections.length > 0 && typeof engine.addDataSection === 'function') {
							if (typeof engine.clearDataSections === 'function') {
								engine.clearDataSections();
							}
							for (const ds of workerData.dataSections) {
								engine.addDataSection(ds.vaStart, ds.bytes);
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
					functionStarts: flags?.functionStarts ?? [],
					dataSections: flags?.dataSections ?? [],
					debugTypeInfoJson: flags?.debugTypeInfoJson ?? '',
				},
			});
			const active: ActiveDecompile = { cancel: () => { void worker.terminate(); } };
			this.activeDecompiles.set(active, workerGroup);

			let settled = false;
			let timeoutHandle: NodeJS.Timeout | undefined;
			const settle = (r: HelixResult): void => {
				if (settled) { return; }
				settled = true;
				if (timeoutHandle) { clearTimeout(timeoutHandle); }
				this.activeDecompiles.delete(active);
				resolve(r);
			};
			if (timeoutMs !== undefined) {
				const boundedTimeout = Math.max(1, Math.min(Math.trunc(timeoutMs), 2_147_483_647));
				timeoutHandle = setTimeout(() => {
					settle(this.errorResult(`Helix worker timed out after ${boundedTimeout}ms`));
					void worker.terminate();
				}, boundedTimeout);
			}

			worker.on('message', (msg: { result?: HelixDecompileResult; error?: string }) => {
				if (msg.error) {
					settle(this.errorResult(`Helix worker error: ${msg.error}`));
				} else if (msg.result) {
					settle(this.wrapResult(msg.result));
				} else {
					settle(this.errorResult('Helix worker returned empty response'));
				}
			});

			worker.on('error', (err) => {
				settle(this.errorResult(`Helix worker thread error: ${err.message}`));
			});

			// Guarantee the Promise always settles: if the worker stops without
			// posting a message or error (silent exit / hard native crash), resolve
			// an error instead of hanging the decompile forever.
			worker.on('exit', (code: number) => {
				settle(this.errorResult(`Helix worker exited without returning a result (code ${code})`));
			});
		});
	}

	/**
	 * Runs Helix in a separate process. Killing a worker_thread while it is inside
	 * LLVM/MLIR native code can terminate the whole Extension Host on Windows.
	 */
	private decompileIrInProcess(
		irText: string,
		arch: HelixArchValue,
		flags?: { skipOptimization?: boolean; useCastLayer?: boolean; variableRenames?: Array<{ oldName: string; newName: string }>; functionStarts?: number[]; dataSections?: Array<{ vaStart: bigint; bytes: Buffer }>; debugTypeInfoJson?: string },
		timeoutMs?: number,
		workerGroup?: string,
	): Promise<HelixResult> {
		return new Promise<HelixResult>((resolve) => {
			const child = fork(path.join(__dirname, 'helixDecompileChild.js'), [], {
				env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
				// The Dev Extension Host carries --inspect=<port>. Inheriting it makes
				// every child contend for the host's inspector and can abort Electron.
				execArgv: [],
				serialization: 'advanced',
				stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
			});
			const active: ActiveDecompile = { cancel: () => { child.kill(); } };
			this.activeDecompiles.set(active, workerGroup);

			let settled = false;
			let timeoutHandle: NodeJS.Timeout | undefined;
			let stderr = '';
			child.stderr?.on('data', chunk => {
				stderr = (stderr + String(chunk)).slice(-8192);
			});
			const settle = (result: HelixResult, terminate = false): void => {
				if (settled) { return; }
				settled = true;
				if (timeoutHandle) { clearTimeout(timeoutHandle); }
				this.activeDecompiles.delete(active);
				resolve(result);
				if (terminate) { child.kill(); }
			};

			if (timeoutMs !== undefined) {
				const boundedTimeout = Math.max(1, Math.min(Math.trunc(timeoutMs), 2_147_483_647));
				timeoutHandle = setTimeout(() => {
					settle(this.errorResult(`Helix process timed out after ${boundedTimeout}ms`), true);
				}, boundedTimeout);
			}

			child.on('message', (message: { result?: HelixDecompileResult; error?: string }) => {
				if (message.error) {
					settle(this.errorResult(`Helix process error: ${message.error}`), true);
				} else if (message.result) {
					settle(this.wrapResult(message.result), true);
				} else {
					settle(this.errorResult('Helix process returned empty response'), true);
				}
			});
			child.on('error', error => {
				settle(this.errorResult(`Helix process launch error: ${error.message}`), true);
			});
			child.on('exit', code => {
				const detail = stderr.trim() ? `: ${stderr.trim()}` : '';
				settle(this.errorResult(`Helix process exited without returning a result (code ${code})${detail}`));
			});

			child.send({
				irText,
				arch,
				modulePaths: this.modulePaths,
				skipOptimization: flags?.skipOptimization ?? false,
				useCastLayer: flags?.useCastLayer ?? false,
				variableRenames: flags?.variableRenames ?? [],
				functionStarts: flags?.functionStarts ?? [],
				dataSections: flags?.dataSections ?? [],
				debugTypeInfoJson: flags?.debugTypeInfoJson ?? '',
			}, error => {
				if (error) {
					settle(this.errorResult(`Helix process IPC error: ${error.message}`), true);
				}
			});
		});
	}

	/** Cancels every isolated decompile currently owned by this wrapper. */
	cancelActiveDecompiles(workerGroup?: string): number {
		const workers = [...this.activeDecompiles.entries()]
			.filter(([, group]) => workerGroup === undefined || group === workerGroup)
			.map(([worker]) => worker);
		for (const worker of workers) {
			this.activeDecompiles.delete(worker);
			worker.cancel();
		}
		return workers.length;
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
		this.cancelActiveDecompiles();
		if (this.engine && !this.engine.isDisposed) {
			this.engine.dispose();
			this.engine = undefined;
		}
		this.currentArch = undefined;
	}
}

/*---------------------------------------------------------------------------------------------
 *  HexCore Souper Wrapper
 *  TypeScript wrapper para o módulo nativo hexcore-souper.
 *  Superoptimizador de LLVM IR via Z3 SMT solving.
 *
 *  Pipeline: Remill (lift) → **Souper (optimize)** → Helix (decompile)
 *
 *  Segue o padrão dos wrappers Remill/Rellic/Helix (v3.7.0+).
 *---------------------------------------------------------------------------------------------*/

import * as path from 'path';
import { loadNativeModule } from 'hexcore-common';

// ---------------------------------------------------------------------------
// Interfaces do módulo nativo hexcore-souper
// ---------------------------------------------------------------------------

interface SouperModule {
	SouperOptimizer: new () => SouperOptimizerInstance;
	version: string;
}

interface SouperOptimizeOptions {
	maxCandidates?: number;
	timeoutMs?: number;
	aggressiveMode?: boolean;
}

interface SouperOptimizerInstance {
	optimize(irText: string, options?: SouperOptimizeOptions): SouperOptimizeResult;
	optimizeAsync(irText: string, options?: SouperOptimizeOptions): Promise<SouperOptimizeResult>;
	close(): void;
	isOpen(): boolean;
}

/**
 * Resultado de uma operação de superoptimização.
 */
export interface SouperOptimizeResult {
	success: boolean;
	ir: string;
	error: string;
	candidatesFound: number;
	candidatesReplaced: number;
	optimizationTimeMs: number;
}

/**
 * Options exposed to callers of the Souper wrapper.
 */
export interface SouperOptions {
	/** Maximum candidates to extract per function (0 = unlimited). Default: 1000 */
	maxCandidates?: number;
	/** Z3 solver timeout in ms per candidate. Default: 30000 */
	timeoutMs?: number;
	/** Try harder synthesis strategies (slower). Default: false */
	aggressiveMode?: boolean;
}

/**
 * Result of the LLVM-IR-text density heuristic used by the "auto"
 * Souper activation mode.
 */
export interface SouperDensityResult {
	/** Value-defining + terminator instructions counted. */
	totalInsns: number;
	/** Crypto/MBA-signal ops (xor/and/or/shl/lshr/ashr + rotate/bswap intrinsics). */
	signalOps: number;
	/** signalOps / totalInsns (0 when no instructions were counted). */
	density: number;
}

/**
 * Cheap structural heuristic over LLVM IR *text* that estimates how
 * "crypto / MBA / packer-like" the IR is, from the density of bitwise
 * and rotate operations. Souper (Z3 superoptimization) is ~zero-value
 * on ordinary code and only pays off on this kind of heavily-arithmetic
 * IR, so the "auto" activation mode uses this to decide whether running
 * Souper is worth its cost. Pure + side-effect-free (unit-testable).
 */
export function computeSouperDensity(irText: string): SouperDensityResult {
	if (!irText) {
		return { totalInsns: 0, signalOps: 0, density: 0 };
	}
	// Bitwise/shift opcodes that signal crypto or MBA obfuscation.
	const SIGNAL = new Set(['xor', 'and', 'or', 'shl', 'lshr', 'ashr']);
	let totalInsns = 0;
	let signalOps = 0;
	for (const raw of irText.split('\n')) {
		const line = raw.trim();
		if (line.length === 0 || line.charCodeAt(0) === 0x3b /* ; */) {
			continue;
		}
		// Value-defining instruction:  %name = <opcode> ...
		if (line.charCodeAt(0) === 0x25 /* % */) {
			const eq = line.indexOf('= ');
			if (eq >= 0) {
				totalInsns++;
				const rest = line.slice(eq + 2).replace(/^\s+/, '');
				const sp = rest.indexOf(' ');
				const opcode = sp >= 0 ? rest.slice(0, sp) : rest;
				if (SIGNAL.has(opcode)) {
					signalOps++;
				} else if (opcode === 'call' && /@llvm\.(fshl|fshr|bswap|bitreverse)\b/.test(rest)) {
					// Rotate / byte-swap intrinsics are crypto signal too.
					signalOps++;
				}
				continue;
			}
		}
		// Terminators contribute to the instruction denominator.
		const sp = line.indexOf(' ');
		const head = sp >= 0 ? line.slice(0, sp) : line;
		if (head === 'br' || head === 'ret' || head === 'switch' ||
			head === 'indirectbr' || head === 'unreachable') {
			totalInsns++;
		}
	}
	const density = totalInsns > 0 ? signalOps / totalInsns : 0;
	return { totalInsns, signalOps, density };
}

/** Tuning knobs for the "auto" Souper activation heuristic. */
export interface SouperAutoConfig {
	/** Minimum signalOps/totalInsns ratio to run Souper. Default: 0.25. */
	threshold?: number;
	/** Minimum absolute signal-op count to run Souper. Default: 8. */
	minSignalOps?: number;
}

/** Outcome of the Souper activation gate for one IR unit. */
export interface SouperGateDecision {
	/** Whether Souper should run on this IR. */
	run: boolean;
	mode: 'forced-on' | 'forced-off' | 'auto-run' | 'auto-skip';
	/** Present only for the 'auto' modes. */
	density?: SouperDensityResult;
	/** Human-readable explanation for logs. */
	reason: string;
}

export const SOUPER_AUTO_DEFAULT_THRESHOLD = 0.25;
export const SOUPER_AUTO_DEFAULT_MIN_OPS = 8;

/**
 * Decide whether to run Souper for a given IR, honoring the tri-state
 * `souper` option:
 *   - `false`          -> never  (forced off)
 *   - `true`           -> always (explicit opt-in)
 *   - `'auto'`/absent  -> only when the IR is crypto/MBA-dense enough to
 *                         benefit
 *
 * Unknown values follow the conservative auto policy rather than paying the
 * solver cost unconditionally.
 */
export function decideSouperGate(
	souperOption: unknown,
	irText: string,
	cfg?: SouperAutoConfig
): SouperGateDecision {
	if (souperOption === false) {
		return { run: false, mode: 'forced-off', reason: 'souper:false' };
	}
	if (souperOption === true) {
		return { run: true, mode: 'forced-on', reason: 'souper:true' };
	}

	const density = computeSouperDensity(irText);
	const threshold = typeof cfg?.threshold === 'number' ? cfg.threshold : SOUPER_AUTO_DEFAULT_THRESHOLD;
	const minSignalOps = typeof cfg?.minSignalOps === 'number' ? cfg.minSignalOps : SOUPER_AUTO_DEFAULT_MIN_OPS;
	const run = density.signalOps >= minSignalOps && density.density >= threshold;
	return {
		run,
		mode: run ? 'auto-run' : 'auto-skip',
		density,
		reason: `auto density=${density.density.toFixed(2)} signalOps=${density.signalOps}/${density.totalInsns} (thr=${threshold}, min=${minSignalOps})`,
	};
}

/** Threshold em bytes acima do qual usamos optimizeAsync */
const ASYNC_THRESHOLD = 65536; // 64KB

/**
 * Wrapper TypeScript para o módulo nativo hexcore-souper.
 *
 * Gerencia o ciclo de vida do SouperOptimizer (criação sob demanda,
 * reutilização entre chamadas, cleanup no dispose) e expõe uma
 * API simplificada para superoptimização de LLVM IR.
 *
 * Degrada graciosamente quando o módulo nativo não está disponível.
 */
export class SouperWrapper {
	private module?: SouperModule;
	private optimizer?: SouperOptimizerInstance;
	private available: boolean = false;
	private lastError?: string;

	constructor() {
		this.tryLoad();
	}

	/**
	 * Tenta carregar o módulo nativo hexcore-souper.
	 * Se falhar, marca como indisponível e registra o erro.
	 */
	private tryLoad(): void {
		const candidatePaths = [
			path.join(__dirname, '..', '..', 'hexcore-souper'),
			path.join(__dirname, '..', '..', '..', 'hexcore-souper'),
		];

		const result = loadNativeModule<SouperModule>({
			moduleName: 'hexcore-souper',
			candidatePaths,
		});

		if (result.module) {
			this.module = result.module;
			this.available = true;
		} else {
			this.lastError = result.errorMessage;
			this.available = false;
			console.warn('hexcore-souper not available:', this.lastError);
		}
	}

	/**
	 * Retorna true se o módulo nativo está carregado e disponível.
	 */
	isAvailable(): boolean {
		return this.available;
	}

	/**
	 * Retorna a versão do módulo nativo, ou undefined se indisponível.
	 */
	getVersion(): string | undefined {
		return this.module?.version;
	}

	/**
	 * Retorna o último erro de carregamento, se houver.
	 */
	getLastError(): string | undefined {
		return this.lastError;
	}

	/**
	 * Garante que existe uma instância do optimizer.
	 * Cria uma nova se não existir ou se foi fechada.
	 */
	private ensureOptimizer(): SouperOptimizerInstance {
		if (this.optimizer && this.optimizer.isOpen()) {
			return this.optimizer;
		}

		this.optimizer = new this.module!.SouperOptimizer();
		return this.optimizer;
	}

	/**
	 * Superoptimiza LLVM IR text.
	 *
	 * Usa optimizeAsync para IR > 64KB, optimize para menores.
	 * Retorna SouperOptimizeResult com success=false se o módulo não está disponível.
	 *
	 * @param irText Texto LLVM IR para otimizar (saída do Remill)
	 * @param options Opções de otimização
	 */
	async optimize(
		irText: string,
		options?: SouperOptions
	): Promise<SouperOptimizeResult> {
		if (!this.available || !this.module) {
			return {
				success: false,
				ir: '',
				error: 'hexcore-souper is not available',
				candidatesFound: 0,
				candidatesReplaced: 0,
				optimizationTimeMs: 0,
			};
		}

		const optimizer = this.ensureOptimizer();

		const nativeOpts: SouperOptimizeOptions | undefined = options ? {
			maxCandidates: options.maxCandidates,
			timeoutMs: options.timeoutMs,
			aggressiveMode: options.aggressiveMode,
		} : undefined;

		try {
			if (irText.length > ASYNC_THRESHOLD) {
				return await optimizer.optimizeAsync(irText, nativeOpts);
			} else {
				return optimizer.optimize(irText, nativeOpts);
			}
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : String(err);
			return {
				success: false,
				ir: '',
				error: `Souper optimization failed: ${msg}`,
				candidatesFound: 0,
				candidatesReplaced: 0,
				optimizationTimeMs: 0,
			};
		}
	}

	/**
	 * Fecha o optimizer e libera recursos.
	 * Idempotente — pode ser chamado múltiplas vezes.
	 */
	dispose(): void {
		if (this.optimizer) {
			try {
				this.optimizer.close();
			} catch {
				// Ignore close errors
			}
			this.optimizer = undefined;
		}
	}
}

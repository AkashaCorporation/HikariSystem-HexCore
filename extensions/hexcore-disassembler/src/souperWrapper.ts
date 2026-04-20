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

/*---------------------------------------------------------------------------------------------
 *  HexCore Helix Wrapper
 *  TypeScript wrapper para o módulo nativo hexcore-helix (NAPI-RS).
 *---------------------------------------------------------------------------------------------*/

import * as path from 'path';
import { loadNativeModule } from 'hexcore-common';

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

interface HelixEngineInstance {
	version(): string;
	architecture(): string;
	decompileIr(irText: string): HelixDecompileResult;
	dispose(): void;
	readonly isDisposed: boolean;
}

interface HelixModule {
	HelixEngine: new (arch: number) => HelixEngineInstance;
	Architecture: Record<string, number>;
}

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

// Architecture.X86_64 = 1 (const enum inlined — usar valor direto em runtime)
const ARCH_X86_64 = 1;

/**
 * Wrapper para o módulo nativo hexcore-helix.
 * Mantém uma instância de HelixEngine reutilizável entre chamadas.
 */
export class HelixWrapper {
	private module?: HelixModule;
	private engine?: HelixEngineInstance;
	private available: boolean = false;
	private lastError?: string;

	constructor() {
		this.tryLoad();
	}

	private tryLoad(): void {
		const candidatePaths = [
			path.join(__dirname, '..', '..', 'hexcore-helix'),
			path.join(__dirname, '..', '..', '..', 'hexcore-helix'),
		];

		const result = loadNativeModule<HelixModule>({
			moduleName: 'hexcore-helix',
			candidatePaths,
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
		return this.engine?.version() ?? (this.available ? this.getEngine()?.version() : undefined);
	}

	getLastError(): string | undefined {
		return this.lastError;
	}

	private getEngine(): HelixEngineInstance | undefined {
		if (!this.module) return undefined;
		if (!this.engine || this.engine.isDisposed) {
			this.engine = new this.module.HelixEngine(ARCH_X86_64);
		}
		return this.engine;
	}

	/**
	 * Decompila LLVM IR text para pseudo-C usando o engine Helix.
	 */
	async decompileIr(irText: string): Promise<HelixResult> {
		if (!this.available || !this.module) {
			return this.errorResult('hexcore-helix is not available');
		}

		try {
			const engine = this.getEngine();
			if (!engine) {
				return this.errorResult('Failed to create HelixEngine instance');
			}

			const result = engine.decompileIr(irText);
			return {
				success: true,
				source: result.source,
				functionName: result.functionName,
				entryAddress: result.entryAddress,
				blockCount: result.blockCount,
				instructionCount: result.instructionCount,
				cfgBuffer: result.cfgBuffer,
				astBuffer: result.astBuffer,
				error: '',
			};
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : String(err);
			return this.errorResult(`Helix native error: ${msg}`);
		}
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

	dispose(): void {
		if (this.engine && !this.engine.isDisposed) {
			this.engine.dispose();
			this.engine = undefined;
		}
	}
}

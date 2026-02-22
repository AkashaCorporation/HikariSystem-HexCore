/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';
import { loadNativeModule } from 'hexcore-common';

// ---------------------------------------------------------------------------
// Interfaces do módulo nativo hexcore-rellic
// ---------------------------------------------------------------------------

interface RellicModule {
	RellicDecompiler: new () => RellicDecompilerInstance;
	version: string;
}

interface RellicDecompilerInstance {
	decompile(irText: string): DecompileResult;
	decompileAsync(irText: string): Promise<DecompileResult>;
	close(): void;
	isOpen(): boolean;
}

/**
 * Resultado de uma operação de decompilação.
 */
export interface DecompileResult {
	/** Se a decompilação foi bem-sucedida */
	success: boolean;
	/** Código pseudo-C gerado */
	code: string;
	/** Mensagem de erro (vazia se sucesso) */
	error: string;
	/** Número de funções decompiladas */
	functionCount: number;
}

/** Threshold em bytes acima do qual usamos decompileAsync */
const ASYNC_THRESHOLD = 65536; // 64KB

/**
 * Wrapper TypeScript para o módulo nativo hexcore-rellic.
 *
 * Gerencia o ciclo de vida do RellicDecompiler (criação sob demanda,
 * reutilização entre chamadas, cleanup no dispose) e expõe uma
 * API simplificada para decompilação de LLVM IR para pseudo-C.
 *
 * Degrada graciosamente quando o módulo nativo não está disponível.
 */
export class RellicWrapper {
	private module?: RellicModule;
	private decompiler?: RellicDecompilerInstance;
	private available: boolean = false;
	private lastError?: string;

	constructor() {
		this.tryLoad();
	}

	/**
	 * Tenta carregar o módulo nativo hexcore-rellic.
	 * Se falhar, marca como indisponível e registra o erro.
	 */
	private tryLoad(): void {
		const candidatePaths = [
			path.join(__dirname, '..', '..', 'hexcore-rellic'),
			path.join(__dirname, '..', '..', '..', 'hexcore-rellic'),
		];

		const result = loadNativeModule<RellicModule>({
			moduleName: 'hexcore-rellic',
			candidatePaths,
		});

		if (result.module) {
			this.module = result.module;
			this.available = true;
		} else {
			this.lastError = result.errorMessage;
			this.available = false;
			console.warn('hexcore-rellic not available:', this.lastError);
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
	 * Garante que existe uma instância do decompiler.
	 * Cria uma nova se não existir ou se foi fechada.
	 */
	private ensureDecompiler(): RellicDecompilerInstance {
		if (this.decompiler && this.decompiler.isOpen()) {
			return this.decompiler;
		}

		// Criar nova instância (re-criação automática após close)
		this.decompiler = new this.module!.RellicDecompiler();
		return this.decompiler;
	}

	/**
	 * Decompila texto LLVM IR para pseudo-C.
	 *
	 * Usa decompileAsync para IR > 64KB, decompile para menores.
	 * Retorna DecompileResult com success=false se o módulo não está disponível.
	 *
	 * @param irText Texto LLVM IR para decompilar
	 */
	async decompile(irText: string): Promise<DecompileResult> {
		if (!this.available || !this.module) {
			return {
				success: false,
				code: '',
				error: 'hexcore-rellic is not available',
				functionCount: 0,
			};
		}

		try {
			const decompiler = this.ensureDecompiler();

			if (irText.length > ASYNC_THRESHOLD) {
				return await decompiler.decompileAsync(irText);
			}

			return decompiler.decompile(irText);
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : String(err);
			return {
				success: false,
				code: '',
				error: `Rellic native error: ${msg}`,
				functionCount: 0,
			};
		}
	}

	/**
	 * Libera recursos nativos do decompiler.
	 * Idempotente — pode ser chamado múltiplas vezes sem erro.
	 */
	dispose(): void {
		if (this.decompiler) {
			this.decompiler.close();
			this.decompiler = undefined;
		}
	}
}


// ---------------------------------------------------------------------------
// Pseudo-C Header Builder
// ---------------------------------------------------------------------------

/**
 * Opções para geração do cabeçalho do documento pseudo-C.
 */
export interface PseudoCHeaderOptions {
	/** Nome do arquivo fonte */
	fileName: string;
	/** Endereço de início (hex string, ex: "0x00401000") */
	address: string;
	/** Arquitetura utilizada (ex: 'amd64') */
	architecture: string;
	/** Nome da função, se aplicável */
	functionName?: string;
}

/**
 * Gera o cabeçalho de comentário para o documento pseudo-C.
 * Inclui marcador EXPERIMENTAL, metadados do arquivo e timestamp.
 */
export function buildPseudoCHeader(options: PseudoCHeaderOptions): string {
	const sep = '// ============================================================';
	const lines: string[] = [
		sep,
		'// HexCore Rellic Decompiler (EXPERIMENTAL)',
		`// File: ${options.fileName}`,
	];

	if (options.functionName) {
		lines.push(`// Function: ${options.functionName}`);
	}

	lines.push(`// Address: ${options.address}`);
	lines.push(`// Architecture: ${options.architecture}`);
	lines.push(`// Generated: ${new Date().toISOString()}`);
	lines.push(sep);
	lines.push('// WARNING: This code was automatically generated by Rellic.');
	lines.push('// It is NOT compilable C — it is pseudo-C for analysis purposes.');
	lines.push(sep);
	lines.push('');

	return lines.join('\n');
}

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';
import { loadNativeModule } from 'hexcore-common';
import type { ArchitectureConfig } from './capstoneWrapper';
import { mapCapstoneToRemill, isArchSupported } from './archMapper';

// ---------------------------------------------------------------------------
// Interfaces do módulo nativo hexcore-remill
// ---------------------------------------------------------------------------

interface RemillModule {
	RemillLifter: new (arch: string, os?: string) => RemillLifterInstance;
	ARCH: Record<string, string>;
	OS: Record<string, string>;
	version: string;
}

interface RemillLifterInstance {
	liftBytes(code: Buffer | Uint8Array, address: number | bigint): LiftResult;
	liftBytesAsync(code: Buffer | Uint8Array, address: number | bigint): Promise<LiftResult>;
	getArch(): string;
	close(): void;
	isOpen(): boolean;
}

/**
 * Resultado de uma operação de lifting.
 */
export interface LiftResult {
	/** Se o lifting foi bem-sucedido */
	success: boolean;
	/** Texto LLVM IR gerado */
	ir: string;
	/** Mensagem de erro (vazia se sucesso) */
	error: string;
	/** Endereço base usado no lifting */
	address: number;
	/** Quantidade de bytes consumidos pelo lifter */
	bytesConsumed: number;
}

/** Threshold em bytes acima do qual usamos liftBytesAsync */
const ASYNC_THRESHOLD = 65536; // 64KB

/**
 * Wrapper TypeScript para o módulo nativo hexcore-remill.
 *
 * Gerencia o ciclo de vida do RemillLifter (criação sob demanda,
 * reutilização por arquitetura, cleanup no dispose) e expõe uma
 * API simplificada para lifting de bytes para LLVM IR.
 *
 * Degrada graciosamente quando o módulo nativo não está disponível.
 */
export class RemillWrapper {
	private module?: RemillModule;
	private lifter?: RemillLifterInstance;
	private currentArch?: string;
	private available: boolean = false;
	private lastError?: string;

	constructor() {
		this.tryLoad();
	}

	/**
	 * Tenta carregar o módulo nativo hexcore-remill.
	 * Se falhar, marca como indisponível e registra o erro.
	 */
	private tryLoad(): void {
		const candidatePaths = [
			path.join(__dirname, '..', '..', 'hexcore-remill'),
			path.join(__dirname, '..', '..', '..', 'hexcore-remill'),
		];

		const result = loadNativeModule<RemillModule>({
			moduleName: 'hexcore-remill',
			candidatePaths,
		});

		if (result.module) {
			this.module = result.module;
			this.available = true;
		} else {
			this.lastError = result.errorMessage;
			this.available = false;
			console.warn('hexcore-remill not available:', this.lastError);
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
	 * Verifica se uma arquitetura Capstone é suportada pelo Remill.
	 */
	isArchSupported(arch: ArchitectureConfig): boolean {
		return isArchSupported(arch);
	}

	/**
	 * Garante que existe uma instância do lifter para a arquitetura dada.
	 * Reutiliza a instância existente se a arquitetura não mudou.
	 * Fecha a instância anterior se a arquitetura mudou.
	 */
	private ensureLifter(arch: ArchitectureConfig): RemillLifterInstance {
		const mapping = mapCapstoneToRemill(arch);
		if (!mapping.supported) {
			throw new Error(`Architecture '${arch}' is not supported by Remill. Supported: x86, x64, arm64.`);
		}

		// Reutilizar instância existente se mesma arquitetura
		if (this.lifter && this.currentArch === mapping.remillArch) {
			return this.lifter;
		}

		// Fechar instância anterior se existir
		if (this.lifter) {
			this.lifter.close();
			this.lifter = undefined;
		}

		this.lifter = new this.module!.RemillLifter(mapping.remillArch, mapping.remillOs);
		this.currentArch = mapping.remillArch;
		return this.lifter;
	}

	/**
	 * Faz lifting de bytes de código de máquina para LLVM IR.
	 *
	 * Usa liftBytesAsync para buffers > 64KB, liftBytes para menores.
	 * Retorna LiftResult com success=false se o módulo não está disponível.
	 *
	 * @param buffer Bytes do código de máquina
	 * @param address Endereço base para o lifting
	 * @param arch Arquitetura Capstone do binário
	 */
	async liftBytes(
		buffer: Buffer | Uint8Array,
		address: number,
		arch: ArchitectureConfig
	): Promise<LiftResult> {
		if (!this.available || !this.module) {
			return {
				success: false,
				ir: '',
				error: 'hexcore-remill is not available',
				address,
				bytesConsumed: 0,
			};
		}

		try {
			const lifter = this.ensureLifter(arch);

			if (buffer.length > ASYNC_THRESHOLD) {
				return await lifter.liftBytesAsync(buffer, address);
			}

			return lifter.liftBytes(buffer, address);
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : String(err);
			return {
				success: false,
				ir: '',
				error: `Remill native error: ${msg}`,
				address,
				bytesConsumed: 0,
			};
		}
	}

	/**
	 * Libera recursos nativos do lifter.
	 * Idempotente — pode ser chamado múltiplas vezes sem erro.
	 */
	dispose(): void {
		if (this.lifter) {
			this.lifter.close();
			this.lifter = undefined;
		}
		this.currentArch = undefined;
	}
}


// ---------------------------------------------------------------------------
// IR Header Builder
// ---------------------------------------------------------------------------

/**
 * Opções para geração do cabeçalho do documento IR.
 */
export interface IRHeaderOptions {
	/** Nome do arquivo fonte */
	fileName: string;
	/** Endereço de início do lifting */
	address: number;
	/** Tamanho em bytes do range */
	size: number;
	/** Arquitetura utilizada (ex: 'amd64') */
	architecture: string;
	/** Nome da função, se aplicável */
	functionName?: string;
}

/**
 * Gera o cabeçalho de comentário para o documento LLVM IR.
 * Inclui marcador EXPERIMENTAL, metadados do arquivo e timestamp.
 */
export function buildIRHeader(options: IRHeaderOptions): string {
	const sep = '; ============================================================';
	const lines: string[] = [
		sep,
		'; HexCore Remill IR Lift (EXPERIMENTAL)',
		`; File: ${options.fileName}`,
	];

	if (options.functionName) {
		lines.push(`; Function: ${options.functionName}`);
	}

	lines.push(`; Address: 0x${options.address.toString(16).padStart(8, '0')}`);
	lines.push(`; Size: ${options.size} bytes`);
	lines.push(`; Architecture: ${options.architecture}`);
	lines.push(`; Generated: ${new Date().toISOString()}`);
	lines.push(sep);
	lines.push('');

	return lines.join('\n');
}

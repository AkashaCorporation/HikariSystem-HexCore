/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type { ArchitectureConfig } from './capstoneWrapper';

/**
 * Resultado do mapeamento de arquitetura Capstone → Remill.
 */
export interface ArchMapResult {
	/** Se a arquitetura Capstone possui equivalente no Remill */
	supported: boolean;
	/** Identificador de arquitetura do Remill (ex: 'amd64', 'x86', 'aarch64') */
	remillArch: string;
	/** Sistema operacional para semânticas do Remill */
	remillOs?: string;
}

/**
 * Mapeamento estático Capstone -> Remill.
 * Apenas arquiteturas com suporte completo no Remill são incluídas.
 *
 * NOTE (v3.8.2): 'arm64' -> 'aarch64' was REMOVED because the shipped native
 * remill build returned "Failed to lift instruction" on a trivial
 * `mov x0,#1; ret`.
 *
 * NOTE (FIX-053): 'arm64' -> 'aarch64' is RE-ENABLED. The native failure was
 * NOT missing aarch64 semantics (those ship and decode fine) -- it was two bugs
 * in the wrapper's multi-instruction path:
 *   1. Phase-1 handed the WHOLE remaining buffer to Remill's AArch64
 *      DecodeInstruction, which has a hard `size == 4` gate and rejects any
 *      buffer that isn't exactly one instruction wide.
 *   2. The reused `remill::Instruction` was not Reset() between decodes, so the
 *      AArch64 decoder (which appends operands) gave every instruction after the
 *      first too many operands -> kLiftedMismatchedISEL -> lift stopped after one
 *      instruction.
 * Both are fixed in remill_wrapper.cpp. `mov x0,#1; ret`, a full
 * stp/mov/add/ldp/ret prologue, and a bl+cbz+ret function now lift to complete,
 * valid aarch64 LLVM IR. (Helix structuring of ARM64 IR is a separate downstream
 * concern and may still stub.)
 */
const ARCH_MAP: Record<string, string> = {
	'x86': 'x86',
	'x64': 'amd64',
	'arm64': 'aarch64',
};

/**
 * Mapeia uma arquitetura Capstone para a equivalente no Remill.
 * @param arch Arquitetura Capstone (ex: 'x86', 'x64', 'arm64')
 * @param os Sistema operacional opcional (auto-detectado se omitido)
 */
export function mapCapstoneToRemill(arch: ArchitectureConfig, os?: string): ArchMapResult {
	const remillArch = ARCH_MAP[arch];
	if (!remillArch) {
		return { supported: false, remillArch: '' };
	}
	return {
		supported: true,
		remillArch,
		remillOs: os ?? detectOs(),
	};
}

/**
 * Verifica se uma arquitetura Capstone possui suporte no Remill.
 */
export function isArchSupported(arch: ArchitectureConfig): boolean {
	return arch in ARCH_MAP;
}

/**
 * Serializa o mapeamento de arquiteturas para JSON.
 */
export function serializeArchMap(): string {
	return JSON.stringify(ARCH_MAP);
}

/**
 * Reconstrói o mapeamento de arquiteturas a partir de JSON serializado.
 */
export function deserializeArchMap(json: string): Record<string, string> {
	return JSON.parse(json);
}

/**
 * Detecta o sistema operacional atual para semânticas do Remill.
 */
function detectOs(): string {
	switch (process.platform) {
		case 'win32': return 'windows';
		case 'darwin': return 'macos';
		default: return 'linux';
	}
}

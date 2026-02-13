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
 * Mapeamento estático Capstone → Remill.
 * Apenas arquiteturas com suporte completo no Remill são incluídas.
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

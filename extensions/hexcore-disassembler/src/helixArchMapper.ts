/*---------------------------------------------------------------------------------------------
 *  HexCore Helix Architecture Mapper
 *  Maps ArchitectureConfig (Capstone) → Helix Architecture enum values.
 *---------------------------------------------------------------------------------------------*/

import type { ArchitectureConfig } from './capstoneWrapper';

/**
 * Helix Architecture enum values (mirrors index.d.ts const enum).
 * Values must match the native module exactly.
 */
export const HelixArch = {
	X86: 0,
	X86_64: 1,
	Arm: 2,
	Aarch64: 3,
	Mips: 4,
	Mips64: 5,
	PowerPc: 6,
	PowerPc64: 7,
	Sparc: 8,
	Sparc64: 9,
	Riscv32: 10,
	Riscv64: 11,
} as const;

export type HelixArchValue = (typeof HelixArch)[keyof typeof HelixArch];

/** Mapeamento Capstone → Helix */
const ARCH_MAP: Partial<Record<ArchitectureConfig, HelixArchValue>> = {
	'x86': HelixArch.X86,
	'x64': HelixArch.X86_64,
	'arm': HelixArch.Arm,
	'arm64': HelixArch.Aarch64,
	'mips': HelixArch.Mips,
	'mips64': HelixArch.Mips64,
};

export function mapCapstoneToHelix(arch: ArchitectureConfig): { supported: boolean; helixArch: HelixArchValue } {
	const helixArch = ARCH_MAP[arch];
	if (helixArch === undefined) {
		return { supported: false, helixArch: HelixArch.X86_64 };
	}
	return { supported: true, helixArch };
}

export function isHelixArchSupported(arch: ArchitectureConfig): boolean {
	return arch in ARCH_MAP;
}

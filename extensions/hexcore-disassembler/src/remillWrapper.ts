/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';
import { loadNativeModule } from 'hexcore-common';
import type { ArchitectureConfig } from './capstoneWrapper';
import { CapstoneWrapper } from './capstoneWrapper';
import { mapCapstoneToRemill, isArchSupported } from './archMapper';
import { deflattenCallfuscation } from './pathfinder';

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
	liftBytes(code: Buffer | Uint8Array, address: number | bigint, options?: RemillLiftOptions): LiftResult;
	liftBytesAsync(code: Buffer | Uint8Array, address: number | bigint, options?: RemillLiftOptions): Promise<LiftResult>;
	getArch(): string;
	close(): void;
	isOpen(): boolean;
	setExternalSymbols?(map: Record<string, string>): number;
	clearExternalSymbols?(): void;
}

/**
 * Lifting mode — selects format-specific heuristics in Phase 1.
 */
export type LiftMode = 'generic' | 'pe64' | 'elf_relocatable';

/**
 * Options passed to the native Remill lifter.
 */
export interface RemillLiftOptions {
	/** Max decoded instructions per lift */
	maxInstructions?: number;
	/** Max discovered basic block leaders per lift */
	maxBasicBlocks?: number;
	/** Max bytes decoded from the input buffer */
	maxBytes?: number;
	/** Record external call targets when direct calls leave the lifted range */
	splitAtCalls?: boolean;
	/** Run LLVM cleanup and simplification passes after lifting */
	optimizeIR?: boolean;
	/** Inline semantic helper functions */
	inlineSemantics?: boolean;
	/** Logical function entry when the supplied buffer begins at an earlier VA. */
	entryAddress?: number;
	/** Emit only instructions reachable from entryAddress after decoding the buffer. */
	reachableOnly?: boolean;
	/** Extra BB entry points from external analysis (jump tables, .pdata, symtab) */
	additionalLeaders?: number[];
	/** Format-specific lifting mode */
	liftMode?: LiftMode;
	/** PE64: function end addresses from .pdata */
	knownFunctionEnds?: number[];
	/**
	 * Instruction-aware callfuscation deflattening (call-as-jmp rewrite) before
	 * lifting. The wrapper decodes real instruction boundaries with Capstone and
	 * applies a ratio gate before rewriting.
	 */
	deflattenCallfuscation?: boolean;
	/**
	 * FIX-052b — opt-in CFG-preserving optimization pipeline. When true, the native
	 * lifter drops SimplifyCFG (whose block merging collapses a deflattened jmp-chain
	 * into a single straight-line block) and runs SROA in PreserveCFG mode, so the
	 * recovered multi-block CFG survives to Helix. Default off — NORMAL lifts keep the
	 * full SimplifyCFG + SROA(ModifyCFG) cleanup. Set only on the deflattened path.
	 */
	preserveCfgTopology?: boolean;
}

/**
 * Resultado de uma operação de lifting.
 */
export interface LiftResult {
	/** Se o lifting foi bem-sucedido */
	success: boolean;
	/** Semantic status is independent from transport/file-write success. */
	status?: 'ok' | 'partial';
	/** Texto LLVM IR gerado */
	ir: string;
	/** Mensagem de erro (vazia se sucesso) */
	error: string;
	/** Endereço base usado no lifting */
	address: number;
	/** Endereço originalmente solicitado antes de backtrack/preamble handling. */
	requestedAddress?: number;
	/** Transformações explícitas aplicadas antes de entregar bytes ao lifter. */
	liftTransformations?: Array<{
		kind: 'cet-preamble' | 'ftrace-preamble';
		address: number;
		bytes: number;
	}>;
	/** Quantidade de bytes consumidos pelo lifter */
	bytesConsumed: number;
	decodedInstructions?: number;
	liftedInstructions?: number;
	unsupportedInstructions?: number;
	decodeFailureInstructions?: number;
	semanticCoverage?: number;
	/** Native limit state; false means maxInstructions/maxBlocks/maxBytes were not exhausted. */
	truncated?: boolean;
	nextAddress?: number;
	truncationReason?: 'max_instructions' | 'max_blocks' | 'max_bytes';
	/** Bytes decoded relative to the explicit lift window. */
	requestedWindowCoverage?: number;
	/** Bytes decoded relative to an authoritative whole-function extent. */
	decodedByteCoverage?: number;
	functionBoundaryKnown?: boolean;
	unsupportedOpcodes?: Record<string, number>;
	semanticWarning?: string;
	/** Pipeline-level metadata: caller intentionally requested a bounded sample. */
	scopeLimited?: boolean;
	requestedInstructionLimit?: number;
	/** External call targets discovered during lifting (Phase 3) */
	callTargets?: number[];
	/** Implicit parameters (registers read before written) */
	implicitParams?: string[];
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
	private currentOs?: string;

	private ensureLifter(arch: ArchitectureConfig, targetOs?: string): RemillLifterInstance {
		const mapping = mapCapstoneToRemill(arch, targetOs);
		if (!mapping.supported) {
			throw new Error(`Architecture '${arch}' is not supported by Remill. Supported: x86, x64, arm64.`);
		}

		const effectiveOs = mapping.remillOs ?? 'linux';

		// Reutilizar instância existente se mesma arquitetura E mesmo OS
		if (this.lifter && this.currentArch === mapping.remillArch && this.currentOs === effectiveOs) {
			return this.lifter;
		}

		// Fechar instância anterior se existir (arch or OS changed)
		if (this.lifter) {
			this.lifter.close();
			this.lifter = undefined;
		}

		this.lifter = new this.module!.RemillLifter(mapping.remillArch, effectiveOs);
		this.currentArch = mapping.remillArch;
		this.currentOs = effectiveOs;
		return this.lifter;
	}

	/**
	 * FIX-011: Set external symbol map for ET_REL relocation resolution.
	 * Called before liftBytes() so the C++ Phase 5.6 can inject declares
	 * into the LLVM Module directly.
	 * @param symbols Map of fakeAddr → symbolName
	 */
	setExternalSymbols(symbols: Map<number, string>): void {
		if (!this.lifter?.setExternalSymbols) { return; }
		const map: Record<string, string> = {};
		for (const [addr, name] of symbols) {
			map[String(addr)] = name;
		}
		this.lifter.setExternalSymbols(map);
	}

	/**
	 * FIX-011: Clear external symbol map after lifting.
	 */
	clearExternalSymbols(): void {
		this.lifter?.clearExternalSymbols?.();
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
	 * @param targetOs OS do binário alvo (overrides host OS detection).
	 *                 Use 'linux' for ELF/.ko, 'windows' for PE, etc.
	 * @param liftOptions Optional native lift options (additionalLeaders, liftMode, etc.)
	 */
	async liftBytes(
		buffer: Buffer | Uint8Array,
		address: number,
		arch: ArchitectureConfig,
		targetOs?: string,
		liftOptions?: RemillLiftOptions,
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
			// Callfuscation deflattening is gated by Capstone instruction boundaries.
			// Raw byte scanning is not safe here because 0xE8 also occurs in operands/data.
			if ((arch === 'x64' || arch === 'x86') && liftOptions?.deflattenCallfuscation === true) {
				const source = Buffer.from(buffer);
				const decoder = new CapstoneWrapper();
				let df;
				try {
					await decoder.initialize(arch);
					const decoded = await decoder.disassemble(
						source,
						address,
						Math.min(liftOptions.maxInstructions ?? 256_000, 256_000),
					);
					const calls = decoded.filter(instruction =>
						instruction.isCall && instruction.size === 5 && instruction.bytes[0] === 0xe8);
					const instructionOffsets = new Set(calls.map(instruction => instruction.address - address));
					df = deflattenCallfuscation(source, address, {
						instructionOffsets,
						decodedCallCount: calls.length,
					});
				} finally {
					decoder.dispose();
				}
				if (df.applied) {
					buffer = df.patched;
					console.log(`[remill] instruction-aware callfuscation deflattening: ${df.linkCount} call->jmp, ` +
						`${df.popsNeutralized} pop discards neutralized`);
					// FIX-052b: the deflattened body is a long jmp-chain whose recovered
					// multi-block CFG must survive to Helix. SimplifyCFG would merge the
					// single-pred/single-succ spine into one block, so request the
					// native CFG-preserving optimization pipeline for THIS lift only.
					// Normal (non-deflattened) lifts never set this and keep the full
					// SimplifyCFG + SROA(ModifyCFG) cleanup.
					liftOptions = {
						...liftOptions,
						preserveCfgTopology: true,
						additionalLeaders: [...new Set([
							...(liftOptions.additionalLeaders ?? []),
							...df.targetAddresses,
						])],
					};
				}
			}

			const lifter = this.ensureLifter(arch, targetOs);

			// Build the native options object if provided
			const nativeOpts = liftOptions ? this.buildNativeOptions(liftOptions) : undefined;

			if (buffer.length > ASYNC_THRESHOLD) {
				return nativeOpts
					? await lifter.liftBytesAsync(buffer, address, nativeOpts)
					: await lifter.liftBytesAsync(buffer, address);
			}

			return nativeOpts
				? lifter.liftBytes(buffer, address, nativeOpts)
				: lifter.liftBytes(buffer, address);
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
	 * Remove a redundant `declare <ty> @NAME(...)` line when the SAME module
	 * already contains `define <ty> ... @NAME(`. Such a declare is both
	 * provably redundant AND an invalid redefinition that makes the LLVM textual
	 * parser (hence Helix stage 1) reject the whole module -> 8-line stub.
	 *
	 * Root cause: the native Remill Phase 5.6 external-symbol injector
	 * (remill_wrapper.cpp `getOrCreateExtern`) declares every name in
	 * externalSymbols_ but only de-dups against its own local cache, never
	 * consulting liftModule->getFunction. A callfuscated function that takes its
	 * own address has its symbol mapped into externalSymbols_, so it gets
	 * `declare ptr @<self>(...)` appended next to its own `define`.
	 *
	 * SAFE: a declare is stripped ONLY when its exact @NAME also appears as a
	 * `define ... @NAME(` in the very same text. A legitimately-external
	 * declaration (mutex_lock, __fentry__, ...) has no matching define and is
	 * never touched. Idempotent; a strict no-op on any collision-free module.
	 *
	 * IMPORTANT: must run AFTER the `lifted_<addr>` -> real-symbol rename
	 * (extension.ts liftToIR), because the native lifter names the define
	 * `lifted_<decimal>` while the spurious declare already carries the real
	 * symbol name -- the define/declare names only collide once the rename has
	 * happened. Running it on the raw native `result.ir` (pre-rename) is a no-op.
	 */
	static dedupSelfDeclares(ir: string): string {
		if (!ir || ir.indexOf('declare') < 0) { return ir; }
		const defined = new Set<string>();
		const defRe = /^define\b[^@\n]*@("[^"]+"|[A-Za-z0-9._$-]+)\s*\(/gm;
		let m: RegExpExecArray | null;
		while ((m = defRe.exec(ir)) !== null) { defined.add(m[1]); }
		if (defined.size === 0) { return ir; }
		const declRe = /^declare\b[^@\n]*@("[^"]+"|[A-Za-z0-9._$-]+)\s*\([^\n]*\)\s*$/;
		const out: string[] = [];
		let stripped = 0;
		for (const line of ir.split('\n')) {
			const dm = declRe.exec(line);
			if (dm && defined.has(dm[1])) { stripped++; continue; }
			out.push(line);
		}
		if (stripped > 0) {
			console.warn(`[remill] dedupSelfDeclares: stripped ${stripped} redundant self-declare(s) ` +
				`(callfuscation self-reference: declare collided with an in-module define)`);
		}
		return out.join('\n');
	}

	/**
	 * Convert TypeScript LiftOptions into the plain object the native module expects.
	 */
	private buildNativeOptions(opts: RemillLiftOptions): Record<string, unknown> {
		const native: Record<string, unknown> = {};
		if (opts.maxInstructions !== undefined) { native.maxInstructions = opts.maxInstructions; }
		if (opts.maxBasicBlocks !== undefined) { native.maxBasicBlocks = opts.maxBasicBlocks; }
		if (opts.maxBytes !== undefined) { native.maxBytes = opts.maxBytes; }
		if (opts.splitAtCalls !== undefined) { native.splitAtCalls = opts.splitAtCalls; }
		if (opts.optimizeIR !== undefined) { native.optimizeIR = opts.optimizeIR; }
		if (opts.inlineSemantics !== undefined) { native.inlineSemantics = opts.inlineSemantics; }
		if (opts.entryAddress !== undefined) { native.entryAddress = opts.entryAddress; }
		if (opts.reachableOnly !== undefined) { native.reachableOnly = opts.reachableOnly; }
		if (opts.preserveCfgTopology !== undefined) { native.preserveCfgTopology = opts.preserveCfgTopology; }
		if (opts.additionalLeaders?.length) { native.additionalLeaders = opts.additionalLeaders; }
		if (opts.liftMode) { native.liftMode = opts.liftMode; }
		if (opts.knownFunctionEnds?.length) { native.knownFunctionEnds = opts.knownFunctionEnds; }
		return native;
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

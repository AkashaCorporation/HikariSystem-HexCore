/*---------------------------------------------------------------------------------------------
 * Jump-table case-target recovery for Remill additionalLeaders (issue #51)
 *
 * RecoverSwitchTables in Helix can enumerate table entries only when Remill
 * already materialised the case bodies as basic blocks. Indirect `jmp reg`
 * (incl. CET `notrack jmp reg`) is a black hole unless we inject the N targets
 * as Phase-1.5 leaders.
 *
 * Patterns (x64):
 *   MSVC/GCC classic:
 *     cmp  reg, N
 *     ja   default
 *     lea  base, [rip+TABLE]
 *     movsxd idx, [base+reg*4]
 *     add  idx, base
 *     jmp  idx                 ; or: notrack jmp idx  (CET)
 *
 *   Table base may be live in a callee-saved reg (r12…) loaded earlier via LEA;
 *   we resolve that by scanning further back for `lea baseReg, [rip±off]`.
 *
 * Table entries are 32-bit signed PIC offsets relative to the table base.
 *---------------------------------------------------------------------------------------------*/

export interface JumpTableHit {
	/** Address of the indirect jmp */
	jmpAddress: number;
	/** Absolute VA of the jump table */
	tableAddress: number;
	/** Absolute case-handler VAs (deduped) */
	targets: number[];
	/** Upper bound used (cmp imm + 1) */
	entryCount: number;
}

export interface DecodedInsnLike {
	address: number;
	size: number;
	mnemonic: string;
	opStr?: string;
	isJump?: boolean;
	isConditional?: boolean;
	/** Defined for direct jumps only — absent/undefined means register/memory target */
	targetAddress?: number;
}

const GPR = 'rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|eax|ebx|ecx|edx|esi|edi|ebp|esp';

/**
 * Detect PIC jump tables from a linear decode of a function and return case
 * targets. `readAbs` maps an absolute VA to raw bytes (engine.getBytes).
 */
export function recoverJumpTableTargets(
	insns: ReadonlyArray<DecodedInsnLike>,
	readAbs: (va: number, size: number) => Buffer | undefined,
	opts?: {
		/** Max absolute distance jmp→target (default 1 MiB) */
		maxTargetDistance?: number;
		/** Max table entries (default 1024) */
		maxEntries?: number;
	},
): JumpTableHit[] {
	const maxDist = opts?.maxTargetDistance ?? 0x100000;
	const maxEntriesCap = opts?.maxEntries ?? 1024;
	const hits: JumpTableHit[] = [];

	for (let i = 0; i < insns.length; i++) {
		const insn = insns[i];
		if (!isIndirectRegJmp(insn)) { continue; }

		// Backward slice: enough room to catch an early LEA of the table base.
		// threadweaver loads r12 ~130 insns / ~500 bytes before the dispatch
		// (lea sits in a cold setup block well above the menu switch).
		const sliceStart = Math.max(0, i - 200);
		const slice = insns.slice(sliceStart, i + 1);

		let tableBase: number | undefined;
		let tableAddress: number | undefined;
		let tableDisplacement = 0;
		let maxEntries: number | undefined;
		let baseReg: string | undefined;

		// Pass 1: near-pattern (last ~12 insns) — cmp bound + movsxd [base+idx*4]
		// Do NOT grab a random nearby `lea rdi, [rip+…]` as the table base —
		// those are often string pointers (printf args). Prefer movsxd's base
		// register, then resolve it via a matching lea later.
		const near = slice.slice(-12);
		for (const s of near) {
			const sm = (s.mnemonic || '').toLowerCase();
			const so = s.opStr || '';

			if (sm === 'cmp' && maxEntries === undefined) {
				const imm = extractTrailingImm(so);
				// cmp reg, 7 → 8 cases (0..7)
				if (imm !== undefined && imm >= 1 && imm < 4096) {
					maxEntries = imm + 1;
				}
			}

			// movsxd rax, dword ptr [r12 + rax*4]
			const ms = so.match(new RegExp(
				`dword ptr\\s*\\[\\s*(${GPR})\\s*\\+\\s*(?:${GPR})\\s*\\*\\s*4(?:\\s*([+-])\\s*(0x[0-9a-fA-F]+|[0-9]+))?\\s*\\]`,
				'i',
			)) || so.match(new RegExp(
				`\\[\\s*(${GPR})\\s*\\+\\s*(?:${GPR})\\s*\\*\\s*4(?:\\s*([+-])\\s*(0x[0-9a-fA-F]+|[0-9]+))?\\s*\\]`,
				'i',
			));
			if ((sm === 'movsxd' || sm === 'movsx' || sm === 'mov') && ms) {
				baseReg = ms[1].toLowerCase();
				if (ms[3]) {
					const displacement = Number.parseInt(ms[3], ms[3].toLowerCase().startsWith('0x') ? 16 : 10);
					tableDisplacement = ms[2] === '-' ? -displacement : displacement;
				}
			}
		}

		// Pass 2: resolve tableBase = lea baseReg, [rip±off] (anywhere in slice)
		if (baseReg) {
			for (const s of slice) {
				const sm = (s.mnemonic || '').toLowerCase();
				const so = s.opStr || '';
				if (sm !== 'lea' || !/rip/i.test(so)) { continue; }
				const dest = so.split(',')[0]?.trim().toLowerCase();
				if (dest !== baseReg && dest !== baseReg.replace(/^r/, 'e')) { continue; }
				const ripOff = extractRipRelativeOffset(so);
				if (ripOff !== undefined) {
					tableBase = s.address + s.size + ripOff;
					// keep scanning — prefer the latest lea of baseReg before the jmp
				}
			}
		}

		// Pass 3: classic path — lea of SOME reg immediately before jmp when
		// movsxd form was not seen (lea base; movsxd; add; jmp with base=lea dest)
		if (tableBase === undefined) {
			for (const s of near) {
				const sm = (s.mnemonic || '').toLowerCase();
				const so = s.opStr || '';
				if (sm !== 'lea' || !/rip/i.test(so)) { continue; }
				const ripOff = extractRipRelativeOffset(so);
				if (ripOff === undefined) { continue; }
				// Only accept if the lea dest is later used as the PIC base in add/movsxd
				const dest = so.split(',')[0]?.trim().toLowerCase();
				if (!dest) { continue; }
				const usedAsBase = near.some(n => {
					const nm = (n.mnemonic || '').toLowerCase();
					const no = n.opStr || '';
					if (nm === 'movsxd' || nm === 'movsx') {
						return new RegExp(`\\[\\s*${dest}\\s*\\+`, 'i').test(no);
					}
					if (nm === 'add') {
						return new RegExp(`,\\s*${dest}\\s*$`, 'i').test(no);
					}
					return false;
				});
				if (usedAsBase) {
					tableBase = s.address + s.size + ripOff;
					baseReg = dest;
				}
			}
		}

		if (tableBase === undefined || maxEntries === undefined) { continue; }
		tableAddress = tableBase + tableDisplacement;

		const n = Math.min(maxEntries, maxEntriesCap);
		const tableBytes = readAbs(tableAddress, n * 4);
		if (!tableBytes || tableBytes.length < 8) { continue; }

		const targets: number[] = [];
		const entries = Math.floor(tableBytes.length / 4);
		for (let e = 0; e < entries; e++) {
			const rel = tableBytes.readInt32LE(e * 4);
			const target = tableBase + rel;
			if (Math.abs(target - insn.address) > maxDist) { break; }
			if (target < 0x10000) { break; }
			// Do NOT mask to 32 bits — PIE VAs live above 4 GiB (#37 Bug 3).
			targets.push(target);
		}

		const unique = [...new Set(targets)];
		if (unique.length < 2) { continue; }

		hits.push({
			jmpAddress: insn.address,
			tableAddress,
			targets: unique,
			entryCount: n,
		});
	}

	return hits;
}

/** Flatten + dedupe all case targets from hits, optionally filtered to [lo, hi). */
export function collectJumpTableLeaders(
	hits: ReadonlyArray<JumpTableHit>,
	range?: { lo: number; hi: number },
): number[] {
	const set = new Set<number>();
	for (const h of hits) {
		for (const t of h.targets) {
			if (range && (t < range.lo || t >= range.hi)) { continue; }
			set.add(t);
		}
	}
	return [...set].sort((a, b) => a - b);
}

/**
 * Capstone may emit mnemonic `notrack jmp` and leave isJump=false (CET).
 * Treat any `*jmp` to a bare register as an indirect reg dispatch.
 */
export function isIndirectRegJmp(insn: DecodedInsnLike): boolean {
	const m = (insn.mnemonic || '').toLowerCase().trim();
	// `jmp`, `notrack jmp`, `rex.w jmp`, etc.
	if (!(m === 'jmp' || m.endsWith(' jmp') || m.includes('jmp'))) {
		return false;
	}
	// Direct jmp with resolved target — not our case
	if (insn.targetAddress !== undefined && insn.targetAddress !== 0) {
		return false;
	}
	// Conditional jumps are not switch dispatch
	if (insn.isConditional) {
		return false;
	}
	const op = (insn.opStr || '').trim().toLowerCase();
	if (!op || op.includes('[') || op.includes('ptr')) {
		return false;
	}
	return new RegExp(`^(${GPR})$`, 'i').test(op);
}

function extractTrailingImm(opStr: string): number | undefined {
	const hex = opStr.match(/,\s*0x([0-9a-fA-F]+)\s*$/i);
	if (hex) { return Number.parseInt(hex[1], 16); }
	const dec = opStr.match(/,\s*(\d+)\s*$/);
	if (dec) { return Number.parseInt(dec[1], 10); }
	return undefined;
}

function extractRipRelativeOffset(opStr: string): number | undefined {
	const m = opStr.match(/\[rip\s*([+-])\s*(?:0x)?([0-9a-fA-F]+)\]/i);
	if (!m) { return undefined; }
	const val = Number.parseInt(m[2], 16);
	return m[1] === '-' ? -val : val;
}

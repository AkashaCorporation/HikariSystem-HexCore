/**
 * HexCore Unicorn - TypeScript Definitions
 *
 * HikariSystem HexCore - CPU Emulator
 * Type definitions for Unicorn Engine bindings
 *
 * @module hexcore-unicorn
 */

// ============== Architecture Constants ==============

export interface ArchConstants {
    readonly ARM: number;
    readonly ARM64: number;
    readonly MIPS: number;
    readonly X86: number;
    readonly PPC: number;
    readonly SPARC: number;
    readonly M68K: number;
    readonly RISCV: number;
    readonly S390X: number;
    readonly TRICORE: number;

    // Raw constants
    readonly UC_ARCH_ARM: number;
    readonly UC_ARCH_ARM64: number;
    readonly UC_ARCH_MIPS: number;
    readonly UC_ARCH_X86: number;
    readonly UC_ARCH_PPC: number;
    readonly UC_ARCH_SPARC: number;
    readonly UC_ARCH_M68K: number;
    readonly UC_ARCH_RISCV: number;
    readonly UC_ARCH_S390X: number;
    readonly UC_ARCH_TRICORE: number;
}

// ============== Mode Constants ==============

export interface ModeConstants {
    // Endianness
    readonly LITTLE_ENDIAN: number;
    readonly BIG_ENDIAN: number;

    // X86 modes
    readonly MODE_16: number;
    readonly MODE_32: number;
    readonly MODE_64: number;

    // ARM modes
    readonly UC_MODE_ARM: number;
    readonly UC_MODE_THUMB: number;
    readonly UC_MODE_MCLASS: number;
    readonly UC_MODE_V8: number;
    readonly UC_MODE_ARMBE8: number;

    // MIPS modes
    readonly UC_MODE_MIPS3: number;
    readonly UC_MODE_MIPS32R6: number;
    readonly UC_MODE_MIPS32: number;
    readonly UC_MODE_MIPS64: number;

    // SPARC modes
    readonly UC_MODE_SPARC32: number;
    readonly UC_MODE_SPARC64: number;
    readonly UC_MODE_V9: number;

    // PPC modes
    readonly UC_MODE_PPC32: number;
    readonly UC_MODE_PPC64: number;
    readonly UC_MODE_QPX: number;

    // RISCV modes
    readonly UC_MODE_RISCV32: number;
    readonly UC_MODE_RISCV64: number;

    // Raw constants
    readonly UC_MODE_LITTLE_ENDIAN: number;
    readonly UC_MODE_BIG_ENDIAN: number;
    readonly UC_MODE_16: number;
    readonly UC_MODE_32: number;
    readonly UC_MODE_64: number;
}

// ============== Memory Protection Constants ==============

export interface ProtConstants {
    readonly NONE: number;
    readonly READ: number;
    readonly WRITE: number;
    readonly EXEC: number;
    readonly ALL: number;
    readonly RW: number;
    readonly RX: number;
    readonly RWX: number;

    // Raw constants
    readonly UC_PROT_NONE: number;
    readonly UC_PROT_READ: number;
    readonly UC_PROT_WRITE: number;
    readonly UC_PROT_EXEC: number;
    readonly UC_PROT_ALL: number;
}

// ============== Hook Type Constants ==============

export interface HookConstants {
    // Friendly names
    readonly INTR: number;
    readonly INSN: number;
    readonly CODE: number;
    readonly BLOCK: number;
    readonly MEM_READ: number;
    readonly MEM_WRITE: number;
    readonly MEM_FETCH: number;
    readonly MEM_ALL: number;

    // Raw constants
    readonly UC_HOOK_INTR: number;
    readonly UC_HOOK_INSN: number;
    readonly UC_HOOK_CODE: number;
    readonly UC_HOOK_BLOCK: number;
    readonly UC_HOOK_MEM_READ_UNMAPPED: number;
    readonly UC_HOOK_MEM_WRITE_UNMAPPED: number;
    readonly UC_HOOK_MEM_FETCH_UNMAPPED: number;
    readonly UC_HOOK_MEM_READ_PROT: number;
    readonly UC_HOOK_MEM_WRITE_PROT: number;
    readonly UC_HOOK_MEM_FETCH_PROT: number;
    readonly UC_HOOK_MEM_READ: number;
    readonly UC_HOOK_MEM_WRITE: number;
    readonly UC_HOOK_MEM_FETCH: number;
    readonly UC_HOOK_MEM_READ_AFTER: number;
    readonly UC_HOOK_MEM_UNMAPPED: number;
    readonly UC_HOOK_MEM_PROT: number;
    readonly UC_HOOK_MEM_READ_INVALID: number;
    readonly UC_HOOK_MEM_WRITE_INVALID: number;
    readonly UC_HOOK_MEM_FETCH_INVALID: number;
    readonly UC_HOOK_MEM_INVALID: number;
    readonly UC_HOOK_MEM_VALID: number;
    readonly UC_HOOK_INSN_INVALID: number;
    readonly UC_HOOK_EDGE_GENERATED: number;
    readonly UC_HOOK_TCG_OPCODE: number;
}

// ============== Memory Access Type Constants ==============

export interface MemConstants {
    readonly UC_MEM_READ: number;
    readonly UC_MEM_WRITE: number;
    readonly UC_MEM_FETCH: number;
    readonly UC_MEM_READ_UNMAPPED: number;
    readonly UC_MEM_WRITE_UNMAPPED: number;
    readonly UC_MEM_FETCH_UNMAPPED: number;
    readonly UC_MEM_WRITE_PROT: number;
    readonly UC_MEM_READ_PROT: number;
    readonly UC_MEM_FETCH_PROT: number;
    readonly UC_MEM_READ_AFTER: number;
}

// ============== Query Type Constants ==============

export interface QueryConstants {
    readonly MODE: number;
    readonly PAGE_SIZE: number;
    readonly ARCH: number;

    readonly UC_QUERY_MODE: number;
    readonly UC_QUERY_PAGE_SIZE: number;
    readonly UC_QUERY_ARCH: number;
    readonly UC_QUERY_TIMEOUT: number;
}

// ============== Error Constants ==============

export interface ErrConstants {
    readonly OK: number;
    readonly NOMEM: number;
    readonly ARCH: number;
    readonly HANDLE: number;
    readonly MODE: number;

    readonly UC_ERR_OK: number;
    readonly UC_ERR_NOMEM: number;
    readonly UC_ERR_ARCH: number;
    readonly UC_ERR_HANDLE: number;
    readonly UC_ERR_MODE: number;
    readonly UC_ERR_VERSION: number;
    readonly UC_ERR_READ_UNMAPPED: number;
    readonly UC_ERR_WRITE_UNMAPPED: number;
    readonly UC_ERR_FETCH_UNMAPPED: number;
    readonly UC_ERR_HOOK: number;
    readonly UC_ERR_INSN_INVALID: number;
    readonly UC_ERR_MAP: number;
    readonly UC_ERR_WRITE_PROT: number;
    readonly UC_ERR_READ_PROT: number;
    readonly UC_ERR_FETCH_PROT: number;
    readonly UC_ERR_ARG: number;
    readonly UC_ERR_READ_UNALIGNED: number;
    readonly UC_ERR_WRITE_UNALIGNED: number;
    readonly UC_ERR_FETCH_UNALIGNED: number;
    readonly UC_ERR_HOOK_EXIST: number;
    readonly UC_ERR_RESOURCE: number;
    readonly UC_ERR_EXCEPTION: number;
}

// ============== X86 Register Constants ==============

export interface X86RegConstants {
    // 64-bit general purpose
    readonly RAX: number;
    readonly RBX: number;
    readonly RCX: number;
    readonly RDX: number;
    readonly RSI: number;
    readonly RDI: number;
    readonly RBP: number;
    readonly RSP: number;
    readonly R8: number;
    readonly R9: number;
    readonly R10: number;
    readonly R11: number;
    readonly R12: number;
    readonly R13: number;
    readonly R14: number;
    readonly R15: number;
    readonly RIP: number;
    readonly RFLAGS: number;

    // 32-bit general purpose
    readonly EAX: number;
    readonly EBX: number;
    readonly ECX: number;
    readonly EDX: number;
    readonly ESI: number;
    readonly EDI: number;
    readonly EBP: number;
    readonly ESP: number;
    readonly EIP: number;
    readonly EFLAGS: number;

    // 16-bit
    readonly AX: number;
    readonly BX: number;
    readonly CX: number;
    readonly DX: number;
    readonly SI: number;
    readonly DI: number;
    readonly BP: number;
    readonly SP: number;
    readonly IP: number;

    // 8-bit
    readonly AL: number;
    readonly AH: number;
    readonly BL: number;
    readonly BH: number;
    readonly CL: number;
    readonly CH: number;
    readonly DL: number;
    readonly DH: number;

    // Segment registers
    readonly CS: number;
    readonly DS: number;
    readonly ES: number;
    readonly FS: number;
    readonly GS: number;
    readonly SS: number;

    // Control registers
    readonly CR0: number;
    readonly CR2: number;
    readonly CR3: number;
    readonly CR4: number;
    readonly CR8: number;

    // Debug registers
    readonly DR0: number;
    readonly DR1: number;
    readonly DR2: number;
    readonly DR3: number;
    readonly DR6: number;
    readonly DR7: number;

    // FPU registers
    readonly FP0: number;
    readonly FP1: number;
    readonly FP2: number;
    readonly FP3: number;
    readonly FP4: number;
    readonly FP5: number;
    readonly FP6: number;
    readonly FP7: number;

    // XMM registers
    readonly XMM0: number;
    readonly XMM1: number;
    readonly XMM2: number;
    readonly XMM3: number;
    readonly XMM4: number;
    readonly XMM5: number;
    readonly XMM6: number;
    readonly XMM7: number;
    readonly XMM8: number;
    readonly XMM9: number;
    readonly XMM10: number;
    readonly XMM11: number;
    readonly XMM12: number;
    readonly XMM13: number;
    readonly XMM14: number;
    readonly XMM15: number;

    // YMM registers
    readonly YMM0: number;
    readonly YMM1: number;
    readonly YMM2: number;
    readonly YMM3: number;
    readonly YMM4: number;
    readonly YMM5: number;
    readonly YMM6: number;
    readonly YMM7: number;
    readonly YMM8: number;
    readonly YMM9: number;
    readonly YMM10: number;
    readonly YMM11: number;
    readonly YMM12: number;
    readonly YMM13: number;
    readonly YMM14: number;
    readonly YMM15: number;

    // Other
    readonly MSR: number;
    readonly MXCSR: number;
    readonly GDTR: number;
    readonly IDTR: number;
    readonly LDTR: number;
    readonly TR: number;
    readonly FS_BASE: number;
    readonly GS_BASE: number;
}

// ============== ARM Register Constants ==============

export interface ArmRegConstants {
    readonly R0: number;
    readonly R1: number;
    readonly R2: number;
    readonly R3: number;
    readonly R4: number;
    readonly R5: number;
    readonly R6: number;
    readonly R7: number;
    readonly R8: number;
    readonly R9: number;
    readonly R10: number;
    readonly R11: number;
    readonly R12: number;
    readonly SP: number;
    readonly LR: number;
    readonly PC: number;
    readonly CPSR: number;
    readonly SPSR: number;
    readonly FP: number;
    readonly IP: number;
}

// ============== ARM64 Register Constants ==============

export interface Arm64RegConstants {
    // 64-bit
    readonly X0: number;
    readonly X1: number;
    readonly X2: number;
    readonly X3: number;
    readonly X4: number;
    readonly X5: number;
    readonly X6: number;
    readonly X7: number;
    readonly X8: number;
    readonly X9: number;
    readonly X10: number;
    readonly X11: number;
    readonly X12: number;
    readonly X13: number;
    readonly X14: number;
    readonly X15: number;
    readonly X16: number;
    readonly X17: number;
    readonly X18: number;
    readonly X19: number;
    readonly X20: number;
    readonly X21: number;
    readonly X22: number;
    readonly X23: number;
    readonly X24: number;
    readonly X25: number;
    readonly X26: number;
    readonly X27: number;
    readonly X28: number;
    readonly X29: number;
    readonly X30: number;

    // 32-bit
    readonly W0: number;
    readonly W1: number;
    readonly W2: number;
    readonly W3: number;
    readonly W4: number;
    readonly W5: number;
    readonly W6: number;
    readonly W7: number;
    readonly W8: number;
    readonly W9: number;
    readonly W10: number;
    readonly W11: number;
    readonly W12: number;
    readonly W13: number;
    readonly W14: number;
    readonly W15: number;
    readonly W16: number;
    readonly W17: number;
    readonly W18: number;
    readonly W19: number;
    readonly W20: number;
    readonly W21: number;
    readonly W22: number;
    readonly W23: number;
    readonly W24: number;
    readonly W25: number;
    readonly W26: number;
    readonly W27: number;
    readonly W28: number;
    readonly W29: number;
    readonly W30: number;

    // Special
    readonly SP: number;
    readonly PC: number;
    readonly NZCV: number;
    readonly FP: number;
    readonly LR: number;

    // SIMD
    readonly Q0: number;
    readonly Q1: number;
    readonly Q2: number;
    readonly Q3: number;
}

// ============== MIPS Register Constants ==============

export interface MipsRegConstants {
    readonly ZERO: number;
    readonly AT: number;
    readonly V0: number;
    readonly V1: number;
    readonly A0: number;
    readonly A1: number;
    readonly A2: number;
    readonly A3: number;
    readonly T0: number;
    readonly T1: number;
    readonly T2: number;
    readonly T3: number;
    readonly T4: number;
    readonly T5: number;
    readonly T6: number;
    readonly T7: number;
    readonly S0: number;
    readonly S1: number;
    readonly S2: number;
    readonly S3: number;
    readonly S4: number;
    readonly S5: number;
    readonly S6: number;
    readonly S7: number;
    readonly T8: number;
    readonly T9: number;
    readonly K0: number;
    readonly K1: number;
    readonly GP: number;
    readonly SP: number;
    readonly FP: number;
    readonly RA: number;
    readonly PC: number;
    readonly HI: number;
    readonly LO: number;
}

// ============== Memory Region ==============

export interface MemoryRegion {
    begin: bigint;
    end: bigint;
    perms: number;
}

// ============== Version Info ==============

export interface VersionInfo {
    major: number;
    minor: number;
    combined: number;
    string: string;
}

// ============== Hook Callbacks ==============

export type CodeHookCallback = (address: bigint, size: number) => void;
export type BlockHookCallback = (address: bigint, size: number) => void;
export type MemHookCallback = (type: number, address: bigint, size: number, value: bigint) => void;
export type InterruptHookCallback = (intno: number) => void;
export type InsnHookCallback = () => void;
export type InvalidMemHookCallback = (type: number, address: bigint, size: number, value: bigint) => boolean;

export type HookCallback =
    | CodeHookCallback
    | BlockHookCallback
    | MemHookCallback
    | InterruptHookCallback
    | InsnHookCallback
    | InvalidMemHookCallback;

// ============== UnicornContext Class ==============

export declare class UnicornContext {
    /**
     * Free the context resources
     */
    free(): void;

    /**
     * Get the size of the context in bytes
     */
    readonly size: number;
}

// ============== Unicorn Class ==============

export declare class Unicorn {
    /**
     * Create a new Unicorn engine instance
     * @param arch - Architecture (ARCH.X86, ARCH.ARM, etc.)
     * @param mode - Mode (MODE.MODE_64, MODE.MODE_32, etc.)
     */
    constructor(arch: number, mode: number);

    // ============== Properties ==============

    /** Architecture of this engine */
    readonly arch: number;

    /** Mode of this engine */
    readonly mode: number;

    /** Raw engine handle (bigint) */
    readonly handle: bigint;

    /** Memory page size */
    readonly pageSize: number;

    // ============== Emulation Control ==============

    /**
     * Start emulation synchronously
     * @param begin - Start address
     * @param until - End address (0 to run until error/hook stop)
     * @param timeout - Timeout in microseconds (0 for no timeout)
     * @param count - Number of instructions to execute (0 for unlimited)
     */
    emuStart(begin: bigint | number, until: bigint | number, timeout?: number, count?: number): void;

    /**
     * Start emulation asynchronously
     * @param begin - Start address
     * @param until - End address
     * @param timeout - Timeout in microseconds
     * @param count - Number of instructions to execute
     * @returns Promise that resolves when emulation completes
     */
    emuStartAsync(begin: bigint | number, until: bigint | number, timeout?: number, count?: number): Promise<void>;

    /**
     * Stop emulation (can be called from hooks)
     */
    emuStop(): void;

    // ============== Memory Operations ==============

    /**
     * Map a memory region
     * @param address - Start address (must be aligned to page size)
     * @param size - Size in bytes (must be multiple of page size)
     * @param perms - Memory permissions (PROT.READ | PROT.WRITE | PROT.EXEC)
     */
    memMap(address: bigint | number, size: number, perms: number): void;

    /**
     * Map a memory region with existing data
     * @param address - Start address
     * @param data - Buffer containing initial data
     * @param perms - Memory permissions
     */
    memMapPtr(address: bigint | number, data: Buffer, perms: number): void;

    /**
     * Unmap a memory region
     * @param address - Start address
     * @param size - Size in bytes
     */
    memUnmap(address: bigint | number, size: number): void;

    /**
     * Change memory permissions
     * @param address - Start address
     * @param size - Size in bytes
     * @param perms - New permissions
     */
    memProtect(address: bigint | number, size: number, perms: number): void;

    /**
     * Read memory
     * @param address - Address to read from
     * @param size - Number of bytes to read
     * @returns Buffer containing the data
     */
    memRead(address: bigint | number, size: number): Buffer;

    /**
     * Write memory
     * @param address - Address to write to
     * @param data - Buffer containing data to write
     */
    memWrite(address: bigint | number, data: Buffer): void;

    /**
     * Get list of mapped memory regions
     * @returns Array of memory region objects
     */
    memRegions(): MemoryRegion[];

    // ============== Register Operations ==============

    /**
     * Read a register value
     * @param regId - Register ID (architecture-specific)
     * @returns Register value (bigint for 64-bit, number for smaller)
     */
    regRead(regId: number): bigint | number;

    /**
     * Write a register value
     * @param regId - Register ID
     * @param value - Value to write
     */
    regWrite(regId: number, value: bigint | number): void;

    /**
     * Read multiple registers at once
     * @param regIds - Array of register IDs
     * @returns Array of values
     */
    regReadBatch(regIds: number[]): (bigint | number)[];

    /**
     * Write multiple registers at once
     * @param regIds - Array of register IDs
     * @param values - Array of values
     */
    regWriteBatch(regIds: number[], values: (bigint | number)[]): void;

    // ============== Hook Operations ==============

    /**
     * Add a hook
     * @param type - Hook type (HOOK.CODE, HOOK.MEM_READ, etc.)
     * @param callback - JavaScript function to call
     * @param begin - Start address (optional, default 1)
     * @param end - End address (optional, default 0 = all addresses)
     * @param extra - Extra argument for instruction hooks (optional)
     * @returns Hook handle (number)
     */
    hookAdd(type: number, callback: HookCallback, begin?: bigint | number, end?: bigint | number, extra?: number): number;

    /**
     * Remove a hook
     * @param hookHandle - Handle returned by hookAdd
     */
    hookDel(hookHandle: number): void;

    /**
     * Add a native breakpoint at the specified address.
     * Stops emulation immediately when execution reaches this address.
     * Much faster than using a JS hook.
     * @param address Address to break at
     */
    breakpointAdd(address: bigint | number): void;

    /**
     * Remove a native breakpoint.
     * @param address Address to remove
     */
    breakpointDel(address: bigint | number): void;

    // ============== Context Operations ==============

    /**
     * Save the current CPU context
     * @returns UnicornContext object
     */
    contextSave(): UnicornContext;

    /**
     * Restore a previously saved context
     * @param context - UnicornContext object
     */
    contextRestore(context: UnicornContext): void;

    /**
     * Save full emulation state (Context + Memory)
     * Useful for taking snapshots.
     * Note: Context is an opaque object, Memory is array of buffers.
     */
    stateSave(): { context: UnicornContext, memory: Array<{ address: bigint, size: number, perms: number, data: Buffer }> };

    /**
     * Restore full emulation state
     * @param state - The object returned by stateSave
     */
    stateRestore(state: { context: UnicornContext, memory: Array<{ address: bigint, size: number, perms: number, data: Buffer }> }): void;

    // ============== Query & Control ==============

    /**
     * Query engine information
     * @param queryType - QUERY.MODE, QUERY.PAGE_SIZE, QUERY.ARCH
     * @returns Query result
     */
    query(queryType: number): number;

    /**
     * Set engine option
     * @param optType - Option type
     * @param value - Option value
     */
    ctlWrite(optType: number, value: number): void;

    /**
     * Get engine option
     * @param optType - Option type
     * @returns Option value
     */
    ctlRead(optType: number): number;

    /**
     * Close the engine and free resources
     */
    close(): void;
}

// ============== Utility Functions ==============

/**
 * Get Unicorn Engine version information
 */
export declare function version(): VersionInfo;

/**
 * Check if an architecture is supported
 * @param arch - Architecture constant
 */
export declare function archSupported(arch: number): boolean;

/**
 * Get error message for an error code
 * @param errorCode - Error code
 */
export declare function strerror(errorCode: number): string;

// ============== Constants ==============

export declare const ARCH: ArchConstants;
export declare const MODE: ModeConstants;
export declare const PROT: ProtConstants;
export declare const HOOK: HookConstants;
export declare const MEM: MemConstants;
export declare const QUERY: QueryConstants;
export declare const ERR: ErrConstants;

export declare const X86_REG: X86RegConstants;
export declare const ARM_REG: ArmRegConstants;
export declare const ARM64_REG: Arm64RegConstants;
export declare const MIPS_REG: MipsRegConstants;

/**
 * hexcore-llvm-mc - LLVM MC-based assembler bindings for Node.js
 * Part of HikariSystem HexCore
 */

/** Assembly result */
export interface AsmResult {
    /** Assembled machine code bytes */
    bytes: Buffer;
    /** Size in bytes */
    size: number;
    /** Address used for assembly */
    address: bigint;
    /** Original assembly statement */
    statement: string;
}

/** Target information */
export interface TargetInfo {
    /** Target name (e.g., "x86-64", "arm") */
    name: string;
    /** Target description */
    description: string;
}

/**
 * LLVM MC Assembler class
 */
export class LlvmMc {
    /**
     * Create a new LLVM MC assembler instance
     * @param triple Target triple (e.g., "x86_64-unknown-unknown")
     * @param cpu Optional CPU name (e.g., "generic", "skylake")
     * @param features Optional CPU features (e.g., "+avx2,+sse4.2")
     */
    constructor(triple: string, cpu?: string, features?: string);

    /**
     * Assemble a single instruction or code block
     * @param code Assembly code to assemble
     * @param address Optional base address for the code
     * @returns Assembly result with machine code bytes
     */
    assemble(code: string, address?: bigint | number): AsmResult;

    /**
     * Assemble code asynchronously
     * @param code Assembly code to assemble
     * @param address Optional base address for the code
     * @returns Promise resolving to assembly result
     */
    assembleAsync(code: string, address?: bigint | number): Promise<AsmResult>;

    /**
     * Assemble multiple instructions
     * @param instructions Array of assembly instructions
     * @param startAddress Optional starting address
     * @returns Array of assembly results
     */
    assembleMultiple(instructions: string[], startAddress?: bigint | number): AsmResult[];

    /**
     * Set assembler option
     * @param option Option type from OPTION constants
     * @param value Option value
     */
    setOption(option: number, value: number | string): void;

    /**
     * Get the target triple
     */
    getTriple(): string;

    /**
     * Get the CPU name
     */
    getCpu(): string;

    /**
     * Get the CPU features string
     */
    getFeatures(): string;

    /**
     * Close and release resources
     */
    close(): void;

    /**
     * Whether the instance is still open
     */
    readonly isOpen: boolean;

    /**
     * Native handle (for advanced use)
     */
    readonly handle: bigint;
}

/** Target triple presets */
export const TRIPLE: {
    // x86
    readonly X86: string;
    readonly X86_64: string;
    readonly I386: string;
    readonly I686: string;

    // ARM
    readonly ARM: string;
    readonly ARMV7: string;
    readonly ARMV8: string;
    readonly THUMB: string;
    readonly THUMBV7: string;

    // ARM64
    readonly ARM64: string;
    readonly AARCH64: string;

    // MIPS
    readonly MIPS: string;
    readonly MIPSEL: string;
    readonly MIPS64: string;
    readonly MIPS64EL: string;

    // PowerPC
    readonly PPC: string;
    readonly PPC64: string;
    readonly PPC64LE: string;

    // SPARC
    readonly SPARC: string;
    readonly SPARCV9: string;
    readonly SPARC64: string;

    // RISC-V
    readonly RISCV32: string;
    readonly RISCV64: string;

    // System Z
    readonly SYSTEMZ: string;
    readonly S390X: string;

    // Hexagon
    readonly HEXAGON: string;

    // WebAssembly
    readonly WASM32: string;
    readonly WASM64: string;

    // BPF
    readonly BPF: string;
    readonly BPFEL: string;
    readonly BPFEB: string;

    // LoongArch
    readonly LOONGARCH32: string;
    readonly LOONGARCH64: string;
};

/** Assembly syntax options */
export const SYNTAX: {
    /** Intel syntax (default for x86) */
    readonly INTEL: number;
    /** AT&T syntax */
    readonly ATT: number;
};

/** Assembler options */
export const OPTION: {
    /** Syntax option */
    readonly SYNTAX: number;
};

/** Error codes */
export const ERR: {
    /** Success */
    readonly OK: number;
    /** Invalid target triple */
    readonly INVALID_TRIPLE: number;
    /** Assembly failed */
    readonly ASM_FAILED: number;
    /** Out of memory */
    readonly NOMEM: number;
    /** Instance closed */
    readonly CLOSED: number;
    /** Invalid parameter */
    readonly INVALID_PARAM: number;
};

/** CPU presets by architecture */
export const CPU: {
    readonly X86: {
        readonly GENERIC: string;
        readonly I386: string;
        readonly I486: string;
        readonly I586: string;
        readonly PENTIUM: string;
        readonly PENTIUM_PRO: string;
        readonly PENTIUM2: string;
        readonly PENTIUM3: string;
        readonly PENTIUM4: string;
        readonly CORE2: string;
        readonly COREI7: string;
        readonly SKYLAKE: string;
        readonly ALDERLAKE: string;
    };
    readonly ARM: {
        readonly GENERIC: string;
        readonly CORTEX_A7: string;
        readonly CORTEX_A8: string;
        readonly CORTEX_A9: string;
        readonly CORTEX_A15: string;
        readonly CORTEX_A53: string;
        readonly CORTEX_A72: string;
        readonly CORTEX_M0: string;
        readonly CORTEX_M3: string;
        readonly CORTEX_M4: string;
    };
    readonly ARM64: {
        readonly GENERIC: string;
        readonly CORTEX_A53: string;
        readonly CORTEX_A72: string;
        readonly CORTEX_A76: string;
        readonly APPLE_A12: string;
        readonly APPLE_A14: string;
        readonly APPLE_M1: string;
    };
};

/** CPU feature presets by architecture */
export const FEATURES: {
    readonly X86: {
        readonly SSE: string;
        readonly SSE2: string;
        readonly SSE3: string;
        readonly SSSE3: string;
        readonly SSE4_1: string;
        readonly SSE4_2: string;
        readonly AVX: string;
        readonly AVX2: string;
        readonly AVX512F: string;
    };
    readonly ARM: {
        readonly NEON: string;
        readonly VFP3: string;
        readonly VFP4: string;
    };
};

/**
 * Get LLVM version string
 * @returns Version string (e.g., "17.0.0")
 */
export function version(): string;

/**
 * Get list of available targets
 * @returns Array of target information
 */
export function getTargets(): TargetInfo[];

// Default export
declare const _default: {
    LlvmMc: typeof LlvmMc;
    TRIPLE: typeof TRIPLE;
    SYNTAX: typeof SYNTAX;
    OPTION: typeof OPTION;
    ERR: typeof ERR;
    CPU: typeof CPU;
    FEATURES: typeof FEATURES;
    version: typeof version;
    getTargets: typeof getTargets;
};

export default _default;

/**
 * Oracle Hook protocol — HexCore side.
 *
 * Mirror of Project Pythia's `src/types/protocol.ts`. Pure TypeScript types,
 * no Zod runtime — validation happens against the JSON at frame boundaries
 * in `oracleTransport.ts`. We don't pull Zod into the disassembler just for
 * one small feature.
 *
 * Keep this file in sync with Pythia's protocol by hand. If the two drift,
 * handshake version mismatch catches it at session start.
 *
 * See https://github.com/AkashaCorporation/Project-Pythia for the canonical
 * schema.
 */

export type TriggerKind =
    | 'instruction'
    | 'api'
    | 'memory_read'
    | 'memory_write'
    | 'exception'
    | 'timing_check'
    | 'peb_access';

export interface Trigger {
    kind: TriggerKind;
    /** Address hex (`0x...`), API name, or region `base-limit`. */
    value: string;
    /** Human-readable reason this fired (used in logs + as model context). */
    reason: string;
}

export interface RegisterState {
    rax: string; rbx: string; rcx: string; rdx: string;
    rsi: string; rdi: string; rbp: string; rsp: string;
    r8:  string; r9:  string; r10: string; r11: string;
    r12: string; r13: string; r14: string; r15: string;
    rip: string; rflags: string;
    gs_base?: string;
    fs_base?: string;
}

export interface DisasmLine {
    address: string;
    bytes: string;
    mnemonic: string;
    operands: string;
}

export interface CallFrame {
    address: string;
    symbol?: string;
    module?: string;
}

export interface MemoryWindow {
    base: string;
    bytes: string;
}

export interface SessionState {
    sessionId: string;
    instructionsExecuted: number;
    apisCalled: string[];
    elapsedMs: number;
    pauseCount: number;
}

export interface DecisionRequest {
    kind: 'decision_request';
    eventId: string;
    trigger: Trigger;
    context: {
        registers: RegisterState;
        disassembly: DisasmLine[];
        callStack: CallFrame[];
        memoryWindow: MemoryWindow;
    };
    session: SessionState;
}

export type PatchTargetKind = 'register' | 'memory' | 'flag';

export interface Patch {
    target: PatchTargetKind;
    location: string;
    value: string;
    /** Byte width for memory patches; ignored for register/flag. */
    size?: number;
}

export interface Skip {
    instructions?: number;
    /** Hex. Skip until PC reaches this exact address. */
    untilAddress?: string;
}

export type DecisionAction =
    | 'continue'
    | 'patch'
    | 'skip'
    | 'patch_and_skip'
    | 'abort';

export interface DecisionResponse {
    kind: 'decision_response';
    eventId: string;
    action: DecisionAction;
    patches?: Patch[];
    skip?: Skip;
    reasoning?: string;
    modelUsed?: 'haiku' | 'sonnet' | 'opus';
    costUsd?: number;
}

export type InspectionTool =
    | 'read_memory'
    | 'disassemble'
    | 'query_helix'
    | 'search_hql'
    | 'list_strings_near'
    | 'get_imports';

export interface ToolCall {
    kind: 'tool_call';
    eventId: string;
    callId: string;
    tool: InspectionTool;
    args: Record<string, unknown>;
}

export interface ToolResult {
    kind: 'tool_result';
    eventId: string;
    callId: string;
    ok: boolean;
    data?: unknown;
    error?: string;
}

export interface Handshake {
    kind: 'handshake';
    protocolVersion: 1;
    hexcoreVersion: string;
    pythiaVersion: string;
    capabilities: string[];
}

export interface SessionEnd {
    kind: 'session_end';
    sessionId: string;
    reason: 'emulation_complete' | 'aborted' | 'timeout' | 'error';
    summary?: {
        instructionsExecuted: number;
        pauseCount: number;
        apisResolved: number;
        patchesApplied: number;
        totalCostUsd: number;
        beaconUrls?: string[];
        iocsExtracted?: string[];
    };
}

export type OracleMessage =
    | Handshake
    | DecisionRequest
    | DecisionResponse
    | ToolCall
    | ToolResult
    | SessionEnd;

/** Current wire protocol version; bump when breaking. */
export const ORACLE_PROTOCOL_VERSION = 1 as const;

/**
 * Lightweight runtime check — no Zod. Returns the parsed message if the
 * `kind` discriminator is recognized, else null. Full structural validation
 * is the caller's responsibility; this is just a gate against garbage frames.
 */
export function isOracleMessage(v: unknown): v is OracleMessage {
    if (!v || typeof v !== 'object') return false;
    const k = (v as { kind?: unknown }).kind;
    return (
        k === 'handshake' ||
        k === 'decision_request' ||
        k === 'decision_response' ||
        k === 'tool_call' ||
        k === 'tool_result' ||
        k === 'session_end'
    );
}

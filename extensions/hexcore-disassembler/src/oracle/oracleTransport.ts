/**
 * Oracle Transport — subprocess lifecycle + NDJSON framing.
 *
 * Owns the Pythia child process. Sends frames on stdin, parses frames off
 * stdout. Pure stdio: SharedArrayBuffer is future work.
 *
 * Safety invariants (see ARCHITECTURE.md in Project-Pythia):
 *   1. Every DecisionRequest has a bounded timeout. If Pythia doesn't answer
 *      within `pauseTimeoutMs`, transport resolves with a `continue` stub so
 *      emulation never hangs. The emulator thread must NEVER block on a
 *      silent oracle.
 *   2. A crashed child is not fatal. The next call resolves with `continue`
 *      until either the child is restarted or the session is closed.
 *   3. Tool calls from Pythia are surfaced through `onToolCall`. The caller
 *      (oracleHookBridge) fulfills them and hands back ToolResults via
 *      `sendToolResult`.
 *
 * No Zod; manual `isOracleMessage` + duck typing. Keep the wire format
 * stable so the Pythia side's Zod parser stays happy.
 */

import { spawn, type ChildProcess, type SpawnOptions } from 'child_process';
import { randomUUID } from 'crypto';
import {
    isOracleMessage,
    ORACLE_PROTOCOL_VERSION,
    type DecisionRequest,
    type DecisionResponse,
    type Handshake,
    type OracleMessage,
    type SessionEnd,
    type ToolCall,
    type ToolResult,
} from './oracle-protocol';

export interface OracleTransportConfig {
    /** Absolute path to `node` (or `npx`) binary used to launch Pythia. */
    nodeBin: string;
    /** Arguments to pass. For tsx dev: `["tsx", "test/pythia-server.ts"]`. */
    spawnArgs: string[];
    /** CWD for the child — must be the Project-Pythia repo root. */
    cwd: string;
    /** Inherit env + overrides (e.g. ANTHROPIC_API_KEY). */
    env?: NodeJS.ProcessEnv;
    /** HexCore side version, sent in the handshake. */
    hexcoreVersion: string;
    /** Max wait for Pythia's response to a DecisionRequest. Default 30000ms. */
    pauseTimeoutMs?: number;
    /** Max wait for handshake frame. Default 5000ms. */
    handshakeTimeoutMs?: number;
    /** Optional logger; defaults to console.error. */
    logger?: (msg: string) => void;
}

export interface OracleTransportEvents {
    /** Pythia asked us to fetch inspection data. Caller returns a ToolResult. */
    onToolCall: (call: ToolCall) => Promise<ToolResult> | ToolResult;
    /** Pythia exited unexpectedly (crash, signal, stderr panic). */
    onChildExit?: (code: number | null, signal: NodeJS.Signals | null) => void;
    /** Stderr line from the child — pass through to VS Code output channel. */
    onStderr?: (line: string) => void;
}

const DEFAULT_PAUSE_TIMEOUT_MS = 30_000;
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 5_000;

export class OracleTransport {
    private readonly cfg: OracleTransportConfig;
    private readonly log: (m: string) => void;
    private events: OracleTransportEvents | null = null;
    private child: ChildProcess | null = null;

    /** eventId -> resolver for the outstanding DecisionRequest, if any. */
    private pendingDecision: {
        eventId: string;
        resolve: (r: DecisionResponse) => void;
        timer: NodeJS.Timeout;
    } | null = null;

    private peerHandshake: Handshake | null = null;
    private stdoutBuffer = '';
    private fatalReason: string | null = null;

    constructor(cfg: OracleTransportConfig) {
        this.cfg = cfg;
        this.log = cfg.logger ?? ((m) => console.error(m));
    }

    /** Public: transport ready to exchange frames after handshake returns. */
    async start(events: OracleTransportEvents): Promise<Handshake> {
        this.events = events;
        const spawnOpts: SpawnOptions = {
            cwd: this.cfg.cwd,
            env: this.cfg.env ?? process.env,
            stdio: ['pipe', 'pipe', 'pipe'],
            shell: process.platform === 'win32',
        };

        this.child = spawn(this.cfg.nodeBin, this.cfg.spawnArgs, spawnOpts);

        this.child.stdout?.on('data', (chunk: Buffer) => this.onStdoutChunk(chunk));
        this.child.stderr?.on('data', (chunk: Buffer) => {
            const text = chunk.toString('utf8');
            for (const line of text.split(/\r?\n/)) {
                if (line.trim() && this.events?.onStderr) this.events.onStderr(line);
            }
        });
        this.child.on('exit', (code, signal) => {
            this.log(`[oracle-transport] child exit code=${code} signal=${signal}`);
            this.failAllPending(new Error(`oracle child exited code=${code} signal=${signal}`));
            this.events?.onChildExit?.(code, signal);
            this.fatalReason = `child exited code=${code}`;
        });
        this.child.on('error', (err) => {
            this.log(`[oracle-transport] spawn error: ${err.message}`);
            this.fatalReason = `spawn: ${err.message}`;
            this.failAllPending(err);
        });

        // Peer (Pythia) sends its handshake first on connect(); we then reply.
        const peer = await this.awaitPeerHandshake();
        this.peerHandshake = peer;

        const outbound: Handshake = {
            kind: 'handshake',
            protocolVersion: ORACLE_PROTOCOL_VERSION,
            hexcoreVersion: this.cfg.hexcoreVersion,
            pythiaVersion: peer.pythiaVersion,
            capabilities: peer.capabilities,
        };
        this.writeFrame(outbound);
        return peer;
    }

    /**
     * Send a DecisionRequest and wait for the matching DecisionResponse. If
     * Pythia takes longer than pauseTimeoutMs OR the child dies, resolve with
     * a safe `continue` decision — emulation keeps moving.
     */
    decide(req: DecisionRequest): Promise<DecisionResponse> {
        if (this.fatalReason) {
            return Promise.resolve(this.stubContinue(req.eventId, `transport dead: ${this.fatalReason}`));
        }
        if (this.pendingDecision) {
            this.log('[oracle-transport] decide() called while another decision is pending; returning continue');
            return Promise.resolve(this.stubContinue(req.eventId, 'pending decision already in flight'));
        }

        return new Promise<DecisionResponse>((resolve) => {
            const pauseMs = this.cfg.pauseTimeoutMs ?? DEFAULT_PAUSE_TIMEOUT_MS;
            const timer = setTimeout(() => {
                this.log(`[oracle-transport] pause timeout (${pauseMs}ms) — falling through to continue`);
                this.pendingDecision = null;
                resolve(this.stubContinue(req.eventId, `timeout ${pauseMs}ms`));
            }, pauseMs);
            timer.unref?.();

            this.pendingDecision = { eventId: req.eventId, resolve, timer };
            this.writeFrame(req);
        });
    }

    /** Reply to a Pythia ToolCall with the fetched data. */
    sendToolResult(result: ToolResult): void {
        if (this.fatalReason) return;
        this.writeFrame(result);
    }

    /** Inform Pythia the session is over and terminate the child. */
    async close(end?: SessionEnd): Promise<void> {
        if (this.child && !this.fatalReason && end) {
            try { this.writeFrame(end); } catch { /* ignore */ }
        }
        this.failAllPending(new Error('transport closing'));
        if (this.child) {
            // Give the child 500ms to finish flushing, then force kill.
            const c = this.child;
            await new Promise<void>((resolve) => {
                const t = setTimeout(() => {
                    c.kill('SIGKILL');
                    resolve();
                }, 500);
                t.unref?.();
                c.once('exit', () => {
                    clearTimeout(t);
                    resolve();
                });
                c.kill('SIGTERM');
            });
            this.child = null;
        }
    }

    // ─── Internals ────────────────────────────────────────────────────────

    private onStdoutChunk(chunk: Buffer): void {
        this.stdoutBuffer += chunk.toString('utf8');
        let nl: number;
        while ((nl = this.stdoutBuffer.indexOf('\n')) >= 0) {
            const line = this.stdoutBuffer.slice(0, nl).trim();
            this.stdoutBuffer = this.stdoutBuffer.slice(nl + 1);
            if (!line) continue;
            let parsed: unknown;
            try {
                parsed = JSON.parse(line);
            } catch {
                this.log(`[oracle-transport] malformed JSON on stdout: ${line.slice(0, 80)}`);
                continue;
            }
            if (!isOracleMessage(parsed)) {
                this.log(`[oracle-transport] frame lacks valid 'kind' discriminator; dropped`);
                continue;
            }
            void this.dispatch(parsed);
        }
    }

    private async dispatch(msg: OracleMessage): Promise<void> {
        switch (msg.kind) {
            case 'handshake':
                this.resolveHandshake?.(msg);
                break;
            case 'decision_response':
                if (this.pendingDecision && this.pendingDecision.eventId === msg.eventId) {
                    clearTimeout(this.pendingDecision.timer);
                    const resolver = this.pendingDecision.resolve;
                    this.pendingDecision = null;
                    resolver(msg);
                } else {
                    this.log(`[oracle-transport] stray decision_response for eventId=${msg.eventId}`);
                }
                break;
            case 'tool_call':
                if (!this.events) break;
                try {
                    const result = await this.events.onToolCall(msg);
                    this.sendToolResult(result);
                } catch (e) {
                    this.sendToolResult({
                        kind: 'tool_result',
                        eventId: msg.eventId,
                        callId: msg.callId,
                        ok: false,
                        error: (e as Error).message,
                    });
                }
                break;
            case 'session_end':
                this.log(`[oracle-transport] peer sent session_end: ${msg.reason}`);
                break;
            default:
                this.log(`[oracle-transport] unexpected inbound kind: ${(msg as { kind: string }).kind}`);
        }
    }

    private resolveHandshake?: (h: Handshake) => void;

    private awaitPeerHandshake(): Promise<Handshake> {
        return new Promise<Handshake>((resolve, reject) => {
            const t = setTimeout(
                () => reject(new Error(`handshake timeout (${this.cfg.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS}ms)`)),
                this.cfg.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS,
            );
            t.unref?.();
            this.resolveHandshake = (h) => {
                clearTimeout(t);
                this.resolveHandshake = undefined;
                resolve(h);
            };
        });
    }

    private writeFrame(msg: OracleMessage): void {
        if (!this.child?.stdin) return;
        const frame = JSON.stringify(msg) + '\n';
        this.child.stdin.write(frame);
    }

    private failAllPending(err: Error): void {
        if (this.pendingDecision) {
            clearTimeout(this.pendingDecision.timer);
            const { resolve, eventId } = this.pendingDecision;
            this.pendingDecision = null;
            resolve(this.stubContinue(eventId, `transport error: ${err.message}`));
        }
    }

    private stubContinue(eventId: string, reason: string): DecisionResponse {
        return {
            kind: 'decision_response',
            eventId,
            action: 'continue',
            reasoning: `[fallback] ${reason}`,
        };
    }

    /** Mint a fresh eventId — used by the hook bridge when it creates requests. */
    static newEventId(prefix: string = 'evt'): string {
        return `${prefix}_${randomUUID().slice(0, 8)}`;
    }
}

/**
 * Oracle Commands — VS Code command registrations for Project Pythia.
 *
 * v0.1 exposes three commands:
 *   - `hexcore.oracle.listSessions`       — show active sessions in a quickpick
 *   - `hexcore.oracle.inspectConfig`      — dump resolved settings + Pythia path
 *   - `hexcore.oracle.demoHeadless`       — single-shot demo emulation with
 *                                           Oracle hook. Takes `{file,
 *                                           triggers, pythiaRepoPath}`.
 *
 * Integration with `hexcore.debug.emulateFullHeadless --oracle` is deferred
 * to Phase 3.5 — it requires reaching into hexcore-debugger's engine, which
 * is outside this branch's scope.
 *
 * All three commands activate on `onStartupFinished` — no need for user
 * interaction before the session can be spawned.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import type { OracleSession, OracleSessionConfig } from './oracleSession';

const activeSessions = new Map<string, OracleSession>();

export function registerOracleCommands(context: vscode.ExtensionContext): void {
    context.subscriptions.push(
        vscode.commands.registerCommand('hexcore.oracle.listSessions', () => listSessions()),
        vscode.commands.registerCommand('hexcore.oracle.inspectConfig', () => inspectConfig()),
        vscode.commands.registerCommand(
            'hexcore.oracle.demoHeadless',
            (arg?: DemoHeadlessArgs) => demoHeadless(arg),
        ),
    );
}

// ─── Command implementations ──────────────────────────────────────────────

async function listSessions(): Promise<void> {
    if (activeSessions.size === 0) {
        vscode.window.showInformationMessage('[Oracle] no active sessions');
        return;
    }
    const items = Array.from(activeSessions.keys()).map((id) => ({
        label: id,
        description: 'active Oracle session',
    }));
    const pick = await vscode.window.showQuickPick(items, {
        placeHolder: 'Active Oracle sessions',
    });
    if (pick) {
        vscode.window.showInformationMessage(`[Oracle] session ${pick.label} — details in Output: "HexCore Oracle"`);
    }
}

async function inspectConfig(): Promise<void> {
    const cfg = resolveOracleConfig();
    const channel = getOutputChannel();
    channel.clear();
    channel.appendLine(`[Oracle Config]`);
    channel.appendLine(`  enabled:            ${cfg.enabled}`);
    channel.appendLine(`  defaultTransport:   ${cfg.defaultTransport}`);
    channel.appendLine(`  pauseTimeoutMs:     ${cfg.pauseTimeoutMs}`);
    channel.appendLine(`  pythiaRepoPath:     ${cfg.pythiaRepoPath || '(unset)'}`);
    channel.appendLine(`  pythiaNodeBin:      ${cfg.pythiaNodeBin}`);
    channel.appendLine(`  maxBudgetUsd:       ${cfg.maxBudgetUsd}`);
    channel.appendLine(`  activeSessions:     ${activeSessions.size}`);
    channel.show(true);
}

/**
 * Demo command — runs a minimal, Oracle-enabled emulation flow against a
 * sample file. This is the hackathon-scope entry point; for production
 * integration, use the upcoming `hexcore.debug.emulateFullHeadless --oracle`
 * option (Phase 3.5).
 *
 * The implementation here is *intentionally* a placeholder: it validates the
 * config, confirms Pythia can be reached via handshake, and returns. Full
 * Unicorn wiring requires access to a binary loader (PE parser, section
 * mapping, PEB setup) which is hexcore-debugger's domain. The integration
 * layer that wires those pieces together is a follow-up commit.
 */
interface DemoHeadlessArgs {
    file?: string;
    /** Array of triggers the session should register. */
    triggers?: Array<{ kind: string; value: string; reason?: string }>;
    /** Absolute path to the Project-Pythia repo; overrides setting. */
    pythiaRepoPath?: string;
}

async function demoHeadless(arg?: DemoHeadlessArgs): Promise<{ ok: boolean; reason: string }> {
    const channel = getOutputChannel();
    channel.show(true);
    channel.clear();

    const cfg = resolveOracleConfig();
    const pythiaRepoPath = arg?.pythiaRepoPath ?? cfg.pythiaRepoPath;

    if (!cfg.enabled) {
        const msg = 'hexcore.oracle.enabled=false — set it to true in settings to run the demo';
        channel.appendLine(`[oracle-demo] ${msg}`);
        return { ok: false, reason: msg };
    }
    if (!pythiaRepoPath) {
        const msg = 'hexcore.oracle.pythiaRepoPath not set — point it at the Project-Pythia repo';
        channel.appendLine(`[oracle-demo] ${msg}`);
        return { ok: false, reason: msg };
    }

    channel.appendLine(`[oracle-demo] handshake probe to Pythia at ${pythiaRepoPath}`);
    channel.appendLine(`[oracle-demo] (full emulator wiring lands in Phase 3.5 — this command validates transport only)`);
    channel.appendLine(`[oracle-demo] file=${arg?.file ?? '(none provided)'}`);
    channel.appendLine(`[oracle-demo] triggers=${JSON.stringify(arg?.triggers ?? [])}`);

    // Transport-only probe: import dynamically so this extension loads even
    // without Pythia present.
    const { OracleTransport } = await import('./oracleTransport');
    const transport = new OracleTransport({
        nodeBin: cfg.pythiaNodeBin,
        spawnArgs: cfg.pythiaSpawnArgs,
        cwd: pythiaRepoPath,
        env: process.env,
        hexcoreVersion: cfg.hexcoreVersion,
        pauseTimeoutMs: cfg.pauseTimeoutMs,
        logger: (m) => channel.appendLine(m),
    });

    try {
        const peer = await transport.start({
            onToolCall: async () => ({
                kind: 'tool_result',
                eventId: 'probe',
                callId: 'probe',
                ok: false,
                error: 'probe mode — no tools',
            }),
            onStderr: (line) => channel.appendLine(`[pythia.err] ${line}`),
        });
        channel.appendLine(`[oracle-demo] handshake ok — peer=${peer.pythiaVersion} caps=[${peer.capabilities.join(',')}]`);
        await transport.close({
            kind: 'session_end',
            sessionId: 'probe',
            reason: 'emulation_complete',
        });
        channel.appendLine('[oracle-demo] probe complete — transport is healthy');
        return { ok: true, reason: 'probe complete' };
    } catch (e) {
        const msg = (e as Error).message;
        channel.appendLine(`[oracle-demo] probe FAILED: ${msg}`);
        await transport.close().catch(() => { /* best effort */ });
        return { ok: false, reason: msg };
    }
}

// ─── Config resolution ────────────────────────────────────────────────────

interface OracleConfig {
    enabled: boolean;
    defaultTransport: 'sab' | 'stdio';
    pauseTimeoutMs: number;
    pythiaRepoPath: string;
    pythiaNodeBin: string;
    pythiaSpawnArgs: string[];
    maxBudgetUsd: number;
    hexcoreVersion: string;
}

function resolveOracleConfig(): OracleConfig {
    const section = vscode.workspace.getConfiguration('hexcore.oracle');
    const rawPath = section.get<string>('pythiaRepoPath', '').trim();
    const resolvedPath = rawPath ? path.normalize(rawPath) : '';
    return {
        enabled: section.get<boolean>('enabled', false),
        defaultTransport: section.get<'sab' | 'stdio'>('defaultTransport', 'stdio'),
        pauseTimeoutMs: section.get<number>('pauseTimeoutMs', 30_000),
        pythiaRepoPath: resolvedPath,
        pythiaNodeBin: section.get<string>('pythiaNodeBin', process.platform === 'win32' ? 'npx.cmd' : 'npx'),
        pythiaSpawnArgs: section.get<string[]>('pythiaSpawnArgs', ['tsx', 'test/pythia-server.ts']),
        maxBudgetUsd: section.get<number>('maxBudgetUsd', 5.0),
        hexcoreVersion: '3.9.0-preview.oracle',
    };
}

// ─── Shared output channel ────────────────────────────────────────────────

let sharedChannel: vscode.OutputChannel | null = null;

function getOutputChannel(): vscode.OutputChannel {
    if (!sharedChannel) {
        sharedChannel = vscode.window.createOutputChannel('HexCore Oracle');
    }
    return sharedChannel;
}

// ─── Exports for tests ────────────────────────────────────────────────────

export const __testing = {
    activeSessions,
    resolveOracleConfig,
};

// Re-export type for callers wanting to plug in a custom session factory.
export type { OracleSessionConfig };

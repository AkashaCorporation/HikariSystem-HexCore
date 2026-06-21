/*---------------------------------------------------------------------------------------------
 *  HexCore Revenant -- VS Code surface for the managed (.NET / CIL) decompiler.
 *  Resurrects C# / IL from managed assemblies the native pipeline cannot read.
 *  Closes the "Better" tier of issue #32. Backend: src/ilspyRunner.ts.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { decompile, RevenantMode, RevenantResult } from './ilspyRunner';

interface RevenantCommandOptions {
	file?: string;
	// The headless pipeline (automationPipelineRunner) injects `output` as an
	// object `{ path, format? }`, while an interactive/scripted caller may pass a
	// bare string. Accept both; resolve to a concrete path via resolveOutputPath.
	output?: string | { path?: string };
	type?: string;
	quiet?: boolean;
}

function normalizeOptions(arg?: vscode.Uri | RevenantCommandOptions): RevenantCommandOptions {
	if (!arg) { return {}; }
	if (arg instanceof vscode.Uri) { return { file: arg.fsPath }; }
	return arg;
}

/**
 * Resolve the output destination to a concrete file path. The pipeline runner
 * passes `{ path }`; direct callers may pass a string. Returns undefined when no
 * usable path was supplied (then the command just returns the result in-memory).
 * Mirrors resolveOptionalOutputPath in hexcore-disassembler so both agree.
 */
function resolveOutputPath(output?: string | { path?: string }): string | undefined {
	if (typeof output === 'string' && output.length > 0) { return output; }
	if (output && typeof output === 'object' && typeof output.path === 'string' && output.path.length > 0) {
		return output.path;
	}
	return undefined;
}

async function resolveTargetFile(options: RevenantCommandOptions): Promise<string | undefined> {
	if (options.file) { return options.file; }
	const active = vscode.window.activeTextEditor?.document.uri;
	if (active && active.scheme === 'file') { return active.fsPath; }
	const picked = await vscode.window.showOpenDialog({
		canSelectMany: false,
		openLabel: 'Decompile',
		filters: { '.NET assemblies': ['exe', 'dll'], 'All files': ['*'] }
	});
	return picked && picked[0] ? picked[0].fsPath : undefined;
}

function banner(file: string, r: RevenantResult): string {
	const tool = r.tool ? path.basename(r.tool) : 'ilspycmd';
	const ver = r.toolVersion ? ` ${r.toolVersion}` : '';
	const lang = r.mode === 'il' ? 'IL' : 'C#';
	return [
		`// Recovered by HexCore Revenant (${lang}) via ${tool}${ver} [ICSharpCode.Decompiler, MIT]`,
		`// Source: ${file}`,
		`// Managed .NET assembly -- the native Remill->Helix pipeline cannot decompile this.`,
		'',
		''
	].join('\n');
}

async function runDecompile(mode: RevenantMode, arg?: vscode.Uri | RevenantCommandOptions): Promise<RevenantResult | undefined> {
	const options = normalizeOptions(arg);
	const file = await resolveTargetFile(options);
	if (!file) { return undefined; }

	const cfg = vscode.workspace.getConfiguration('hexcore.revenant');
	const ilspyPath = cfg.get<string>('ilspyPath') || undefined;
	const timeoutMs = cfg.get<number>('timeoutMs') || 120000;

	const outputPath = resolveOutputPath(options.output);

	const execute = async (): Promise<RevenantResult> => {
		const r = await decompile(file, { mode, type: options.type, ilspyPath, timeoutMs });
		if (r.ok && outputPath) {
			try {
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, banner(file, r) + r.code, 'utf-8');
			} catch (err) {
				r.ok = false;
				r.error = `decompiled OK but could not write output: ${(err as Error).message}`;
			}
		}
		return r;
	};

	// Headless (pipeline) path: return the structured result with a `success`
	// mirror of `ok`. The automation runner inspects `commandReturn.success ===
	// false` to surface the command's real `error` instead of a generic
	// "output file not created" mask; without this mirror a Revenant failure
	// would be reported as a blank validation error.
	if (options.quiet) {
		const r = await execute();
		return { ...r, success: r.ok } as RevenantResult & { success: boolean };
	}

	let result: RevenantResult | undefined;
	await vscode.window.withProgress(
		{ location: vscode.ProgressLocation.Notification, title: `Revenant: decompiling ${path.basename(file)} to ${mode === 'il' ? 'IL' : 'C#'}...`, cancellable: false },
		async () => { result = await execute(); }
	);
	if (!result) { return undefined; }

	if (!result.ok) {
		vscode.window.showErrorMessage(`Revenant: ${result.error || 'decompile failed'}`);
		return result;
	}
	const doc = await vscode.workspace.openTextDocument({
		content: banner(file, result) + result.code,
		language: mode === 'il' ? 'plaintext' : 'csharp'
	});
	await vscode.window.showTextDocument(doc, { preview: false });
	vscode.window.showInformationMessage(`Revenant: recovered ${mode === 'il' ? 'IL' : 'C#'} from ${path.basename(file)} (${result.elapsedMs}ms).`);
	return result;
}

export function activate(context: vscode.ExtensionContext): void {
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.revenant.decompile', (arg?: vscode.Uri | RevenantCommandOptions) => runDecompile('csharp', arg)),
		vscode.commands.registerCommand('hexcore.revenant.decompileIL', (arg?: vscode.Uri | RevenantCommandOptions) => runDecompile('il', arg))
	);
}

export function deactivate(): void { /* no resources to release */ }

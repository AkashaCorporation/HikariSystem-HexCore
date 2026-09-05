/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as vscode from 'vscode';
import { isAnalysisObjectId, parseAnalysisObjectId, type AnalysisSession, type AnalysisTarget } from 'hexcore-common';
import type { InvestigationPreset } from './investigationModel';

export type AnalysisAction =
	| 'openBinary'
	| 'analyze'
	| 'lift'
	| 'decompile'
	| 'hex'
	| 'yara'
	| 'entropy'
	| 'pe'
	| 'runJob'
	| 'doctor'
	| 'nativeStatus';

export interface AnalysisEngineStatus {
	id: string;
	label: string;
	status: 'ready' | 'unavailable' | 'disabled';
	detail: string;
}

export interface AnalysisCenterSnapshot {
	loaded: boolean;
	fileName: string;
	filePath: string;
	format: string;
	architecture: string;
	entryPoint: number;
	baseAddress: number;
	imageSize: number;
	metrics: {
		functions: number;
		sections: number;
		imports: number;
		exports: number;
		strings: number;
		bookmarks: number;
	};
	engines: AnalysisEngineStatus[];
	emulator: string;
	workspaceName: string;
	jobFiles: string[];
	sessionPath: string;
	sessionPersistence: boolean;
	analysisTarget: AnalysisTarget | null;
	analysisSession: AnalysisSession | null;
	workspaceTargets: AnalysisWorkspaceTarget[];
	investigations: AnalysisInvestigation[];
	recentFindings: AnalysisFinding[];
	savedFindings: AnalysisFinding[];
}

export interface AnalysisWorkspaceTarget {
	name: string;
	path: string;
	relativePath: string;
}

export interface AnalysisInvestigation {
	id: string;
	title: string;
	kind: string;
	query: string;
	status: string;
	resultCount: number;
	createdAt: string;
}

export interface AnalysisFinding {
	id: string;
	investigationId: string;
	query: string;
	label: string;
	stringAddress: string;
	referenceAddress: string | null;
	functionAddress: string | null;
	functionName: string | null;
	encoding: string | null;
	saved: boolean;
}

export type AnalysisCenterRequest =
	| { type: 'action'; action: AnalysisAction }
	| { type: 'loadTarget'; path: string }
	| { type: 'runInvestigation'; preset: InvestigationPreset; query: string }
	| { type: 'createInvestigationJob'; name: string; findingId: string }
	| { type: 'openInvestigation'; id: string }
	| { type: 'finding'; action: 'save' | 'unsave' | 'open' | 'decompile'; id: string };

export interface AnalysisActionResult {
	title: string;
	message: string;
}

type SnapshotProvider = () => Promise<AnalysisCenterSnapshot>;
type ActionHandler = (request: AnalysisCenterRequest) => Promise<AnalysisActionResult | void>;

export class AnalysisCenterProvider implements vscode.WebviewViewProvider, vscode.Disposable {
	public static readonly viewType = 'hexcore.analysis.overview';
	public static readonly panelType = 'hexcore.analysis.center';

	private view: vscode.WebviewView | undefined;
	private panel: vscode.WebviewPanel | undefined;
	private readonly disposables: vscode.Disposable[] = [];

	constructor(
		private readonly getSnapshot: SnapshotProvider,
		private readonly handleAction: ActionHandler
	) { }

	public resolveWebviewView(view: vscode.WebviewView): void {
		this.view = view;
		this.configureWebview(view.webview, 'sidebar');
		this.disposables.push(view.onDidChangeVisibility(() => {
			if (view.visible) {
				void this.postSnapshot(view.webview);
			}
		}));
	}

	public show(): void {
		if (this.panel) {
			this.panel.reveal(vscode.ViewColumn.One);
			void this.postSnapshot(this.panel.webview);
			return;
		}

		this.panel = vscode.window.createWebviewPanel(
			AnalysisCenterProvider.panelType,
			'HexCore Analysis Center',
			vscode.ViewColumn.Active,
			{ enableScripts: true, retainContextWhenHidden: true }
		);
		this.configureWebview(this.panel.webview, 'panel');
		this.disposables.push(this.panel.onDidDispose(() => {
			this.panel = undefined;
		}));
	}

	public refresh(): void {
		if (this.view?.visible) {
			void this.postSnapshot(this.view.webview);
		}
		if (this.panel?.visible) {
			void this.postSnapshot(this.panel.webview);
		}
	}

	public dispose(): void {
		this.panel?.dispose();
		for (const disposable of this.disposables.splice(0)) {
			disposable.dispose();
		}
	}

	private configureWebview(webview: vscode.Webview, mode: 'sidebar' | 'panel'): void {
		webview.options = { enableScripts: true };
		webview.html = this.getHtml(webview, mode);
		this.disposables.push(webview.onDidReceiveMessage(async (message: unknown) => {
			if (!message || typeof message !== 'object') {
				return;
			}
			const value = message as Record<string, unknown>;
			if (value.type === 'ready' || value.type === 'refresh') {
				await this.postSnapshot(webview);
				return;
			}
			if (value.type === 'openCenter') {
				this.show();
				return;
			}
			const request = parseAnalysisCenterRequest(value);
			if (request) {
				try {
					const activity = describeRequest(request);
					await webview.postMessage({ type: 'activity', status: 'running', action: activity });
					const result = await this.handleAction(request);
					await this.postSnapshot(webview);
					this.refresh();
					await webview.postMessage({
						type: 'activity',
						status: 'complete',
						action: activity,
						title: result?.title ?? 'Action complete',
						message: result?.message ?? 'HexCore state refreshed'
					});
				} catch (error) {
					const message = error instanceof Error ? error.message : String(error);
					await webview.postMessage({ type: 'activity', status: 'error', action: describeRequest(request), message });
					await webview.postMessage({ type: 'error', message });
					void vscode.window.showErrorMessage(`HexCore action failed: ${message}`);
				}
			}
		}));
	}

	private async postSnapshot(webview: vscode.Webview): Promise<void> {
		try {
			const snapshot = await this.getSnapshot();
			await webview.postMessage({ type: 'snapshot', snapshot });
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			await webview.postMessage({ type: 'error', message });
		}
	}

	private getHtml(webview: vscode.Webview, mode: 'sidebar' | 'panel'): string {
		const nonce = crypto.randomBytes(16).toString('hex');
		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
	<title>HexCore Analysis Center</title>
	<style nonce="${nonce}">
		* { box-sizing: border-box; }
		:root { color-scheme: light dark; }
		body {
			margin: 0;
			background: var(--vscode-editor-background);
			color: var(--vscode-editor-foreground);
			font-family: var(--vscode-font-family);
			font-size: 13px;
			letter-spacing: 0;
		}
		.shell { min-height: 100vh; }
		.topbar {
			display: flex;
			align-items: center;
			justify-content: space-between;
			gap: 12px;
			min-height: 50px;
			padding: 8px 16px;
			border-bottom: 1px solid var(--vscode-panel-border);
			background: var(--vscode-sideBar-background);
		}
		.top-actions { display: flex; gap: 6px; align-items: center; }
		.identity { min-width: 0; }
		.identity h1 {
			margin: 0;
			font-size: 18px;
			font-weight: 600;
			line-height: 24px;
			white-space: nowrap;
			overflow: hidden;
			text-overflow: ellipsis;
		}
		.identity .path {
			color: var(--vscode-descriptionForeground);
			font-family: var(--vscode-editor-font-family);
			font-size: 11px;
			white-space: nowrap;
			overflow: hidden;
			text-overflow: ellipsis;
		}
		.state {
			flex: 0 0 auto;
			padding: 2px 7px;
			border: 1px solid var(--vscode-panel-border);
			border-radius: 4px;
			color: var(--vscode-descriptionForeground);
			font-size: 11px;
			text-transform: uppercase;
		}
		.state.ready { color: var(--vscode-testing-iconPassed); border-color: var(--vscode-testing-iconPassed); }
		.toolbar {
			display: flex;
			flex-wrap: wrap;
			gap: 6px;
			padding: 8px 16px;
			border-bottom: 1px solid var(--vscode-panel-border);
			background: var(--vscode-editorGroupHeader-tabsBackground);
		}
		button {
			min-height: 28px;
			padding: 4px 10px;
			border: 1px solid var(--vscode-button-border, transparent);
			border-radius: 4px;
			background: var(--vscode-button-secondaryBackground);
			color: var(--vscode-button-secondaryForeground);
			font: inherit;
			cursor: pointer;
		}
		button:hover { background: var(--vscode-button-secondaryHoverBackground); }
		button.primary { background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
		button.primary:hover { background: var(--vscode-button-hoverBackground); }
		button:disabled { cursor: default; opacity: .45; }
		.icon-button { width: 30px; padding: 0; font-size: 17px; line-height: 26px; }
		.tabs {
			display: flex;
			gap: 0;
			padding: 0 16px;
			border-bottom: 1px solid var(--vscode-panel-border);
		}
		.tab {
			min-height: 34px;
			padding: 7px 12px;
			border: 0;
			border-bottom: 2px solid transparent;
			border-radius: 0;
			background: transparent;
			color: var(--vscode-descriptionForeground);
		}
		.tab.active { color: var(--vscode-foreground); border-bottom-color: var(--vscode-focusBorder); }
		.content { max-width: 1180px; padding: 14px 16px 28px; }
		.page { display: none; }
		.page.active { display: block; }
		.section { margin: 0 0 18px; }
		.section h2 {
			margin: 0 0 7px;
			font-size: 12px;
			font-weight: 600;
			text-transform: uppercase;
			color: var(--vscode-descriptionForeground);
		}
		.metrics {
			display: grid;
			grid-template-columns: repeat(6, minmax(96px, 1fr));
			border: 1px solid var(--vscode-panel-border);
			border-radius: 4px;
			overflow: hidden;
		}
		.metric { min-width: 0; padding: 10px; border-right: 1px solid var(--vscode-panel-border); }
		.metric:last-child { border-right: 0; }
		.metric strong { display: block; font-size: 18px; font-weight: 600; }
		.metric span { color: var(--vscode-descriptionForeground); font-size: 11px; }
		table { width: 100%; border-collapse: collapse; border: 1px solid var(--vscode-panel-border); }
		th, td { padding: 7px 9px; border-bottom: 1px solid var(--vscode-panel-border); text-align: left; vertical-align: top; }
		th { width: 160px; color: var(--vscode-descriptionForeground); font-weight: 500; background: var(--vscode-sideBar-background); }
		td.code { font-family: var(--vscode-editor-font-family); overflow-wrap: anywhere; }
		.status-dot { display: inline-block; width: 7px; height: 7px; margin-right: 7px; border-radius: 50%; background: var(--vscode-descriptionForeground); }
		.status-dot.ready { background: var(--vscode-testing-iconPassed); }
		.status-dot.unavailable { background: var(--vscode-testing-iconFailed); }
		.status-dot.disabled { background: var(--vscode-descriptionForeground); }
		.detail { color: var(--vscode-descriptionForeground); }
		.job-list { border: 1px solid var(--vscode-panel-border); border-radius: 4px; overflow: hidden; }
		.job { padding: 7px 9px; border-bottom: 1px solid var(--vscode-panel-border); font-family: var(--vscode-editor-font-family); font-size: 12px; overflow-wrap: anywhere; }
		.job:last-child { border-bottom: 0; }
		.form-row { display: grid; grid-template-columns: minmax(160px, 220px) minmax(220px, 1fr) auto; gap: 8px; align-items: end; }
		.field { min-width: 0; }
		.field label { display: block; margin-bottom: 5px; color: var(--vscode-descriptionForeground); font-size: 11px; }
		input, select {
			width: 100%;
			height: 30px;
			padding: 4px 7px;
			border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
			border-radius: 3px;
			outline: none;
			background: var(--vscode-input-background);
			color: var(--vscode-input-foreground);
			font: inherit;
		}
		input:focus, select:focus { border-color: var(--vscode-focusBorder); }
		.target-picker { display: grid; grid-template-columns: minmax(240px, 1fr) auto; gap: 8px; }
		.results { border: 1px solid var(--vscode-panel-border); overflow: hidden; }
		.result-row { display: grid; grid-template-columns: minmax(220px, 1fr) minmax(150px, 240px) auto; gap: 12px; align-items: center; min-height: 54px; padding: 8px 9px; border-bottom: 1px solid var(--vscode-panel-border); }
		.result-row:last-child { border-bottom: 0; }
		.result-label { min-width: 0; font-family: var(--vscode-editor-font-family); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
		.result-meta { min-width: 0; color: var(--vscode-descriptionForeground); font-size: 11px; }
		.result-meta .code { display: block; font-family: var(--vscode-editor-font-family); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
		.result-actions { display: flex; gap: 5px; justify-content: flex-end; }
		.result-actions button { min-width: 30px; padding: 3px 8px; }
		.history-row { display: grid; grid-template-columns: minmax(180px, 1fr) auto; gap: 8px; padding: 7px 9px; border-bottom: 1px solid var(--vscode-panel-border); }
		.history-row:last-child { border-bottom: 0; }
		.history-title { font-weight: 600; }
		.history-meta { color: var(--vscode-descriptionForeground); font-size: 11px; }
		.inline-toolbar { padding: 0; border: 0; background: transparent; }
		.empty {
			padding: 28px 12px;
			border: 1px dashed var(--vscode-panel-border);
			text-align: center;
			color: var(--vscode-descriptionForeground);
		}
		.empty strong { display: block; margin-bottom: 12px; color: var(--vscode-foreground); font-size: 14px; }
		.error { display: none; margin: 10px 16px 0; padding: 7px 9px; border-left: 3px solid var(--vscode-testing-iconFailed); background: var(--vscode-inputValidation-errorBackground); }
		.activity { display: none; margin: 10px 16px 0; padding: 7px 9px; border-left: 3px solid var(--vscode-focusBorder); background: var(--vscode-textBlockQuote-background); }
		.activity.running { display: block; color: var(--vscode-descriptionForeground); }
		.activity.complete { display: block; border-left-color: var(--vscode-testing-iconPassed); }
		.activity.error { display: block; border-left-color: var(--vscode-testing-iconFailed); }
		.sidebar-only { display: none; }
		.center-launch { width: 100%; padding: 0 10px 10px; border-bottom: 1px solid var(--vscode-panel-border); }
		.center-launch button { width: 100%; }
		body.sidebar .topbar { padding: 8px 10px; }
		body.sidebar .identity h1 { font-size: 14px; }
		body.sidebar .toolbar, body.sidebar .tabs { padding-left: 10px; padding-right: 10px; }
		body.sidebar .content { padding: 10px; }
		body.sidebar .tabs { display: none; }
		body.sidebar .sidebar-only { display: inline-flex; }
		body.sidebar .activity, body.sidebar .error { margin-left: 10px; margin-right: 10px; }
		body.sidebar .metrics { grid-template-columns: repeat(2, minmax(90px, 1fr)); }
		body.sidebar .metric { border-bottom: 1px solid var(--vscode-panel-border); }
		body.sidebar .metric:nth-child(2n) { border-right: 0; }
		body.sidebar .target-section { display: none; }
		body.sidebar th { width: 92px; }
		body.sidebar .panel-only { display: none; }
		@media (max-width: 760px) {
			.metrics { grid-template-columns: repeat(2, minmax(90px, 1fr)); }
			.metric { border-bottom: 1px solid var(--vscode-panel-border); }
			.metric:nth-child(2n) { border-right: 0; }
			.topbar { align-items: flex-start; }
			.form-row { grid-template-columns: 1fr; }
			.target-picker { grid-template-columns: 1fr; }
			.result-row { grid-template-columns: 1fr; }
			.result-actions { justify-content: flex-start; }
		}
	</style>
</head>
<body class="${mode}">
	<div class="shell">
		<header class="topbar">
			<div class="identity">
				<h1 id="targetName">HexCore Analysis</h1>
				<div class="path" id="targetPath">No binary loaded</div>
			</div>
			<div class="top-actions">
				<span class="state" id="targetState">Idle</span>
				<button class="icon-button sidebar-only" data-open-center title="Open full Analysis Center" aria-label="Open full Analysis Center">&#x26F6;</button>
				<button class="icon-button" data-action="refresh" title="Refresh analysis state" aria-label="Refresh analysis state">&#x21bb;</button>
			</div>
		</header>
		<div class="toolbar">
			<button class="primary" data-action="openBinary">Open Binary</button>
			<button data-action="analyze" data-requires-target>Analyze</button>
			<button data-action="lift" data-requires-target>Lift IR</button>
			<button data-action="decompile" data-requires-target>Decompile</button>
			<button data-action="hex" data-requires-target>Hex</button>
			<button class="panel-only" data-action="yara" data-requires-target>YARA</button>
			<button class="panel-only" data-action="entropy" data-requires-target>Entropy</button>
			<button class="panel-only" data-action="pe" data-requires-target>PE</button>
		</div>
		<div class="sidebar-only center-launch">
			<button class="primary" data-open-center>Open Analysis Center</button>
		</div>
		<div class="error" id="errorBanner"></div>
		<div class="activity" id="activityBanner" aria-live="polite"></div>
		<nav class="tabs" aria-label="Analysis Center views">
			<button class="tab active" data-tab="overview">Overview</button>
			<button class="tab" data-tab="investigate">Investigate</button>
			<button class="tab" data-tab="saved" id="savedTab">Saved</button>
			<button class="tab" data-tab="engines">Engines</button>
			<button class="tab" data-tab="automation">Automation</button>
			<button class="tab" data-tab="jobs">Jobs</button>
		</nav>
		<main class="content">
			<section class="page active" data-page="overview">
				<div id="overviewLoaded">
					<div class="section"><h2>Analysis Index</h2><div class="metrics" id="metrics"></div></div>
					<div class="section target-section"><h2>Target</h2><table><tbody id="targetTable"></tbody></table></div>
				</div>
				<div class="section panel-only" id="workspaceTargetsSection">
					<h2>Workspace Targets</h2>
					<div class="target-picker">
						<select id="workspaceTarget" aria-label="Workspace binary"></select>
						<button data-load-target>Load</button>
					</div>
				</div>
				<div class="empty" id="overviewEmpty"><strong>No binary loaded</strong><button class="primary" data-action="openBinary">Open Binary</button></div>
			</section>
			<section class="page" data-page="investigate">
				<div class="section">
					<h2>Investigation Builder</h2>
					<form id="investigationForm" class="form-row">
						<div class="field">
							<label for="investigationPreset">Focus</label>
							<select id="investigationPreset">
								<option value="custom">Custom string</option>
								<option value="health">Health / state</option>
								<option value="anti-debug">Anti-debug</option>
								<option value="network">Network / URLs</option>
								<option value="credentials">Credentials / secrets</option>
							</select>
						</div>
						<div class="field">
							<label for="investigationQuery">String or term</label>
							<input id="investigationQuery" type="text" minlength="3" maxlength="256" placeholder="health, IsDebuggerPresent, endpoint...">
						</div>
						<button class="primary" type="submit" data-requires-target>Search References</button>
					</form>
				</div>
				<div class="section">
					<h2>Results</h2>
					<div id="recentResults"></div>
				</div>
				<div class="section">
					<h2>Recent Investigations</h2>
					<div class="results" id="investigationHistory"></div>
				</div>
			</section>
			<section class="page" data-page="saved">
				<div class="section">
					<h2>Saved Findings</h2>
					<div id="savedResults"></div>
				</div>
			</section>
			<section class="page" data-page="engines">
				<div class="section"><h2>Native Engines</h2><table><tbody id="engineTable"></tbody></table></div>
				<button data-action="nativeStatus">Run Native Status Check</button>
			</section>
			<section class="page" data-page="automation">
				<div class="section"><h2>Workspace</h2><table><tbody id="workspaceTable"></tbody></table></div>
				<div class="section"><h2>Jobs</h2><div class="job-list" id="jobList"></div></div>
				<div class="toolbar inline-toolbar">
					<button class="primary" data-action="runJob">Run Job</button>
					<button data-action="doctor">Pipeline Doctor</button>
				</div>
			</section>
			<section class="page" data-page="jobs">
				<div class="section">
					<h2>Investigation Job</h2>
					<form id="jobForm" class="form-row">
						<div class="field">
							<label for="jobName">Job name</label>
							<input id="jobName" type="text" minlength="1" maxlength="80" placeholder="health-points">
						</div>
						<div class="field">
							<label for="jobFinding">Saved finding</label>
							<select id="jobFinding" aria-label="Saved finding"></select>
						</div>
						<button class="primary" id="createJobButton" type="submit" data-requires-target>Create &amp; Run</button>
					</form>
				</div>
				<div class="section"><h2>Workspace Jobs</h2><div class="job-list" id="generatedJobList"></div></div>
			</section>
		</main>
	</div>
	<script nonce="${nonce}">
		const vscode = acquireVsCodeApi();
		const IS_SIDEBAR = ${mode === 'sidebar'};
		let snapshot;
		let busy = false;
		const saved = vscode.getState() || {};
		const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
		const hex = value => '0x' + Number(value || 0).toString(16).toUpperCase();
		const size = value => {
			const bytes = Number(value || 0);
			if (bytes < 1024) return bytes + ' B';
			if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KiB';
			return (bytes / (1024 * 1024)).toFixed(1) + ' MiB';
		};
		function selectTab(name) {
			document.querySelectorAll('.tab').forEach(el => el.classList.toggle('active', el.dataset.tab === name));
			document.querySelectorAll('.page').forEach(el => el.classList.toggle('active', el.dataset.page === name));
			vscode.setState({ tab: name });
		}
		function row(label, value, cls = '') { return '<tr><th>' + esc(label) + '</th><td class="' + cls + '">' + esc(value) + '</td></tr>'; }
		function compactId(value) {
			if (!value) return 'Unavailable';
			const parts = String(value).split(':');
			const tail = parts[parts.length - 1];
			return tail.length > 16 ? tail.slice(0, 16) + '...' : tail;
		}
		function findingRows(findings, emptyMessage) {
			if (!findings.length) return '<div class="empty"><strong>' + esc(emptyMessage) + '</strong></div>';
			return '<div class="results">' + findings.map(finding => {
				const location = finding.functionAddress
					? (finding.functionName || 'Function') + ' at ' + finding.functionAddress
					: (finding.referenceAddress ? 'Reference at ' + finding.referenceAddress : 'String at ' + finding.stringAddress);
				const savedAction = finding.saved ? 'unsave' : 'save';
				const savedTitle = finding.saved ? 'Remove from Saved' : 'Save finding';
				return '<div class="result-row">' +
					'<div class="result-label" title="' + esc(finding.label) + '">' + esc(finding.label) + '</div>' +
					'<div class="result-meta"><span class="code">' + esc(location) + '</span><span>' + esc(finding.query) + ' / ' + esc(finding.encoding || 'unknown') + '</span></div>' +
					'<div class="result-actions">' +
						'<button data-finding-action="' + savedAction + '" data-finding-id="' + esc(finding.id) + '" title="' + savedTitle + '" aria-label="' + savedTitle + '">' + (finding.saved ? '&#9733;' : '&#9734;') + '</button>' +
						'<button data-finding-action="open" data-finding-id="' + esc(finding.id) + '" ' + (finding.referenceAddress || finding.functionAddress ? '' : 'disabled') + '>Open</button>' +
						'<button data-finding-action="decompile" data-finding-id="' + esc(finding.id) + '" ' + (finding.functionAddress || finding.referenceAddress ? '' : 'disabled') + ' title="' + (finding.functionAddress ? 'Decompile function' : 'Resolve function from reference and decompile') + '">Decompile</button>' +
					'</div></div>';
			}).join('') + '</div>';
		}
		function render(data) {
			snapshot = data;
			document.getElementById('targetName').textContent = data.loaded ? data.fileName : 'HexCore Analysis';
			document.getElementById('targetPath').textContent = data.loaded ? data.filePath : 'No binary loaded';
			const state = document.getElementById('targetState');
			state.textContent = data.loaded ? 'Loaded' : 'Idle';
			state.classList.toggle('ready', data.loaded);
			document.querySelectorAll('[data-requires-target]').forEach(button => button.disabled = !data.loaded);
			document.getElementById('overviewLoaded').style.display = data.loaded ? '' : 'none';
			document.getElementById('overviewEmpty').style.display = data.loaded ? 'none' : '';
			const metricLabels = [['functions','Functions'],['sections','Sections'],['imports','Imports'],['exports','Exports'],['strings','Strings'],['bookmarks','Bookmarks']];
			document.getElementById('metrics').innerHTML = metricLabels.map(([key,label]) => '<div class="metric"><strong>' + esc(data.metrics[key]) + '</strong><span>' + label + '</span></div>').join('');
			document.getElementById('targetTable').innerHTML = row('Format', data.format) + row('Architecture', data.architecture) + row('Entry point', hex(data.entryPoint), 'code') + row('Image base', hex(data.baseAddress), 'code') + row('Image size', size(data.imageSize)) + row('Target ID', compactId(data.analysisTarget?.id), 'code') + row('Session generation', data.analysisSession ? data.analysisSession.generation : 'Unavailable', 'code') + row('Emulator', data.emulator) + row('Session cache', data.sessionPersistence ? data.sessionPath : 'Unavailable', 'code');
			document.getElementById('engineTable').innerHTML = data.engines.map(engine => '<tr><th><span class="status-dot ' + esc(engine.status) + '"></span>' + esc(engine.label) + '</th><td><span>' + esc(engine.status) + '</span><br><span class="detail">' + esc(engine.detail) + '</span></td></tr>').join('');
			document.getElementById('workspaceTable').innerHTML = row('Workspace', data.workspaceName || 'No workspace') + row('Job files', data.jobFiles.length);
			document.getElementById('jobList').innerHTML = data.jobFiles.length ? data.jobFiles.map(job => '<div class="job">' + esc(job) + '</div>').join('') : '<div class="job detail">No .hexcore_job.json files found</div>';
			const targetSelect = document.getElementById('workspaceTarget');
			targetSelect.innerHTML = data.workspaceTargets.length
				? data.workspaceTargets.map(target => '<option value="' + esc(target.path) + '">' + esc(target.relativePath) + '</option>').join('')
				: '<option value="">No binaries found in this workspace</option>';
			document.querySelector('[data-load-target]').disabled = data.workspaceTargets.length === 0;
			document.getElementById('workspaceTargetsSection').style.display = data.workspaceTargets.length ? '' : 'none';
			const findingSelect = document.getElementById('jobFinding');
			const selectedFinding = findingSelect.value;
			findingSelect.innerHTML = data.savedFindings.length
				? data.savedFindings.map(finding => '<option value="' + esc(finding.id) + '">' + esc(finding.label) + ' - ' + esc(finding.functionAddress || finding.referenceAddress || finding.stringAddress) + '</option>').join('')
				: '<option value="">No saved findings</option>';
			if (data.savedFindings.some(finding => finding.id === selectedFinding)) findingSelect.value = selectedFinding;
			document.getElementById('createJobButton').disabled = !data.loaded || data.savedFindings.length === 0;
			const investigationJobs = data.jobFiles.filter(job => String(job).toLowerCase().includes('hexcore-jobs'));
			document.getElementById('generatedJobList').innerHTML = investigationJobs.length ? investigationJobs.map(job => '<div class="job">' + esc(job) + '</div>').join('') : '<div class="job detail">No investigation jobs created</div>';
			document.getElementById('recentResults').innerHTML = findingRows(data.recentFindings, data.investigations.length ? 'No references found' : 'Run an investigation to collect references');
			document.getElementById('savedResults').innerHTML = findingRows(data.savedFindings, 'No saved findings');
			document.getElementById('savedTab').textContent = data.savedFindings.length ? 'Saved (' + data.savedFindings.length + ')' : 'Saved';
			document.getElementById('investigationHistory').innerHTML = data.investigations.length
				? data.investigations.map(item => '<div class="history-row"><div><div class="history-title">' + esc(item.title) + '</div><div class="history-meta">' + esc(item.query) + ' / ' + esc(item.resultCount) + ' results' + (item.status === 'complete-truncated' ? ' (limited)' : '') + '</div></div><button data-open-investigation="' + esc(item.id) + '">View</button></div>').join('')
				: '<div class="job detail">No investigations recorded</div>';
			document.querySelector('[data-action="pe"]')?.toggleAttribute('disabled', !data.loaded || !String(data.format).startsWith('PE'));
			if (busy) {
				document.querySelectorAll('[data-action], [data-load-target], [data-finding-action], #investigationForm button, #jobForm button').forEach(button => {
					if (button.dataset.action !== 'refresh') button.disabled = true;
				});
			}
		}
		document.addEventListener('click', event => {
			const button = event.target.closest('button');
			if (!button || button.disabled) return;
			if (button.hasAttribute('data-open-center')) { vscode.postMessage({ type: 'openCenter' }); return; }
			if (button.dataset.tab) { selectTab(button.dataset.tab); return; }
			if (button.hasAttribute('data-load-target')) {
				const path = document.getElementById('workspaceTarget').value;
				if (path) vscode.postMessage({ type: 'loadTarget', path });
				return;
			}
			if (button.dataset.openInvestigation) {
				vscode.postMessage({ type: 'openInvestigation', id: button.dataset.openInvestigation });
				return;
			}
			if (button.dataset.findingAction && button.dataset.findingId) {
				vscode.postMessage({ type: 'finding', action: button.dataset.findingAction, id: button.dataset.findingId });
				return;
			}
			const action = button.dataset.action;
			if (action === 'refresh') vscode.postMessage({ type: 'refresh' });
			else if (action) vscode.postMessage({ type: 'action', action });
		});
		document.getElementById('investigationPreset').addEventListener('change', event => {
			const custom = event.target.value === 'custom';
			const input = document.getElementById('investigationQuery');
			input.disabled = !custom;
			input.placeholder = custom ? 'health, IsDebuggerPresent, endpoint...' : 'Preset terms will be searched';
		});
		document.getElementById('investigationForm').addEventListener('submit', event => {
			event.preventDefault();
			const preset = document.getElementById('investigationPreset').value;
			const query = document.getElementById('investigationQuery').value;
			if (preset === 'custom' && query.trim().length < 3) {
				document.getElementById('investigationQuery').focus();
				return;
			}
			vscode.postMessage({ type: 'runInvestigation', preset, query });
		});
		document.getElementById('jobForm').addEventListener('submit', event => {
			event.preventDefault();
			const name = document.getElementById('jobName').value.trim();
			const findingId = document.getElementById('jobFinding').value;
			if (!name) {
				document.getElementById('jobName').focus();
				return;
			}
			if (findingId) vscode.postMessage({ type: 'createInvestigationJob', name, findingId });
		});
		window.addEventListener('message', event => {
			if (event.data.type === 'snapshot') {
				document.getElementById('errorBanner').style.display = 'none';
				render(event.data.snapshot);
			} else if (event.data.type === 'error') {
				const banner = document.getElementById('errorBanner');
				banner.textContent = event.data.message;
				banner.style.display = 'block';
			} else if (event.data.type === 'activity') {
				const activity = document.getElementById('activityBanner');
				activity.className = 'activity ' + event.data.status;
				const detail = IS_SIDEBAR && event.data.message
					? event.data.message.split(' Cache:')[0]
					: (event.data.message || '');
				activity.textContent = event.data.status === 'running'
					? 'Running ' + event.data.action + '...'
					: ((event.data.title ? event.data.title + ': ' : '') + detail);
				const running = event.data.status === 'running';
				busy = running;
				if (running) {
					document.querySelectorAll('[data-action], [data-load-target], [data-finding-action], #investigationForm button, #jobForm button').forEach(button => {
						if (button.dataset.action !== 'refresh') button.disabled = true;
					});
				} else if (snapshot) {
					render(snapshot);
				}
			}
		});
		selectTab(IS_SIDEBAR ? 'overview' : (saved.tab || 'overview'));
		vscode.postMessage({ type: 'ready' });
	</script>
</body>
</html>`;
	}
}

function isAnalysisAction(value: unknown): value is AnalysisAction {
	return typeof value === 'string' && [
		'openBinary', 'analyze', 'lift', 'decompile', 'hex', 'yara', 'entropy',
		'pe', 'runJob', 'doctor', 'nativeStatus'
	].includes(value);
}

function parseAnalysisCenterRequest(value: Record<string, unknown>): AnalysisCenterRequest | undefined {
	if (value.type === 'action' && isAnalysisAction(value.action)) {
		return { type: 'action', action: value.action };
	}
	if (value.type === 'loadTarget' && typeof value.path === 'string' && value.path.length <= 32768) {
		return { type: 'loadTarget', path: value.path };
	}
	if (value.type === 'runInvestigation' && isInvestigationPreset(value.preset) && typeof value.query === 'string') {
		return { type: 'runInvestigation', preset: value.preset, query: value.query.slice(0, 256) };
	}
	if (value.type === 'createInvestigationJob' &&
		typeof value.name === 'string' && value.name.trim().length > 0 && value.name.length <= 80 &&
		isFindingId(value.findingId)) {
		return { type: 'createInvestigationJob', name: value.name.trim(), findingId: value.findingId };
	}
	if (value.type === 'openInvestigation' && typeof value.id === 'string' && /^[a-f0-9-]{16,64}$/i.test(value.id)) {
		return { type: 'openInvestigation', id: value.id };
	}
	if (value.type === 'finding' && isFindingAction(value.action) && isFindingId(value.id)) {
		return { type: 'finding', action: value.action, id: value.id };
	}
	return undefined;
}

/**
 * Accepts both the legacy 24-hex finding IDs and the 3.8.4 Analysis Contract
 * `finding:sha256:<digest>:...` stable IDs during the transition.
 */
function isFindingId(value: unknown): value is string {
	if (typeof value !== 'string') {
		return false;
	}
	if (/^[a-f0-9]{24}$/i.test(value)) {
		return true;
	}
	return isAnalysisObjectId(value) && parseAnalysisObjectId(value).kind === 'finding';
}

function isInvestigationPreset(value: unknown): value is InvestigationPreset {
	return typeof value === 'string' && ['custom', 'health', 'anti-debug', 'network', 'credentials'].includes(value);
}

function isFindingAction(value: unknown): value is 'save' | 'unsave' | 'open' | 'decompile' {
	return typeof value === 'string' && ['save', 'unsave', 'open', 'decompile'].includes(value);
}

function describeRequest(request: AnalysisCenterRequest): string {
	switch (request.type) {
		case 'action': return request.action;
		case 'loadTarget': return 'load target';
		case 'runInvestigation': return 'investigation';
		case 'createInvestigationJob': return 'create investigation job';
		case 'openInvestigation': return 'open investigation';
		case 'finding': return request.action === 'decompile' ? 'decompile finding' : `${request.action} finding`;
	}
}

import * as assert from 'assert';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') return '__vscode_mock_semantic_explorer__';
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache.__vscode_mock_semantic_explorer__ = { id: '__vscode_mock_semantic_explorer__', filename: '__vscode_mock_semantic_explorer__', loaded: true, exports: {} } as NodeModule;
const { renderSemanticExplorerHtml } = require('./semanticExplorer') as typeof import('./semanticExplorer');

suite('R37 Semantic Explorer UI', function () {
	this.timeout(60_000);
	test('renders functional evidence views without desktop or mobile viewport overflow', async () => {
		const root = require('path').resolve(__dirname, '..');
		const fs = require('fs') as typeof import('fs');
		const manifest = JSON.parse(fs.readFileSync(require('path').join(root, 'package.json'), 'utf8')) as { activationEvents: string[]; contributes: { commands: Array<{ command: string }> } };
		const extension = fs.readFileSync(require('path').join(root, 'src', 'extension.ts'), 'utf8');
		const runner = fs.readFileSync(require('path').join(root, 'src', 'automationPipelineRunner.ts'), 'utf8');
		for (const command of ['hexcore.semanticExplorer.open']) {
			assert.strictEqual(manifest.activationEvents.filter(item => item === `onCommand:${command}`).length, 1);
			assert.strictEqual(manifest.contributes.commands.filter(item => item.command === command).length, 1);
			assert.strictEqual(extension.split(`registerCommand('${command}'`).length - 1, 1);
			assert.strictEqual(runner.split(`['${command}'`).length - 1, 2);
		}
		const snapshot: import('./semanticExplorer').SemanticExplorerSnapshot = {
			targetIdentity: `target:sha256:${'a'.repeat(64)}`, analysisGeneration: 7, latestAcceptedPropagationGeneration: 7,
			types: [{ typeId: 'type:context', name: 'Context', kind: 'struct', sizeBits: 128, members: [{ name: 'value' }], evidence: { strength: 'debug', producer: 'pdb' } }],
			prototypes: [{ functionIdentity: 'function:0x140001000', callingConventionId: 'win64', returnTypeId: 'type:u64', parameters: [], evidence: { strength: 'definitive', producer: 'analyst' }, evidenceSet: [] }],
			bindings: [{ scope: 'register-value', valueIdentity: 'rcx', typeId: 'type:context', functionIdentity: 'function:0x140001000', evidence: { strength: 'derived', producer: 'r34' } }],
			xrefs: [{ source: { ownerFunctionIdentity: 'function:0x140001000', address: '0x140001010' }, relation: 'data-read', target: { kind: 'global', identity: 'global:counter' }, accessWidthBits: 32, evidenceSet: [], provenanceSet: [] } as any],
			summaries: [{ functionIdentity: 'function:0x140001000', calls: [], globalEffects: [{}], fieldAccesses: [{}], barriers: [], outputHash: 'b'.repeat(64) }],
			conflicts: [{ factKind: 'type', factKey: 'type:context', reason: 'fixture' }], generations: [], dirty: [],
		};
		const html = renderSemanticExplorerHtml(snapshot, 'fixture');
		const browserHtml = html.replace('<script nonce="fixture">', '<script nonce="fixture">globalThis.acquireVsCodeApi=()=>({postMessage:()=>{}});</script><script nonce="fixture">');
		assert.ok(html.includes('Prototype editor'));
		assert.ok(html.includes('Why this target'));
		assert.ok(html.includes('data-undo'));
		assert.ok(!html.includes('<img src=x onerror='));
		const { chromium } = require('playwright') as typeof import('playwright');
		const browser = await chromium.launch({ headless: true });
		try {
			for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
				const page = await browser.newPage({ viewport });
				await page.setContent(browserHtml);
				await page.addStyleTag({ content: ':root{--vscode-foreground:#d8dee9;--vscode-editor-background:#101318;--vscode-sideBar-background:#151922;--vscode-panel-border:#303744;--vscode-descriptionForeground:#93a1b5;--vscode-focusBorder:#8b5cf6;--vscode-textLink-foreground:#61afef;--vscode-button-background:#6d4aff;--vscode-button-foreground:#fff;--vscode-button-secondaryBackground:#293140;--vscode-input-background:#0d1117;--vscode-input-border:#394252;--vscode-editorWarning-foreground:#e5c07b;--vscode-font-family:Segoe UI,sans-serif;--vscode-editor-font-family:Consolas,monospace}' });
				const dimensions = await page.evaluate(() => { const document = (globalThis as any).document; return { body: document.body.scrollWidth, client: document.documentElement.clientWidth, barBottom: document.querySelector('.bar').getBoundingClientRect().bottom, layoutTop: document.querySelector('.layout').getBoundingClientRect().top }; });
				assert.ok(dimensions.body <= dimensions.client, `horizontal overflow at ${viewport.width}px`);
				assert.ok(dimensions.layoutTop >= dimensions.barBottom, 'toolbar and content overlap');
				await page.click('[data-tab="types"]');
				assert.strictEqual(await page.locator('#types').evaluate((element: any) => element.classList.contains('active')), true);
				const screenshot = await page.screenshot();
				assert.ok(screenshot.length > 5000, 'rendered UI screenshot is unexpectedly blank');
				await page.close();
			}
		} finally { await browser.close(); }
	});
});

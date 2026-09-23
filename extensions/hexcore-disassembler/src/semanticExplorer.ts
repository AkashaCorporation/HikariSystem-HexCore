import * as vscode from 'vscode';
import type { DisassemblerEngine } from './disassemblerEngine';
import type { CanonicalReferenceEdge, ReferenceGenerationDiff } from './typedReferenceGraph';
import { openSemanticQueryView, type SemanticQueryCoverage } from './semanticQueryView';
import { propagationEffectIdentity } from './semanticExplanation';

export interface SemanticExplorerSnapshot {
	snapshotSha256?: string;
	universeSha256?: string;
	engineGeneration?: number;
	queryCoverage?: Readonly<SemanticQueryCoverage>;
	targetIdentity: string;
	analysisGeneration: number;
	latestAcceptedPropagationGeneration: number | null;
	types: any[];
	prototypes: any[];
	bindings: any[];
	xrefs: CanonicalReferenceEdge[];
	summaries: any[];
	conflicts: any[];
	generations: any[];
	dirty: any[];
	generationDiff?: ReferenceGenerationDiff;
}

export function buildSemanticExplorerSnapshot(engine: DisassemblerEngine): SemanticExplorerSnapshot {
	const session = engine.getSessionStore();
	if (!session) { throw new Error('Semantic Explorer requires a bound HXDB session.'); }
	const view = openSemanticQueryView(session, { engineGeneration: engine.getAnalysisGeneration() });
	const snapshot = view.exportSnapshot();
	const data = snapshot.data;
	return {
		targetIdentity: view.identity.targetIdentity, analysisGeneration: view.identity.generation,
		engineGeneration: view.identity.engineGeneration, snapshotSha256: view.identity.snapshotSha256,
		universeSha256: view.identity.universeSha256, queryCoverage: view.getCoverage(),
		latestAcceptedPropagationGeneration: view.identity.propagationGeneration,
		types: [...data.types], prototypes: [...data.prototypes], bindings: [...data.bindings],
		xrefs: [...data.references], summaries: [...data.summaries], conflicts: [...data.conflicts],
		generations: [...data.generations], dirty: [...data.dirty],
		...(snapshot.generationDiff ? { generationDiff: snapshot.generationDiff } : {}),
	};
}

function escapeHtml(value: unknown): string {
	return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);
}

function nonce(): string { return `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`; }

export function renderSemanticExplorerHtml(snapshot: SemanticExplorerSnapshot, scriptNonce = nonce()): string {
	const data = JSON.stringify(snapshot).replace(/</g, '\\u003c');
	return `<!doctype html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${scriptNonce}'">
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;overflow:hidden;color:var(--vscode-foreground);background:var(--vscode-editor-background);font:13px var(--vscode-font-family)}button,input,select,textarea{font:inherit;color:inherit}.bar{height:44px;border-bottom:1px solid var(--vscode-panel-border);display:flex;align-items:center;gap:8px;padding:0 14px;overflow:hidden;white-space:nowrap;background:var(--vscode-sideBar-background)}.bar strong{font-size:14px}.grow{flex:1}.muted{color:var(--vscode-descriptionForeground)}.badge{border:1px solid var(--vscode-panel-border);padding:2px 6px;font-size:11px}.warn{color:var(--vscode-editorWarning-foreground)}.layout{display:grid;grid-template-columns:260px minmax(0,1fr);height:calc(100vh - 44px)}aside{border-right:1px solid var(--vscode-panel-border);padding:12px;overflow:auto}main{min-width:0;overflow:auto}.tabs{display:flex;border-bottom:1px solid var(--vscode-panel-border);padding:0 16px;position:sticky;top:0;background:var(--vscode-editor-background);z-index:2}.tab{border:0;background:transparent;padding:11px 12px;border-bottom:2px solid transparent;cursor:pointer}.tab.active{border-color:var(--vscode-focusBorder);color:var(--vscode-textLink-foreground)}.pane{display:none;padding:16px}.pane.active{display:block}.section{max-width:100%;overflow-x:auto;margin-bottom:20px}.section h2{font-size:13px;text-transform:uppercase;font-weight:600;margin:0 0 8px;color:var(--vscode-descriptionForeground)}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--vscode-panel-border);vertical-align:top}th{font-size:11px;text-transform:uppercase;color:var(--vscode-descriptionForeground)}code{font-family:var(--vscode-editor-font-family);font-size:12px}.btn{border:1px solid var(--vscode-button-border,transparent);background:var(--vscode-button-secondaryBackground);padding:5px 8px;cursor:pointer}.btn.primary{background:var(--vscode-button-background);color:var(--vscode-button-foreground)}.icon{width:28px;padding:5px}.field{display:grid;gap:4px;margin-bottom:9px}.field input,.field select,.field textarea{width:100%;background:var(--vscode-input-background);border:1px solid var(--vscode-input-border);padding:6px}.field textarea{min-height:70px;font-family:var(--vscode-editor-font-family)}details{border-top:1px solid var(--vscode-panel-border);padding:7px 0}summary{cursor:pointer}.list button{display:block;width:100%;text-align:left;border:0;background:transparent;padding:6px;cursor:pointer}.list button:hover{background:var(--vscode-list-hoverBackground)}.empty{padding:18px;color:var(--vscode-descriptionForeground)}.explain-actions{display:flex;gap:4px;flex-wrap:wrap}.explain{padding:3px 6px;white-space:nowrap}dialog{width:min(920px,calc(100vw - 32px));max-height:calc(100vh - 32px);padding:0;border:1px solid var(--vscode-panel-border);background:var(--vscode-editor-background);color:var(--vscode-foreground)}dialog::backdrop{background:rgba(0,0,0,.55)}.dialog-head{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid var(--vscode-panel-border)}.dialog-body{padding:12px;overflow:auto;max-height:calc(100vh - 90px)}.dialog-body pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px var(--vscode-editor-font-family)}.navigation{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}@media(max-width:760px){.layout{grid-template-columns:1fr}aside{display:none}.pane{padding:10px}.tabs{padding:0;overflow-x:auto}.tab{padding:10px 8px}}
</style></head><body><header class="bar"><strong>Semantic Explorer</strong><span class="badge">generation ${snapshot.analysisGeneration}</span><span class="badge">propagation ${snapshot.latestAcceptedPropagationGeneration ?? 'none'}</span>${snapshot.snapshotSha256 ? `<span class="badge" title="${escapeHtml(snapshot.snapshotSha256)}">snapshot ${escapeHtml(snapshot.snapshotSha256.slice(0, 8))}</span>` : ''}${snapshot.queryCoverage?.semanticReadErrors ? `<span class="warn" title="${escapeHtml(snapshot.queryCoverage.errors.map(error => `${error.collection}: ${error.code}`).join('; '))}">${snapshot.queryCoverage.semanticReadErrors} unavailable reads</span>` : ''}${snapshot.dirty.length ? `<span class="warn">${snapshot.dirty.length} stale summaries</span>` : ''}<span class="grow"></span><button class="btn icon" id="refresh" title="Refresh">&#x21bb;</button></header>
<div class="layout"><aside><div class="muted">${escapeHtml(snapshot.targetIdentity)}</div><h3>Functions</h3><div class="list">${snapshot.prototypes.map((prototype: any) => `<button data-function="${escapeHtml(prototype.functionIdentity)}">${escapeHtml(prototype.functionIdentity)}<br><span class="muted">${escapeHtml(prototype.callingConventionId)}</span></button>`).join('') || '<div class="empty">No prototypes</div>'}</div></aside>
<main><nav class="tabs"><button class="tab active" data-tab="prototypes">Prototypes</button><button class="tab" data-tab="types">Types</button><button class="tab" data-tab="xrefs">Xrefs</button><button class="tab" data-tab="history">History</button></nav>
<section class="pane active" id="prototypes"><div class="section"><h2>Prototype editor</h2><div class="field"><label>Function identity</label><input id="fn"></div><div class="field"><label>Calling convention</label><select id="cc">${['cdecl','stdcall','fastcall','thiscall','vectorcall','win64','sysv64','aapcs32','aapcs64'].map(value=>`<option>${value}</option>`).join('')}</select></div><div class="field"><label>Return type</label><input id="ret" value="void"></div><div class="field"><label>Parameters JSON</label><textarea id="params">[]</textarea></div><button class="btn primary" id="apply">Apply</button> <button class="btn" id="clear">Undo override</button></div><div class="section"><h2>Stored prototypes</h2>${table(['Function','CC','Return','Evidence','Why','Actions'],snapshot.prototypes.map((p:any)=>[p.functionIdentity,p.callingConventionId,p.returnTypeId,`${p.evidence?.strength ?? 'unknown'} / ${p.evidence?.producer ?? 'unknown'}`,why(p.evidenceSet),explainButton('prototype',p.prototypeId)]))}</div><div class="section"><h2>Local and global bindings</h2>${table(['Scope','Value','Type','Function','Evidence','Actions'],snapshot.bindings.map((b:any)=>[b.scope,b.valueIdentity,b.typeId,b.functionIdentity ?? '',`${b.evidence?.strength ?? ''} / ${b.evidence?.producer ?? ''}`,explainButton('type-binding',b.bindingId)]))}</div></section>
<section class="pane" id="types"><div class="section"><h2>Type catalog</h2>${table(['Name','Kind','Size','Members','Evidence','Actions'],(snapshot.types as any[]).map((t:any)=>[t.name ?? t.typeId,t.kind,t.sizeBits ?? '',t.members?.length ?? 0,`${t.evidence?.strength ?? ''} / ${t.evidence?.producer ?? ''}`,raw(`<button class="btn" data-rename="${escapeHtml(t.typeId)}">Rename</button> <button class="btn" data-undo="${escapeHtml(t.typeId)}">Undo</button> <button class="btn" data-delete="${escapeHtml(t.typeId)}">Delete</button>`)]))}</div></section>
<section class="pane" id="xrefs"><div class="section"><h2>Typed references</h2>${table(['Source','Relation','Target','Width','Why this target','Actions'],snapshot.xrefs.map((x:any)=>[raw(`${escapeHtml(x.source.ownerFunctionIdentity)}<br><code>${escapeHtml(x.source.address)}</code>`),x.relation,`${x.target.kind}: ${x.target.identity}`,x.accessWidthBits ?? '',why([...(x.evidenceSet ?? []),...(x.provenanceSet ?? [])]),explainButton('typed-reference',x.edgeId)]))}</div><div class="section"><h2>Function summaries</h2>${table(['Function','Calls','Globals','Fields','Barriers','Output','Effects'],snapshot.summaries.map((s:any)=>[s.functionIdentity,s.calls?.length ?? 0,s.globalEffects?.length ?? 0,s.fieldAccesses?.length ?? 0,s.barriers?.length ?? 0,String(s.outputHash).slice(0,12),effectButtons(s)]))}</div></section>
<section class="pane" id="history"><div class="section"><h2>Conflicts and stale state</h2>${table(['Kind','Key','Reason','State','Actions'],snapshot.conflicts.map((c:any)=>[c.factKind,c.factKey,c.reason,'conflict',explainButton('semantic-conflict',c.conflictHash)]).concat(snapshot.dirty.map((d:any)=>['summary',d.functionIdentity,d.reason,'stale',''])))}</div><div class="section"><h2>Generation diff</h2>${snapshot.generationDiff ? table(['From','To','Added','Removed','Changed'],[[snapshot.generationDiff.fromGeneration,snapshot.generationDiff.toGeneration,snapshot.generationDiff.added.length,snapshot.generationDiff.removed.length,snapshot.generationDiff.changed.length]]) : '<div class="empty">No generation diff yet</div>'}</div></section>
</main></div><dialog id="explanation"><div class="dialog-head"><strong id="explanation-title">Semantic explanation</strong><span id="explanation-status" class="badge"></span><span class="grow"></span><button class="btn icon" id="explanation-close" title="Close">&#x2715;</button></div><div class="dialog-body"><div id="explanation-navigation" class="navigation"></div><pre id="explanation-json"></pre></div></dialog><script nonce="${scriptNonce}">const vscode=acquireVsCodeApi();const data=${data};document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab,.pane').forEach(e=>e.classList.remove('active'));b.classList.add('active');document.getElementById(b.dataset.tab).classList.add('active')});document.querySelectorAll('[data-function]').forEach(b=>b.onclick=()=>{const p=data.prototypes.find(x=>x.functionIdentity===b.dataset.function);fn.value=p.functionIdentity;cc.value=p.callingConventionId;ret.value=p.returnTypeId;params.value=JSON.stringify(p.parameters.map(x=>({ordinal:x.ordinal,name:x.name,type:{typeId:x.typeId}})),null,2)});refresh.onclick=()=>vscode.postMessage({command:'refresh'});apply.onclick=()=>vscode.postMessage({command:'applyPrototype',functionIdentity:fn.value,callingConventionId:cc.value,returnType:ret.value,parameters:JSON.parse(params.value)});clear.onclick=()=>vscode.postMessage({command:'clearOverride',functionIdentity:fn.value});document.querySelectorAll('[data-rename]').forEach(b=>b.onclick=()=>{const name=prompt('New type name');if(name)vscode.postMessage({command:'renameType',typeId:b.dataset.rename,name})});document.querySelectorAll('[data-delete]').forEach(b=>b.onclick=()=>confirm('Delete this unused type?')&&vscode.postMessage({command:'deleteType',typeId:b.dataset.delete}));document.querySelectorAll('[data-undo]').forEach(b=>b.onclick=()=>vscode.postMessage({command:'undoType',typeId:b.dataset.undo}));document.querySelectorAll('[data-explain-kind]').forEach(b=>b.onclick=()=>vscode.postMessage({command:'explain',kind:b.dataset.explainKind,identity:b.dataset.explainId,snapshotSha256:data.snapshotSha256}));const explanation=document.getElementById('explanation');document.getElementById('explanation-close').onclick=()=>explanation.close();window.addEventListener('message',event=>{if(event.data?.command!=='explanation')return;const result=event.data.result;document.getElementById('explanation-title').textContent=result.request?.kind+' '+(result.claim?.label??result.request?.identity??'');document.getElementById('explanation-status').textContent=result.status;document.getElementById('explanation-json').textContent=JSON.stringify(result,null,2);const nav=document.getElementById('explanation-navigation');nav.replaceChildren();for(const item of result.navigation??[]){if(!item.address)continue;const button=document.createElement('button');button.className='btn';button.textContent='Open '+item.address;button.onclick=()=>vscode.postMessage({command:'openAddress',address:item.address});nav.appendChild(button)}if(!explanation.open)explanation.showModal()});</script></body></html>`;
}

function table(headers: string[], rows: unknown[][]): string {
	if (!rows.length) return '<div class="empty">No rows in this snapshot</div>';
	return `<table><thead><tr>${headers.map(header=>`<th>${escapeHtml(header)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map(cell=>`<td>${cell && typeof cell === 'object' && '__html' in cell ? String((cell as {__html:string}).__html) : escapeHtml(cell)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}
function raw(html: string): { __html: string } { return { __html: html }; }
function why(evidence: any): { __html: string } { return raw(`<details><summary>Evidence</summary><code>${escapeHtml(JSON.stringify(evidence ?? [],null,2))}</code></details>`); }
function explainButton(kind: string, identity: string): { __html: string } { return raw(`<button class="btn explain" data-explain-kind="${escapeHtml(kind)}" data-explain-id="${escapeHtml(identity)}" title="Explain persisted evidence">Explain</button>`); }
function effectButtons(summary: any): { __html: string } {
	const fields = [['parameter','parameterEffects'],['return','returnRelationships'],['call','calls'],['global','globalEffects'],['ownership','ownershipEffects'],['field','fieldAccesses'],['function-pointer','functionPointerTargets']] as const;
	const effects = fields.flatMap(([category, field]) => (summary[field] ?? []).map((effect: unknown, index: number) => ({ category, label: `${category} ${index + 1}`, identity: propagationEffectIdentity(summary.functionIdentity, summary.generation, category, effect) })));
	return raw(`<div class="explain-actions">${effects.map(effect => `<button class="btn explain" data-explain-kind="propagation-effect" data-explain-id="${escapeHtml(effect.identity)}" title="Explain ${escapeHtml(effect.category)} evidence">${escapeHtml(effect.label)}</button>`).join('')}</div>`);
}

export class SemanticExplorerPanel {
	private static current: SemanticExplorerPanel | undefined;
	static show(extensionUri: vscode.Uri, engine: DisassemblerEngine): void {
		if (this.current) { this.current.panel.reveal(); this.current.refresh(); return; }
		this.current = new SemanticExplorerPanel(extensionUri, engine);
	}
	private readonly panel = vscode.window.createWebviewPanel('hexcore.semanticExplorer','HexCore Semantic Explorer',vscode.ViewColumn.One,{enableScripts:true,retainContextWhenHidden:true});
	private constructor(_extensionUri: vscode.Uri, private readonly engine: DisassemblerEngine) {
		this.panel.onDidDispose(()=>{ SemanticExplorerPanel.current=undefined; });
		this.panel.webview.onDidReceiveMessage(async message=>{
			try {
				switch(message.command){
					case 'refresh': break;
					case 'explain': {
						const result = await vscode.commands.executeCommand('hexcore.semantic.explain', { kind: message.kind, identity: message.identity, expected: { snapshotSha256: message.snapshotSha256 } });
						await this.panel.webview.postMessage({ command: 'explanation', result });
						return;
					}
					case 'openAddress': {
						if (typeof message.address !== 'string' || !/^0x[0-9a-f]{1,16}$/i.test(message.address) || BigInt(message.address) > BigInt(Number.MAX_SAFE_INTEGER)) { throw new Error('Explanation address is invalid for the active engine.'); }
						await vscode.commands.executeCommand('hexcore.disasm.goToAddress', Number(BigInt(message.address)));
						return;
					}
					case 'applyPrototype': await vscode.commands.executeCommand('hexcore.types.applyPrototype',{...message,quiet:true}); break;
					case 'clearOverride': await vscode.commands.executeCommand('hexcore.types.clearOverride',{functionIdentity:message.functionIdentity,quiet:true}); break;
					case 'renameType': await vscode.commands.executeCommand('hexcore.typeManager.rename',{typeId:message.typeId,name:message.name,quiet:true}); break;
					case 'deleteType': await vscode.commands.executeCommand('hexcore.typeManager.delete',{typeId:message.typeId,quiet:true}); break;
					case 'undoType': await vscode.commands.executeCommand('hexcore.typeManager.undo',{typeId:message.typeId,quiet:true}); break;
				}
				this.refresh();
			}catch(error){vscode.window.showErrorMessage(`Semantic Explorer: ${error instanceof Error?error.message:String(error)}`)}
		});
		this.refresh();
	}
	private refresh(): void { this.panel.webview.html=renderSemanticExplorerHtml(buildSemanticExplorerSnapshot(this.engine)); }
}

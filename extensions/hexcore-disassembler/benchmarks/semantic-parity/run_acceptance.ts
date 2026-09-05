import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function(request: string, parent: unknown, isMain: boolean, options: unknown) {
  if (request === 'vscode') return '__vscode_mock_semantic_parity__';
  return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache.__vscode_mock_semantic_parity__ = { id:'__vscode_mock_semantic_parity__',filename:'__vscode_mock_semantic_parity__',loaded:true,exports:{workspace:{getConfiguration:()=>({get:(_k:string,f:unknown)=>f}),onDidChangeConfiguration:()=>({dispose(){}}),workspaceFolders:undefined},commands:{executeCommand:async()=>undefined,getCommands:async()=>[]},extensions:{getExtension:()=>undefined},Uri:{file:(file:string)=>({fsPath:file,scheme:'file'})},window:{}}};

const { DisassemblerEngine } = require('../../src/disassemblerEngine') as typeof import('../../src/disassemblerEngine');
const { importPdbSemantics } = require('../../src/pdbSemanticImport') as typeof import('../../src/pdbSemanticImport');
const { applyImportSignatureProvider } = require('../../src/signatureProvider') as typeof import('../../src/signatureProvider');
const { syncWholeProgramPropagation } = require('../../src/wholeProgramPropagationProducer') as typeof import('../../src/wholeProgramPropagationProducer');
const { loadPdbProvider } = require('../../src/pdbProvider') as typeof import('../../src/pdbProvider');
const { recoverRecordsFromPropagation } = require('../../src/recordRecovery') as typeof import('../../src/recordRecovery');

function canonical(value: unknown): unknown { if(Array.isArray(value))return value.map(canonical);if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value as any).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,v])=>[k,canonical(v)]));return value; }
function hash(value: unknown): string { return crypto.createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex'); }
async function main(): Promise<void> {
const root=path.resolve(__dirname);
const manifest=JSON.parse(fs.readFileSync(path.join(root,'build','build-manifest.json'),'utf8').replace(/^\uFEFF/,'')) as any;
const truth=JSON.parse(fs.readFileSync(path.join(root,'build','ground-truth.json'),'utf8')) as any;
const results:any[]=[];
let conventionCorrect=0, conventionTotal=0, exactBoundaries=0, boundaryTotal=0;
const filter=process.env.HEXCORE_PARITY_FILTER;const selectedEntries=filter?manifest.entries.filter((entry:any)=>entry.id.includes(filter)):manifest.entries;
for(const entry of selectedEntries){
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),`hexcore-parity-${entry.id}-`));const target=path.join(directory,'semantic_parity.dll');fs.copyFileSync(entry.binaryPath,target);
  const pdb=entry.pdbPath?path.join(directory,'semantic_parity.pdb'):undefined;if(pdb)fs.copyFileSync(entry.pdbPath,pdb);
  const engine=new DisassemblerEngine();
  try{
    if(!await engine.loadFile(target))throw new Error(`${entry.id}: load failed`);await engine.analyzeAll();
    const configTruth=truth.configurations.find((item:any)=>item.id===entry.id);const boundaries:any[]=[];
    for(const expected of Object.values(configTruth.functions) as any[]){const address=engine.getBaseAddress()+Number.parseInt(expected.export.rva.slice(2),16);const fn=engine.getFunctionAt(address);const exact=Boolean(fn&&fn.address===address);boundaryTotal++;if(exact)exactBoundaries++;boundaries.push({name:expected.function,address:`0x${address.toString(16)}`,exact,size:fn?.size??0});}
	const exportBodyAddress=(name:string)=>{const exportAddress=engine.getBaseAddress()+Number.parseInt(entry.exports.find((x:any)=>x.name===name).rva.slice(2),16);const fn=engine.getFunctionAt(exportAddress);const transfer=fn?.instructions.find((instruction:any)=>(instruction.isJump||instruction.isCall)&&instruction.targetAddress!==undefined);return transfer?.targetAddress??exportAddress;};
    const signatures=applyImportSignatureProvider(engine);let pdbImport:any=null;const materializations:any[]=[];
    if(pdb){pdbImport=await importPdbSemantics(engine,{pdbPath:pdb,maxFunctions:10000});if(pdbImport.provider.status==='error')throw new Error(`${entry.id}: PDB error`);}
	for(const expected of Object.values(configTruth.functions) as any[]){
		const bodyAddress=exportBodyAddress(expected.function);
		if(!engine.getFunctionAt(bodyAddress)){try{await engine.analyzeFunction(bodyAddress,expected.function);}catch(error){materializations.push({name:expected.function,address:`0x${bodyAddress.toString(16)}`,analyzeError:error instanceof Error?error.message:String(error)});continue}}
		const materialized=await engine.materializeFunctionForAnalysis(bodyAddress);materializations.push({name:expected.function,address:`0x${bodyAddress.toString(16)}`,status:materialized.status,instructions:materialized.function?.instructions.length??0});
	}
    const semantic=engine.getSessionStore()!.getSemanticStore();const conventions:any[]=[];
    if(entry.symbols==='debug'&&entry.optimization==='O0')for(const expected of Object.values(configTruth.functions) as any[]){
      const address=exportBodyAddress(expected.function);const prototype=semantic.getPrototype(`function:0x${address.toString(16)}`);const actual=prototype?.callingConventionId??'missing';const correct=actual===expected.expectedCallingConvention;conventionTotal++;if(correct)conventionCorrect++;conventions.push({name:expected.function,address:`0x${address.toString(16)}`,pdbAddress:expected.pdb.address,expected:expected.expectedCallingConvention,actual,correct,hiddenSret:prototype?.parameters.some((p:any)=>p.hiddenSret)??false,variadic:prototype?.variadic??false});
    }
    const closure=syncWholeProgramPropagation(engine);if(!closure.run.committed)throw new Error(`${entry.id}: propagation ${closure.run.status}`);
	const recordRecovery=recoverRecordsFromPropagation(engine.getSessionStore()!.getSemanticStore(),closure.collection.analysisGeneration);
    const known=new Set(engine.getFunctions().map((fn:any)=>`function:0x${fn.address.toString(16)}`));
    const dangling=closure.references.edgesCollected?semantic.getReferenceGraph().query({direction:'both'}).filter((edge:any)=>edge.target.kind==='function'&&!known.has(edge.target.identity)).length:0;
    const callbackAddress=exportBodyAddress('xref_callback');
    const jumpAddress=exportBodyAddress('xref_jump_table');
    const recordAddress=exportBodyAddress('record_roundtrip');
    const callbackIdentity=`function:0x${callbackAddress.toString(16)}`;const jumpIdentity=`function:0x${jumpAddress.toString(16)}`;const recordIdentity=`function:0x${recordAddress.toString(16)}`;
    const callbackEdges=semantic.getReferenceGraph().query({direction:'outgoing',functionIdentity:callbackIdentity});const jumpEdges=semantic.getReferenceGraph().query({direction:'outgoing',functionIdentity:jumpIdentity});const recordSummary=semantic.getWholeProgramPropagationStore().getSummary(recordIdentity);const recordPrototype=semantic.getPrototype(recordIdentity);
    const recordChecks=entry.symbols==='debug'?Object.entries(configTruth.records).map(([name,expected]:any)=>{const actual=semantic.listTypes().find((type:any)=>type.name===name&&(type.kind==='struct'||type.kind==='union'));return{name,found:Boolean(actual),sizeBytes:actual?.sizeBits/8??null,expectedSize:expected?.size??null,exactSize:Boolean(actual&&expected&&actual.sizeBits===expected.size*8)}}):[];
    results.push({id:entry.id,binarySha256:entry.binarySha256,pdbSha256:entry.pdbSha256,boundaries,materializations,conventions,signatureMatched:signatures.matchedCount,pdbPrototypeCount:pdbImport?.prototypeCount??0,pdbPrototypeFailures:pdbImport?.prototypeFailures??0,pdbFailureDiagnostics:pdbImport?.failureDiagnostics??[],referenceGraphHash:closure.references.graphHash,propagationOutputHash:closure.run.outputHash,recordRecoveryHash:recordRecovery.resultHash,recordRecoveryPromoted:recordRecovery.promotedCount,edges:closure.references.edgesCollected,dangling,semanticAddresses:{callback:callbackIdentity,jump:jumpIdentity,record:recordIdentity},callback:{summaryFound:Boolean(semantic.getWholeProgramPropagationStore().getSummary(callbackIdentity)),unresolved:closure.collection.inputs.find((x:any)=>x.functionIdentity===callbackIdentity)?.barriers?.length??0,edges:callbackEdges.length},jumpSummaryFound:Boolean(semantic.getWholeProgramPropagationStore().getSummary(jumpIdentity)),jumpTableEdges:jumpEdges.filter((e:any)=>e.indirectResolutionSet?.some((r:any)=>r.source==='jump-table')).length,recordPrototype:recordPrototype?{callingConventionId:recordPrototype.callingConventionId,parameters:recordPrototype.parameters}:null,recordSummaryFound:Boolean(recordSummary),recordFieldEffects:recordSummary?.fieldAccesses.length??0,recordChecks});
  }finally{engine.dispose();fs.rmSync(directory,{recursive:true,force:true});}
}
const debugEntries=manifest.entries.filter((entry:any)=>entry.pdbPath);const mismatch=loadPdbProvider({pdbPath:debugEntries[0].pdbPath,imageBase:0x180000000,expectedGuid:'00000000-0000-0000-0000-000000000000',expectedAge:99});
const debugRecordChecks=results.flatMap(result=>result.recordChecks);const explicitAbiChecks=results.flatMap(result=>result.conventions.filter((item:any)=>item.name==='cc_sret'||item.name==='cc_variadic'));
const logical={schemaVersion:1,corpusId:manifest.corpusId,filter:filter??null,sourceSha256:manifest.sourceSha256,groundTruthSha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'build','ground-truth.json'))).digest('hex'),metrics:{binaryCount:results.length,boundaryAccuracy:exactBoundaries/boundaryTotal,conventionAccuracy:conventionTotal?conventionCorrect/conventionTotal:0,conventionCorrect,conventionTotal,totalDangling:results.reduce((n,r)=>n+r.dangling,0),pdbMismatchRejected:mismatch.status==='error'&&!mismatch.identityValidated,exactDebugRecords:debugRecordChecks.every((item:any)=>item.exactSize),explicitSretAndVariadic:explicitAbiChecks.every((item:any)=>item.name==='cc_sret'?item.hiddenSret:item.variadic),qualifiedCallbackCandidates:results.reduce((n,r)=>n+r.callback.edges,0),jumpTableCandidates:results.reduce((n,r)=>n+r.jumpTableEdges,0),recordFieldEffects:results.reduce((n,r)=>n+r.recordFieldEffects,0)},results};
const artifact={...logical,artifactSha256:hash(logical)};const runDir=path.join(root,'runs');fs.mkdirSync(runDir,{recursive:true});fs.writeFileSync(path.join(runDir,'semantic-parity-acceptance.json'),JSON.stringify(artifact,null,2)+'\n');
console.log(JSON.stringify({metrics:artifact.metrics,artifactSha256:artifact.artifactSha256},null,2));
if(!filter&&(artifact.metrics.binaryCount!==16||artifact.metrics.boundaryAccuracy!==1||artifact.metrics.conventionAccuracy!==1||artifact.metrics.totalDangling!==0||!artifact.metrics.pdbMismatchRejected||!artifact.metrics.exactDebugRecords||!artifact.metrics.explicitSretAndVariadic||artifact.metrics.qualifiedCallbackCandidates<1||artifact.metrics.jumpTableCandidates<1||artifact.metrics.recordFieldEffects<1))process.exitCode=1;
}
main().catch(error=>{console.error(error);process.exitCode=1;});

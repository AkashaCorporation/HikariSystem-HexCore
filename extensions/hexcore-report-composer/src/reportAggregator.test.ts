/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ReportAggregator, detectReportType, type ReportSource } from './reportAggregator';

/**
 * Unit tests for ReportAggregator.
 * Validates: Requirements 3.1, 3.3, 3.5
 */

suite('ReportAggregator — scanReportsDirectory', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-report-test-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	test('returns 3 sources from directory with 3 .md reports', () => {
		const files = [
			{ name: 'pe-report.md', content: '# PE Analysis\n\nDOS Header found.' },
			{ name: 'strings-report.md', content: '# Extracted Strings\n\nFound 42 strings.' },
			{ name: 'entropy-report.md', content: '# Entropy\n\nAverage entropy: 6.2' },
		];
		for (const f of files) {
			fs.writeFileSync(path.join(tmpDir, f.name), f.content, 'utf8');
		}

		const aggregator = new ReportAggregator();
		const sources = aggregator.scanReportsDirectory(tmpDir);

		assert.strictEqual(sources.length, 3);
		const names = sources.map(s => s.fileName).sort();
		assert.deepStrictEqual(names, ['entropy-report.md', 'pe-report.md', 'strings-report.md']);

		// Verify detected types
		const peSource = sources.find(s => s.fileName === 'pe-report.md');
		assert.strictEqual(peSource?.type, 'pe-analysis');

		const strSource = sources.find(s => s.fileName === 'strings-report.md');
		assert.strictEqual(strSource?.type, 'strings');

		const entSource = sources.find(s => s.fileName === 'entropy-report.md');
		assert.strictEqual(entSource?.type, 'entropy');
	});

	test('includes both .md and .json files', () => {
		fs.writeFileSync(path.join(tmpDir, 'report.md'), '# PE Analysis report', 'utf8');
		fs.writeFileSync(path.join(tmpDir, 'data.json'), '{"type":"hash","SHA256":"abc"}', 'utf8');

		const aggregator = new ReportAggregator();
		const sources = aggregator.scanReportsDirectory(tmpDir);

		assert.strictEqual(sources.length, 2);
		const exts = sources.map(s => path.extname(s.fileName)).sort();
		assert.deepStrictEqual(exts, ['.json', '.md']);
	});

	test('ignores non-.md/.json files', () => {
		fs.writeFileSync(path.join(tmpDir, 'report.md'), '# Entropy analysis', 'utf8');
		fs.writeFileSync(path.join(tmpDir, 'notes.txt'), 'some notes', 'utf8');
		fs.writeFileSync(path.join(tmpDir, 'image.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));

		const aggregator = new ReportAggregator();
		const sources = aggregator.scanReportsDirectory(tmpDir);

		assert.strictEqual(sources.length, 1);
		assert.strictEqual(sources[0].fileName, 'report.md');
	});

	test('throws error when directory does not exist', () => {
		const aggregator = new ReportAggregator();
		const fakePath = path.join(tmpDir, 'nonexistent');

		assert.throws(
			() => aggregator.scanReportsDirectory(fakePath),
			(err: Error) => {
				assert.ok(err.message.includes('Reports directory not found'));
				return true;
			}
		);
	});

	test('throws error when path is a file, not a directory', () => {
		const filePath = path.join(tmpDir, 'afile.md');
		fs.writeFileSync(filePath, 'content', 'utf8');

		const aggregator = new ReportAggregator();

		assert.throws(
			() => aggregator.scanReportsDirectory(filePath),
			(err: Error) => {
				assert.ok(err.message.includes('Path is not a directory'));
				return true;
			}
		);
	});

	test('returns empty array when directory has no .md or .json files', () => {
		fs.writeFileSync(path.join(tmpDir, 'readme.txt'), 'hello', 'utf8');
		fs.writeFileSync(path.join(tmpDir, 'data.csv'), 'a,b,c', 'utf8');

		const aggregator = new ReportAggregator();
		const sources = aggregator.scanReportsDirectory(tmpDir);

		assert.strictEqual(sources.length, 0);
	});

	test('excludes the output report during terminal recomposition', () => {
		const sourcePath = path.join(tmpDir, 'analysis.json');
		const outputPath = path.join(tmpDir, 'FINAL_REPORT.md');
		fs.writeFileSync(sourcePath, '{"status":"ok"}', 'utf8');
		fs.writeFileSync(outputPath, '# stale pre-terminal report', 'utf8');

		const aggregator = new ReportAggregator();
		const sources = aggregator.scanReportsDirectory(tmpDir, [outputPath]);
		assert.deepStrictEqual(sources.map(source => source.fileName), ['analysis.json']);
	});
});

suite('ReportAggregator — compose', () => {
	test('front-loads coverage and preserves parser rejections without falsely promoting them', () => {
		const sources: ReportSource[] = [
			{ fileName: 'analysis.json', filePath: '/reports/analysis.json', type: 'analysis-index', content: JSON.stringify({
				totalFunctions: 27916, functionsMaterialized: 2, materializedFunctionRatio: 2 / 27916, analysisDepth: 'reconnaissance-only' }) },
			{ fileName: 'ioc.json', filePath: '/reports/ioc.json', type: 'ioc', content: JSON.stringify({ indicators: {
				ipv6: [{ value: '23:59:59' }], ipv4: [{ value: '12.2.2.8', context: '1.3.6.1.4.1.1722.12.2.2.8' }],
			} }) },
		];
		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources);
		assert.strictEqual(report.rejectedIndicators?.length, 2);
		assert.strictEqual(report.crossModuleFindings, undefined);
		const markdown = aggregator.toSummaryMarkdown(report);
		assert.ok(markdown.indexOf('## Analysis Coverage') < markdown.indexOf('## Indicator Validation'));
		assert.ok(markdown.includes('2 / 27916'));
		assert.ok(markdown.includes('reconnaissance-only'));
	});
	test('provenance wins over misleading shape and unrelated JSON text is never rescanned', () => {
		const lineage = { targetId: 'target:a', producers: ['filetype'], command: 'hexcore.filetype.detect', inputIds: [] };
		assert.strictEqual(detectReportType('{"matches": []}', 'anything.json', lineage), 'filetype');
		assert.strictEqual(detectReportType('{"results": [{"value":"Strings"}]}', 'anything.json',
			{ ...lineage, command: 'hexcore.disasm.analyzePEHeadless' }), 'pe-analysis');
		assert.strictEqual(detectReportType('{"format": "oops", "message": "Strings YARA Entropy"}', 'anything.json'), 'unknown');
		const sources = ['a.json', 'b.json'].map(fileName => ({ fileName, filePath: fileName, type: 'unknown', content: '{"schemaUrl":"https://example.test/schema"}' }));
		assert.strictEqual(new ReportAggregator().compose(sources).crossModuleFindings, undefined);
	});
	test('detects and renders HQL evidence without fabricating confidence', () => {
		const hql = {
			success: true, status: 'ok', command: 'hexcore.hql.scanHeadless',
			targetCount: 2, completedTargetCount: 2, failedTargetCount: 0,
			matchedFunctionCount: 1, totalFindings: 1,
			results: [
				{
					address: '0x140001000', function: 'xor_worker', nodeCount: 20,
					adapterCoverage: { totalNodes: 20, lossyNodes: 1, coverage: 0.95, unsupportedNodeCounts: { CAsmStmt: 1 } },
					signatureSetSha256: 'a'.repeat(64),
					findings: [{ signatureId: 'crypto.xor_present', structuralCompleteness: 1, evidenceLevel: 'signal', adapterCoverage: 0.95, matchCount: 1 }],
				},
				{
					address: '0x140002000', function: 'clean_negative', nodeCount: 5,
					adapterCoverage: { totalNodes: 5, lossyNodes: 0, coverage: 1, unsupportedNodeCounts: {} },
					signatureSetSha256: 'a'.repeat(64), findings: [],
				},
			],
		};
		const content = JSON.stringify(hql);
		assert.strictEqual(detectReportType(content, 'hql.json'), 'hql');
		assert.strictEqual(detectReportType(content, 'opaque.json', {
			targetId: 'target:sha256:a', producers: ['hexcore-disassembler@1.4.58'],
			command: 'hexcore.hql.scanHeadless', inputIds: [],
		}), 'hql');
		const source = { filePath: '/reports/hql.json', fileName: 'hql.json', content, type: 'hql' };
		const markdown = new ReportAggregator().toSummaryMarkdown(new ReportAggregator().compose([source]));
		assert.ok(markdown.includes('## HQL Semantic Scan'));
		assert.ok(markdown.includes('| hql.json | ok | 2 | 1 | 1 | 1 | 1 | 0.0 none structural | aaaaaaaaaaaa |'));
		assert.ok(markdown.includes('| xor_worker | 0x140001000 | crypto.xor_present | signal | 1.000 | 0.950 | not calibrated |'));
		assert.ok(markdown.includes('### HQL No-Match Results'));
		assert.ok(markdown.includes('| clean_negative | 0x140002000 | 5 | 1.000 |'));
		assert.ok(markdown.includes('### HQL Adapter Loss And Budgets'));
		assert.ok(markdown.includes('CAsmStmt:1'));
		assert.ok(markdown.includes('structural evidence'));
		assert.ok(!markdown.includes('confidence 1.0'));
	});

	test('renders R37 semantic coverage, provider hashes, barriers and runtime corroboration', () => {
		const sources = [
			{
				filePath: '/reports/propagation.json', fileName: 'propagation.json', type: 'semantic-propagation',
				content: JSON.stringify({ command: 'hexcore.propagation.solve', semanticStatus: 'partial', outputHash: 'a'.repeat(64),
					references: { edgesCollected: 12 }, collection: { analysisGeneration: 7, barrierCount: 2 },
					run: { status: 'committed', generation: 7, summaries: [{ conflicts: [{ reason: 'fixture' }] }] } }),
			},
			{
				filePath: '/reports/pdb.json', fileName: 'pdb.json', type: 'semantic-provider',
				content: JSON.stringify({ command: 'hexcore.pdb.importSemantics', prototypeCount: 9, auxiliaryTypeCount: 4,
					provider: { providerVersion: 'pdb-r36', status: 'partial', pdbSha256: 'b'.repeat(64) }, types: { typeCount: 5 } }),
			},
			{
				filePath: '/reports/runtime.json', fileName: 'runtime.json', type: 'runtime-evidence',
				content: JSON.stringify({ runtimeEvidence: { producer: 'hexcore-debugger:runtime-observations-r37', normalizedIdentitySha256: 'c'.repeat(64),
					target: { binarySha256: 'd'.repeat(64) }, inputConfigurationSha256: 'e'.repeat(64), traceConfigurationSha256: 'f'.repeat(64), observations: [{ kind: 'memory-write' }], truncated: false } }),
			},
		] as ReportSource[];
		const markdown = new ReportAggregator().toSummaryMarkdown(new ReportAggregator().compose(sources));
		assert.ok(markdown.includes('## Semantic Model Coverage'));
		assert.ok(markdown.includes('### Semantic Providers'));
		assert.ok(markdown.includes('### Runtime Corroboration'));
		assert.ok(markdown.includes('Runtime observations are bound'));
		assert.ok(markdown.includes('2 | 7 |'));
	});
	test('same-lineage deterministic reruns are replicated, never corroborated', () => {
		const lineage = {
			targetId: 'target:sha256:abc',
			producers: ['hexcore-disassembler@1.4.46'],
			command: 'hexcore.disasm.windowsFilesystemAuditHeadless',
			configurationSha256: 'config-a',
			inputIds: ['artifact:sha256:analysis'],
		};
		const content = JSON.stringify({ status: 'partial', value: 'https://example.test', generatedAt: 'volatile' });
		const sources = ['audit-a.json', 'audit-b.json'].map(fileName => ({
			filePath: `/reports/${fileName}`,
			fileName,
			content,
			type: 'windows-filesystem-audit',
			lineage,
			normalizedIdentity: 'same-normalized-content',
		}));
		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources);
		assert.strictEqual(report.crossModuleFindings, undefined);
		assert.deepStrictEqual(report.replicatedSources, [{
			representative: 'audit-a.json',
			replicas: ['audit-b.json'],
			command: 'hexcore.disasm.windowsFilesystemAuditHeadless',
			normalizedIdentity: 'same-normalized-content',
		}]);
		const markdown = aggregator.toSummaryMarkdown(report);
		assert.ok(markdown.includes('## Replicated Evidence'));
		assert.ok(markdown.includes('do not increase independent corroboration'));
		assert.ok(!markdown.includes('## Corroborated Findings'));
	});

	test('different parsers observing the same binary remain signals without independent corroboration', () => {
		const base = {
			targetId: 'target:sha256:abc',
			configurationSha256: 'same-config',
			inputIds: ['artifact:sha256:binary'],
		};
		const sources = [
			{ fileName: 'ioc.json', producer: 'hexcore-ioc@1', command: 'hexcore.ioc.extract' },
			{ fileName: 'yara.json', producer: 'hexcore-yara@1', command: 'hexcore.yara.scan' },
		].map(item => ({
			filePath: `/reports/${item.fileName}`,
			fileName: item.fileName,
			content: 'https://example.test/path',
			type: 'unknown',
			lineage: { ...base, producers: [item.producer], command: item.command },
		}));
		const report = new ReportAggregator().compose(sources);
		assert.strictEqual(report.crossModuleFindings?.length, 1);
		assert.deepStrictEqual(report.crossModuleFindings?.[0].sources, ['ioc.json', 'yara.json']);
		assert.strictEqual(report.crossModuleFindings?.[0].evidenceLevel, 'signal');
		assert.strictEqual(report.crossModuleFindings?.[0].independentCorroboration, false);
		assert.ok(!new ReportAggregator().toSummaryMarkdown(report).includes('## Corroborated Findings'));
	});

	test('collapses exact audit replicas and compares parameter variants once', () => {
		const baseLineage = {
			targetId: 'target:sha256:abc',
			producers: ['hexcore-disassembler@1.4.47'],
			command: 'hexcore.disasm.windowsFilesystemAuditHeadless',
			inputIds: ['artifact:sha256:analysis'],
		};
		const makeAudit = (fileName: string, maxStringSignals: number, candidates: number, identity: string) => ({
			filePath: `/reports/${fileName}`,
			fileName,
			type: 'windows-filesystem-audit',
			normalizedIdentity: identity,
			lineage: { ...baseLineage, configurationSha256: `config-${maxStringSignals}` },
			content: JSON.stringify({
				status: 'partial', verdict: 'incomplete', target: 'target.exe',
				auditConfiguration: { maxStringSignals },
				principal: { requestedExecutionLevel: 'requireAdministrator', uiAccess: false },
				coverage: { totalFunctions: 10, materializedFunctions: 5, lazyFunctions: 5, materializedFunctionRatio: 0.5 },
				capabilities: [], stringPivots: Array.from({ length: maxStringSignals === 1 ? 1 : 4 }, () => ({})),
				chain: [{ kind: 'writer', status: 'blocked', evidence: [], blockers: ['ACL dataflow missing'] }],
				candidateFunctions: Array.from({ length: candidates }, (_, index) => ({
					address: `0x${(0x401000 + index).toString(16)}`, name: `fn_${index}`, roles: ['path-producer'], evidenceCount: 1, rankScore: index + 1,
				})),
				relatedFunctions: [], candidateEdges: [], topCandidateChains: [],
			}),
		});
		const sources = [
			makeAudit('audit-min.json', 1, 1, 'min'),
			makeAudit('audit-full.json', 250, 3, 'full'),
			makeAudit('audit-full-repeat.json', 250, 3, 'full'),
		];
		const aggregator = new ReportAggregator();
		const markdown = aggregator.toSummaryMarkdown(aggregator.compose(sources));
		assert.strictEqual((markdown.match(/^## Windows Filesystem Boundary Audit$/gm) ?? []).length, 1);
		assert.strictEqual((markdown.match(/^## Windows Filesystem Audit Comparison$/gm) ?? []).length, 1);
		assert.ok(markdown.includes('audit-full-repeat.json'));
		assert.ok(markdown.includes('- Representative: audit-full.json'));
		assert.ok(!markdown.includes('- Representative: audit-min.json'));
	});

	test('summary keeps large analyzer payloads as linked attachments', () => {
		const blob = 'A'.repeat(1_000_000);
		const sources = [{
			filePath: '/reports/advanced-strings.json',
			fileName: 'advanced-strings.json',
			content: JSON.stringify({ status: 'ok', results: [blob] }),
			type: 'strings',
		}];
		const aggregator = new ReportAggregator();
		const markdown = aggregator.toSummaryMarkdown(aggregator.compose(sources));

		assert.ok(markdown.length < 10_000, `summary unexpectedly grew to ${markdown.length} chars`);
		assert.ok(markdown.includes('[advanced-strings.json](<advanced-strings.json>)'));
		assert.ok(markdown.includes('results: 1 item(s)'));
		assert.ok(!markdown.includes(blob.slice(0, 1000)));
	});

	test('filesystem audit summary foregrounds chain blockers and suppresses offset floods', () => {
		const audit = {
			status: 'partial', verdict: 'incomplete', target: 'C:\\target.exe',
			principal: { requestedExecutionLevel: 'requireAdministrator', uiAccess: false },
			coverage: { totalFunctions: 100, materializedFunctions: 25, lazyFunctions: 75, materializedFunctionRatio: 0.25 },
			capabilities: [{ status: 'owned-callsite' }, { status: 'import-signal' }],
			chain: [{ kind: 'writer', status: 'blocked', evidence: ['AddAccessAllowedAce'], blockers: ['Recover effective ACL.'] }],
			candidateFunctions: [{ address: '0x401000', name: 'ZipUtils', roles: ['archive-parser'], evidenceCount: 4 }],
			relatedFunctions: [{ address: '0x402000' }], candidateEdges: [{ from: '0x401000', to: '0x402000' }],
		};
		const sources = [{
			filePath: '/reports/audit.json', fileName: 'audit.json', content: JSON.stringify(audit), type: 'windows-filesystem-audit',
		}];
		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources);
		report.crossModuleFindings = [{ kind: 'offset', value: '0x401000', sources: ['a', 'b'], offsets: [0x401000] }];
		const markdown = aggregator.toSummaryMarkdown(report);
		assert.ok(markdown.includes('## Windows Filesystem Boundary Audit'));
		assert.ok(markdown.includes('requireAdministrator'));
		assert.ok(markdown.includes('Recover effective ACL.'));
		assert.ok(markdown.includes('| 1 | 0x401000 | ZipUtils | archive-parser | 4 | 4 |'));
		assert.ok(!markdown.includes('## Corroborated Findings'));
	});

	test('filesystem audit summary separates downgraded value signals from proofs', () => {
		const audit = {
			status: 'partial', verdict: 'incomplete', target: 'C:\\target.exe',
			principal: {},
			coverage: { totalFunctions: 1, materializedFunctions: 1, lazyFunctions: 0, materializedFunctionRatio: 1 },
			capabilities: [], stringPivots: [], chain: [], candidateFunctions: [], relatedFunctions: [], candidateEdges: [], topCandidateChains: [],
			dataflow: {
				facts: [], typedPaths: [], handleLifecycles: [],
				deepValueFlow: {
					callsites: [{}, {}], proofs: [],
					signals: [{
						kind: 'same-path', status: 'signal', functionAddress: '0x401000', canonicalIdentity: 'storage:[rsp+0x80]',
						producer: { api: 'KERNEL32.dll!GetFullPathNameW', callSite: '0x401010' },
						consumer: { api: 'KERNEL32.dll!CreateFileW', callSite: '0x401030' },
						blockers: ['Storage address escapes to unknown_mutator without a read-only summary.'],
					}],
				},
			},
		};
		const sources = [{ filePath: '/reports/audit.json', fileName: 'audit.json', content: JSON.stringify(audit), type: 'windows-filesystem-audit' }];
		const markdown = new ReportAggregator().toSummaryMarkdown(new ReportAggregator().compose(sources));
		assert.ok(markdown.includes('0 proven identities; 1 downgraded signals'));
		assert.ok(markdown.includes('### Deep Value Identity Signals'));
		assert.ok(markdown.includes('unknown_mutator without a read-only summary'));
		assert.ok(!markdown.includes('### Deep Value Identity Proofs'));
	});

	test('summary reports which disassemblies changed the downstream audit universe', () => {
		const sources = [{
			filePath: '/reports/lazy.disassembly.json',
			fileName: 'lazy.disassembly.json',
			type: 'disassembly',
			content: JSON.stringify({
				status: 'ok', semanticInstructionCount: 42,
				analysisClosure: {
					status: 'committed', functionAddress: '0x401000', auditUniverseChanged: true,
					engineGenerationBefore: 3, engineGenerationAfter: 4,
					sessionGenerationBefore: 7, sessionGenerationAfter: 8,
					reason: 'Function body was classified and committed.',
				},
			}),
		}];
		const aggregator = new ReportAggregator();
		const markdown = aggregator.toSummaryMarkdown(aggregator.compose(sources));
		assert.ok(markdown.includes('## Investigation Closure'));
		assert.ok(markdown.includes('| lazy.disassembly.json | 0x401000 | committed | true | 42 | 3 -> 4 | 7 -> 8 |'));
	});

	test('summary renders isolated native execution and snapshot pressure', () => {
		const sources = [{
			filePath: '/reports/analysis.json', fileName: 'analysis.json', type: 'analysis-index',
			content: JSON.stringify({
				status: 'ok',
				nativeExecution: {
					isolation: 'child-process', outcome: 'completed', workerPid: 42,
					durationMs: 1000, lastPhase: 'completed', snapshotBytes: 100,
					snapshotUncompressedBytes: 1000, heartbeatPath: '.hexcore-meta/heartbeat.json',
				},
			}),
		}];
		const aggregator = new ReportAggregator();
		const markdown = aggregator.toSummaryMarkdown(aggregator.compose(sources));
		assert.ok(markdown.includes('## Native Analysis Execution'));
		assert.ok(markdown.includes('| analysis.json | child-process | completed | 42 | 1000 ms | completed | 100 B / 1000 B raw |'));
	});

	test('compose with analyst notes sets analystNotes and includes in Markdown', () => {
		const sources = [
			{ filePath: '/reports/pe.md', fileName: 'pe.md', content: '# PE Analysis\nDOS Header', type: 'pe-analysis' },
		];
		const notes = 'This sample appears to be a dropper. Further sandbox analysis recommended.';

		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources, notes);

		assert.strictEqual(report.analystNotes, notes);

		const markdown = aggregator.toMarkdown(report);
		assert.ok(markdown.includes('## Analyst Notes'));
		assert.ok(markdown.includes(notes));
	});

	test('compose without notes leaves analystNotes undefined', () => {
		const sources = [
			{ filePath: '/reports/strings.md', fileName: 'strings.md', content: '# Extracted Strings', type: 'strings' },
		];

		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources);

		assert.strictEqual(report.analystNotes, undefined);

		const markdown = aggregator.toMarkdown(report);
		assert.ok(!markdown.includes('## Analyst Notes'));
	});

	test('compose with empty string notes leaves analystNotes undefined', () => {
		const sources = [
			{ filePath: '/reports/hash.md', fileName: 'hash.md', content: '# Hash report', type: 'hash' },
		];

		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources, '');

		assert.strictEqual(report.analystNotes, undefined);
	});

	test('compose creates sections with correct titles from file names', () => {
		const sources = [
			{ filePath: '/reports/pe-analysis.md', fileName: 'pe-analysis.md', content: 'PE content', type: 'pe-analysis' },
			{ filePath: '/reports/entropy_report.md', fileName: 'entropy_report.md', content: 'Entropy content', type: 'entropy' },
		];

		const aggregator = new ReportAggregator();
		const report = aggregator.compose(sources);

		assert.strictEqual(report.sections.length, 2);
		assert.strictEqual(report.sections[0].title, 'Pe Analysis');
		assert.strictEqual(report.sections[1].title, 'Entropy Report');
	});
});

suite('ReportAggregator — detectReportType', () => {
	test('uses audit schema instead of incidental entropy/string/hash keywords', () => {
		assert.strictEqual(detectReportType(JSON.stringify({
			status: 'partial', chain: [], candidateFunctions: [], capabilities: [],
			limitations: ['entropy strings SHA256'],
		}), '02-audit.json'), 'windows-filesystem-audit');
	});

	test('recognizes analysis index and pipeline status schemas', () => {
		assert.strictEqual(detectReportType(JSON.stringify({
			totalFunctions: 10, materializedFunctionRatio: 0.5, functions: [],
		}), '00-analysis.json'), 'analysis-index');
		assert.strictEqual(detectReportType(JSON.stringify({
			jobFile: 'job.json', steps: [], provenance: {},
		}), 'hexcore-pipeline.status.json'), 'pipeline-status');
	});


	test('detects PE Analysis', () => {
		assert.strictEqual(detectReportType('# PE Analysis\nDOS Header found'), 'pe-analysis');
	});

	test('detects Strings', () => {
		assert.strictEqual(detectReportType('Extracted Strings from binary'), 'strings');
	});

	test('detects Entropy', () => {
		assert.strictEqual(detectReportType('Entropy analysis: 7.2'), 'entropy');
	});

	test('detects Base64', () => {
		assert.strictEqual(detectReportType('Base64 decoded content at offset 0x100'), 'base64');
	});

	test('detects Hash/SHA/MD5', () => {
		assert.strictEqual(detectReportType('SHA256: abcdef1234'), 'hash');
		assert.strictEqual(detectReportType('MD5 checksum'), 'hash');
	});

	test('detects ELF Analysis', () => {
		assert.strictEqual(detectReportType('ELF Analysis of /bin/ls'), 'elf-analysis');
	});

	test('detects Disassembly', () => {
		assert.strictEqual(detectReportType('Disassembly output at 0x401000'), 'disassembly');
	});

	test('detects YARA', () => {
		assert.strictEqual(detectReportType('YARA rule matched: suspicious_packer'), 'yara');
	});

	test('returns unknown for unrecognized content', () => {
		assert.strictEqual(detectReportType('Just some random text here'), 'unknown');
	});
});

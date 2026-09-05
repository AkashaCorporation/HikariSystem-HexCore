import * as assert from 'assert';
import { buildWindowsFilesystemAudit } from './windowsFilesystemAudit';

suite('Windows filesystem boundary audit', () => {
	test('distinguishes an owned IAT callsite from an import-only signal', () => {
		const result = buildWindowsFilesystemAudit({
			principal: { status: 'found', requestedExecutionLevel: 'requireAdministrator', uiAccess: false },
			imports: [{
				name: 'KERNEL32.dll',
				functions: [
					{ name: 'WriteFile', address: 0x140006000 },
					{ name: 'MoveFileExW', address: 0x140006008 },
				],
			}],
			functions: [{
				address: 0x140001000,
				name: 'sub_140001000',
				size: 0x40,
				endAddress: 0x140001040,
				callers: [],
				callees: [],
				instructions: [{
					address: 0x140001010,
					bytes: Buffer.from([0xff, 0x15, 0xea, 0x4f, 0, 0]),
					mnemonic: 'call',
					opStr: 'qword ptr [rip + 0x4fea]',
					size: 6,
					isCall: true,
					isJump: false,
					isRet: false,
					isConditional: false,
				}],
			}],
			strings: [],
			lazyFunctions: 0,
		});

		assert.strictEqual(result.capabilities.find(item => item.api === 'WriteFile')?.status, 'owned-callsite');
		assert.strictEqual(result.capabilities.find(item => item.api === 'MoveFileExW')?.status, 'import-signal');
		assert.strictEqual(result.chain[0].status, 'confirmed');
		assert.strictEqual(result.status, 'partial');
		assert.strictEqual(result.securityEvidenceUsable, false);
	});

	test('maps referenced archive vocabulary to its owning function without declaring a finding', () => {
		const result = buildWindowsFilesystemAudit({
			imports: [],
			functions: [{
				address: 0x401000, name: 'ZipUtils_Decompress', size: 0x100, endAddress: 0x401100,
				instructions: [], callers: [], callees: [],
			}],
			strings: [{
				address: 0x500000, string: 'extract zip archive', encoding: 'ascii', references: [0x401020],
			}],
			lazyFunctions: 1,
		});
		assert.deepStrictEqual(result.stringPivots[0].owners, [{
			functionAddress: '0x401000', functionName: 'ZipUtils_Decompress',
		}]);
		assert.strictEqual(result.chain.find(edge => edge.kind === 'parser')?.status, 'signal');
		assert.strictEqual(result.verdict, 'incomplete');
		assert.deepStrictEqual(result.candidateFunctions, [{
			address: '0x401000',
			name: 'ZipUtils_Decompress',
			roles: ['archive-parser'],
			apiEvidence: [],
			stringEvidence: ['unknown:archive:extract zip archive@0x500000'],
			callers: [],
			callees: [],
			evidenceCount: 1,
			roleDiversity: 1,
			graphDegree: 0,
			dataflowPathCount: 0,
			productEvidenceCount: 0,
			thirdPartyEvidenceCount: 0,
			criticalApiWeight: 0,
			productGraphLinks: 0,
			rankScore: 7,
			rankReasons: ['1 direct evidence item(s)', '1 role(s)'],
		}]);
	});

	test('retains enum message-table strings without assigning filesystem roles', () => {
		const instructions = Array.from({ length: 6 }, (_, index) => {
			const address = 0x401000 + index * 3;
			return [
				{ address, bytes: Buffer.alloc(1), mnemonic: 'lea', opStr: `rax, [rip + 0x${(0x100 + index * 8).toString(16)}]`, size: 1, isCall: false, isJump: false, isRet: false, isConditional: false },
				{ address: address + 1, bytes: Buffer.alloc(1), mnemonic: 'mov', opStr: `qword ptr [rbp + 0x${(index * 16).toString(16)}], rax`, size: 1, isCall: false, isJump: false, isRet: false, isConditional: false },
				{ address: address + 2, bytes: Buffer.alloc(1), mnemonic: 'mov', opStr: `dword ptr [rbp + 0x${(index * 16 + 8).toString(16)}], ${index}`, size: 1, isCall: false, isJump: false, isRet: false, isConditional: false },
			];
		}).flat();
		const result = buildWindowsFilesystemAudit({
			imports: [],
			functions: [{
				address: 0x401000, name: 'error_message_table', size: 0x40, endAddress: 0x401040,
				instructions, callers: [], callees: [],
			}],
			strings: [{
				address: 0x500000, string: 'Item is not a directory', encoding: 'ascii', references: [0x401000],
			}],
			lazyFunctions: 0,
		});
		assert.strictEqual(result.stringPivots[0].evidenceClass, 'message-table');
		assert.deepStrictEqual(result.candidateFunctions, []);
		assert.strictEqual(result.chain.find(edge => edge.kind === 'state-location')?.status, 'missing');
		assert.strictEqual(result.chain.find(edge => edge.kind === 'reparse-safety')?.status, 'not-assessed');
	});

	test('retains unclassified graph neighbors for bounded multi-hop navigation', () => {
		const functions = [
			{
				address: 0x401000, name: 'ZipUtils', size: 0x100, endAddress: 0x401100,
				instructions: [], callers: [], callees: [0x402000],
			},
			{
				address: 0x402000, name: 'PathHelper', size: 0x80, endAddress: 0x402080,
				instructions: [], callers: [0x401000], callees: [0x403000],
			},
		];
		const result = buildWindowsFilesystemAudit({
			imports: [], functions, lazyFunctions: 2,
			strings: [{ address: 0x500000, string: 'zip archive', encoding: 'ascii', references: [0x401020] }],
		});
		assert.deepStrictEqual(result.relatedFunctions, [{
			address: '0x402000',
			name: 'PathHelper',
			relation: 'callee',
			sourceCandidates: ['0x401000'],
			callers: ['0x401000'],
			callees: ['0x403000'],
		}]);
	});

	test('builds typed SID/ACL/path/handle signals without claiming value identity', () => {
		const result = buildWindowsFilesystemAudit({
			imports: [
				{ name: 'ADVAPI32.dll', functions: [
					{ name: 'AllocateAndInitializeSid', address: 0x500010 },
					{ name: 'InitializeAcl', address: 0x500020 },
					{ name: 'SetFileSecurityW', address: 0x500030 },
				] },
				{ name: 'KERNEL32.dll', functions: [
					{ name: 'CreateFileW', address: 0x500040 },
					{ name: 'WriteFile', address: 0x500050 },
					{ name: 'CloseHandle', address: 0x500060 },
				] },
			],
			functions: [
				{
					address: 0x401000, name: 'BuildAcl', size: 0x100, endAddress: 0x401100,
					instructions: [], callers: [], callees: [0x500010, 0x500020, 0x500030, 0x402000],
				},
				{
					address: 0x402000, name: 'WriteArchive', size: 0x100, endAddress: 0x402100,
					instructions: [], callers: [0x401000], callees: [0x500040, 0x500050, 0x500060],
				},
			],
			strings: [
				{ address: 0x600000, string: 'extract archive', encoding: 'ascii', references: [0x401010] },
				{ address: 0x600100, string: 'restore path', encoding: 'ascii', references: [0x402010] },
			],
			lazyFunctions: 0,
		});
		const byKind = new Map(result.dataflow.typedPaths.map(flow => [flow.kind, flow]));
		assert.strictEqual(byKind.get('sid-to-acl')?.status, 'co-located-signal');
		assert.strictEqual(byKind.get('acl-to-apply')?.status, 'co-located-signal');
		assert.strictEqual(byKind.get('parser-to-path')?.status, 'call-neighborhood-signal');
		assert.strictEqual(byKind.get('path-to-open')?.status, 'co-located-signal');
		assert.strictEqual(byKind.get('open-to-write')?.status, 'co-located-signal');
		assert.ok(result.dataflow.typedPaths.every(flow => flow.sameValueProven === false));
		assert.deepStrictEqual(result.dataflow.handleLifecycles.map(item => item.functionAddress), ['0x402000']);
		assert.strictEqual(result.dataflow.handleLifecycles[0].sameHandleProven, false);
	});

	test('retains access-mask immediates as candidates from a bounded call window', () => {
		const result = buildWindowsFilesystemAudit({
			imports: [{ name: 'ADVAPI32.dll', functions: [{ name: 'AddAccessAllowedAce', address: 0x500020 }] }],
			functions: [{
				address: 0x401000, name: 'BuildAcl', size: 0x40, endAddress: 0x401040,
				callers: [], callees: [0x500020],
				instructions: [
					{ address: 0x401000, bytes: Buffer.from([0x41, 0xb8, 0x40, 0, 0, 0]), mnemonic: 'mov', opStr: 'r8d, 0x40', size: 6, isCall: false, isJump: false, isRet: false, isConditional: false },
					{ address: 0x401006, bytes: Buffer.from([0xe8, 0, 0, 0, 0]), mnemonic: 'call', opStr: '0x500020', size: 5, isCall: true, isJump: false, isRet: false, isConditional: false, targetAddress: 0x500020 },
				],
			}],
			strings: [], lazyFunctions: 0,
		});
		const fact = result.dataflow.facts.find(item => item.api.endsWith('!AddAccessAllowedAce'));
		assert.ok(fact);
		assert.deepStrictEqual(fact?.immediateCandidates, [{ value: '0x40', labels: ['FILE_DELETE_CHILD'] }]);
		assert.strictEqual(fact?.callSite, '0x401006');
	});

	test('promotes only the typed route whose exact consumer participates in the proof', () => {
		const functions = [
			{
				address: 0x401000, name: 'open_close', size: 0x20, endAddress: 0x401020,
				callers: [], callees: [0x402000],
				instructions: [
					{ address: 0x401000, bytes: Buffer.alloc(1), mnemonic: 'call', opStr: '0x500000', size: 1, isCall: true, isJump: false, isRet: false, isConditional: false, targetAddress: 0x500000 },
					{ address: 0x401001, bytes: Buffer.alloc(1), mnemonic: 'mov', opStr: 'rcx, rax', size: 1, isCall: false, isJump: false, isRet: false, isConditional: false },
					{ address: 0x401002, bytes: Buffer.alloc(1), mnemonic: 'call', opStr: '0x500010', size: 1, isCall: true, isJump: false, isRet: false, isConditional: false, targetAddress: 0x500010 },
				],
			},
			{
				address: 0x402000, name: 'unrelated_write', size: 0x10, endAddress: 0x402010,
				callers: [0x401000], callees: [],
				instructions: [
					{ address: 0x402000, bytes: Buffer.alloc(1), mnemonic: 'call', opStr: '0x500020', size: 1, isCall: true, isJump: false, isRet: false, isConditional: false, targetAddress: 0x500020 },
				],
			},
		];
		const result = buildWindowsFilesystemAudit({
			imports: [{ name: 'KERNEL32.dll', functions: [
				{ name: 'CreateFileW', address: 0x500000 },
				{ name: 'CloseHandle', address: 0x500010 },
				{ name: 'WriteFile', address: 0x500020 },
			] }],
			functions, strings: [], lazyFunctions: 0,
		});
		const paths = new Map(result.dataflow.typedPaths.map(pathValue => [pathValue.kind, pathValue]));
		assert.strictEqual(paths.get('open-to-close')?.sameValueProven, true);
		assert.deepStrictEqual(paths.get('open-to-close')?.functions, ['0x401000']);
		assert.strictEqual(paths.get('open-to-write')?.sameValueProven, false);
		assert.notStrictEqual(paths.get('open-to-write')?.status, 'proven-value-flow');
	});
});

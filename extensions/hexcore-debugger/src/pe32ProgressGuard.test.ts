import * as assert from 'assert';
import {
	nextPe32StagnantBatchCount,
	PE32_MAX_STAGNANT_BATCHES,
	UnicornWrapper,
} from './unicornWrapper';
import { DebugEngine } from './debugEngine';

suite('PE32 worker stagnant-progress guard (#48)', () => {
	test('counts a zero-instruction batch when PC does not move', () => {
		assert.strictEqual(nextPe32StagnantBatchCount(7, 0x72000001n, 0x72000001n, 0), 8);
	});

	test('resets when an instruction executes', () => {
		assert.strictEqual(nextPe32StagnantBatchCount(7, 0x401000n, 0x401000n, 1), 0);
	});

	test('resets when stub dispatch redirects PC', () => {
		assert.strictEqual(nextPe32StagnantBatchCount(7, 0x72000001n, 0x401020n, 0), 0);
	});

	test('configured bound matches the ELF fail-safe', () => {
		assert.strictEqual(PE32_MAX_STAGNANT_BATCHES, 5000);
	});

	test('full PE32 loop aborts a null-dispatch stub that never advances', async () => {
		const pc = 0x72000001n;
		let batches = 0;
		const wrapper = Object.create(UnicornWrapper.prototype) as any;
		wrapper._pe32Worker = {
			regRead: async () => pc,
			regWrite: async () => undefined,
			executeBatch: async () => {
				batches++;
				return {
					instructionsExecuted: 0,
					pc,
					error: null,
					faultInfo: null,
					stubHit: true,
					stubAddress: pc,
					stopped: false,
				};
			},
		};
		wrapper.unicornModule = { X86_REG: { EIP: 1, EAX: 2 } };
		wrapper.architecture = 'x86';
		wrapper.state = {
			isRunning: false, isPaused: false, isReady: false,
			currentAddress: pc, instructionsExecuted: 0,
		};
		wrapper.breakpoints = new Set();
		wrapper.codeHooks = new Map();
		wrapper.deferredMemoryWrites = [];
		wrapper.deferredRegisterWrites = new Map();
		wrapper._pe32StubRangeStart = 0x72000000n;
		wrapper._pe32StubRangeEnd = 0x72040000n;
		wrapper._pe32StubRangesExtra = [];
		wrapper._pe32StubCallback = async () => null;

		await assert.rejects(
			wrapper.startPe32Worker(pc, 0n, 0),
			/PE32 worker stalled at 0x72000001/,
		);
		assert.strictEqual(batches, PE32_MAX_STAGNANT_BATCHES);
		assert.match(wrapper.state.lastError, /zero-progress batches/);
	});

	test('direct PE32 stub dispatch propagates API output buffers to the worker', async () => {
		const stubPc = 0x700000a0n;
		const outputPtr = 0x5000n;
		const output = Buffer.from('8096980000000000', 'hex');
		const workerWrites: Array<{ address: bigint; data: Buffer }> = [];
		const wrapper = Object.create(UnicornWrapper.prototype) as any;

		wrapper._pe32Worker = {
			regRead: async () => stubPc,
			regWrite: async () => undefined,
			memWrite: async (address: bigint, data: Buffer) => {
				workerWrites.push({ address, data: Buffer.from(data) });
			},
			executeBatch: async () => ({
				instructionsExecuted: 1,
				pc: stubPc,
				error: null,
				faultInfo: null,
				stubHit: true,
				stubAddress: stubPc,
				stopped: false,
			}),
		};
		wrapper.uc = { memWrite: () => undefined };
		wrapper.unicornModule = { X86_REG: { EIP: 1, EAX: 2 } };
		wrapper.architecture = 'x86';
		wrapper.state = {
			isRunning: false, isPaused: false, isReady: false,
			currentAddress: stubPc, instructionsExecuted: 0,
		};
		wrapper.breakpoints = new Set();
		wrapper.codeHooks = new Map();
		wrapper.deferredMemoryWrites = [];
		wrapper.deferredRegisterWrites = new Map();
		wrapper._pe32StubRangeStart = 0x70000000n;
		wrapper._pe32StubRangeEnd = 0x70040000n;
		wrapper._pe32StubRangesExtra = [];
		wrapper._pe32StubCallback = async () => {
			wrapper.writeMemorySync(outputPtr, output);
			return { returnValue: 1n, newPc: 0x401005n };
		};

		await wrapper.startPe32Worker(stubPc, 0n, 1);

		assert.deepStrictEqual(workerWrites, [{ address: outputPtr, data: output }]);
		assert.deepStrictEqual(wrapper.deferredMemoryWrites, []);
	});

	test('stops on a breakpoint reached inside a PE32 worker batch', async () => {
		const entry = 0x401000n;
		const breakpoint = 0x40178en;
		let workerPc = entry;
		let observedTerminals: bigint[] = [];
		const wrapper = Object.create(UnicornWrapper.prototype) as any;
		wrapper._pe32Worker = {
			regRead: async () => workerPc,
			executeBatch: async (_start: bigint, _count: number, terminals: bigint[]) => {
				observedTerminals = terminals;
				workerPc = breakpoint;
				return {
					instructionsExecuted: 37,
					pc: breakpoint,
					error: null,
					faultInfo: null,
					stubHit: false,
					stubAddress: null,
					stopped: true,
				};
			},
		};
		wrapper.unicornModule = { X86_REG: { EIP: 1, EAX: 2 } };
		wrapper.architecture = 'x86';
		wrapper.state = {
			isRunning: false, isPaused: false, isReady: false,
			currentAddress: entry, instructionsExecuted: 0,
		};
		wrapper.breakpoints = new Set([breakpoint]);
		wrapper.codeHooks = new Map();
		wrapper.deferredMemoryWrites = [];
		wrapper.deferredRegisterWrites = new Map();
		wrapper._pe32StubRangeStart = 0x72000000n;
		wrapper._pe32StubRangeEnd = 0x72040000n;
		wrapper._pe32StubRangesExtra = [];

		await wrapper.startPe32Worker(entry, 0n, 10_000);

		assert.ok(observedTerminals.includes(breakpoint));
		assert.strictEqual(wrapper.state.currentAddress, breakpoint);
		assert.strictEqual(wrapper.state.isPaused, true);
		assert.strictEqual(wrapper.state.instructionsExecuted, 37);
	});

	test('new PE32 run clears a stale fault before reporting a breakpoint', async () => {
		const breakpoint = 0x40178en;
		const wrapper = Object.create(UnicornWrapper.prototype) as any;
		wrapper._pe32Worker = {
			// PE32/x86 native register reads are numbers at runtime even though the
			// cross-architecture client also supports bigint for x64.
			regRead: async () => Number(breakpoint),
			executeBatch: async () => ({
				instructionsExecuted: 1, pc: Number(breakpoint), error: null, faultInfo: null,
				stubHit: false, stubAddress: null, stopped: true,
			}),
		};
		wrapper.unicornModule = { X86_REG: { EIP: 1, EAX: 2 } };
		wrapper.architecture = 'x86';
		wrapper.state = {
			isRunning: false, isPaused: false, isReady: false,
			currentAddress: 0x401000n, instructionsExecuted: 0,
			lastError: 'UC_ERR_READ_UNMAPPED from a repaired prior run',
		};
		wrapper.lastError = wrapper.state.lastError;
		wrapper._lastFaultInfo = { address: '0xdeadbeef' };
		wrapper.breakpoints = new Set([breakpoint]);
		wrapper.codeHooks = new Map();
		wrapper.deferredMemoryWrites = [];
		wrapper.deferredRegisterWrites = new Map();
		wrapper._pe32StubRangeStart = 0x72000000n;
		wrapper._pe32StubRangeEnd = 0x72040000n;
		wrapper._pe32StubRangesExtra = [];

		await wrapper.start(0x401000n, 0n, 0, 10);

		assert.strictEqual(wrapper.state.currentAddress, breakpoint);
		assert.strictEqual(wrapper.state.lastError, undefined);
		assert.strictEqual(wrapper.getLastFaultInfo(), undefined);
		assert.strictEqual(wrapper.state.isPaused, true);
	});

	test('captures configured artifacts once when execution stops at a breakpoint', async () => {
		const address = 0x40178en;
		const engine = Object.create(DebugEngine.prototype) as any;
		engine.emulator = {
			getState: () => ({ currentAddress: address, instructionsExecuted: 209 }),
			getBreakpoints: () => [address],
		};
		engine.emulationOptions = {
			breakpointConfigs: [{ address: '0x40178e', autoSnapshot: true }],
		};
		const captured: unknown[] = [];
		const dumpTriggers: string[] = [];
		engine.takeBreakpointSnapshot = async (config: unknown) => { captured.push(config); };
		engine.collectMemoryDumps = async (trigger: string) => { dumpTriggers.push(trigger); };

		await engine.captureBreakpointArtifacts();
		await engine.captureBreakpointArtifacts();

		assert.strictEqual(captured.length, 1);
		assert.deepStrictEqual(captured[0], { address: '0x40178e', autoSnapshot: true });
		assert.deepStrictEqual(dumpTriggers, ['breakpoint']);
	});
});

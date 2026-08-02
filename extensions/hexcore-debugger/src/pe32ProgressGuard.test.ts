import * as assert from 'assert';
import {
	nextPe32StagnantBatchCount,
	PE32_MAX_STAGNANT_BATCHES,
	UnicornWrapper,
} from './unicornWrapper';

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
});

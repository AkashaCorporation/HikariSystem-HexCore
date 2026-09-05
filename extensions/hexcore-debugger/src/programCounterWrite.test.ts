import * as assert from 'assert';
import { UnicornWrapper } from './unicornWrapper';

function createState(currentAddress = 0x401000n) {
	return {
		isRunning: false,
		isPaused: true,
		isReady: true,
		currentAddress,
		instructionsExecuted: 0,
	};
}

suite('Program-counter register writes', () => {
	test('labels PE workers by the actual target bitness', () => {
		const wrapper = Object.create(UnicornWrapper.prototype) as any;
		wrapper._arm64Worker = undefined;
		wrapper._x64ElfWorker = undefined;
		wrapper._pe32Worker = {};
		wrapper.architecture = 'x64';
		assert.strictEqual(wrapper.getExecutionBackend(), 'worker-pe64');
		wrapper.architecture = 'x86';
		assert.strictEqual(wrapper.getExecutionBackend(), 'worker-pe32');
	});

	test('direct x64 RIP write updates the address used by continue', async () => {
		const writes: Array<{ register: number; value: bigint }> = [];
		const wrapper = Object.create(UnicornWrapper.prototype) as any;
		wrapper.architecture = 'x64';
		wrapper.state = createState();
		wrapper._arm64Worker = undefined;
		wrapper._x64ElfWorker = undefined;
		wrapper._pe32Worker = undefined;
		wrapper.deferredRegisterWrites = new Map();
		wrapper._insideBlockingHook = false;
		wrapper.unicornModule = {
			X86_REG: { RIP: 1, RAX: 2 },
			ARM64_REG: {},
		};
		wrapper.uc = {
			regWrite: (register: number, value: bigint) => writes.push({ register, value }),
		};

		await wrapper.setRegister('RIP', 0x1400832f8n);
		assert.strictEqual(wrapper.state.currentAddress, 0x1400832f8n);
		assert.deepStrictEqual(writes, [{ register: 1, value: 0x1400832f8n }]);

		await wrapper.setRegister('RAX', 0x55n);
		assert.strictEqual(wrapper.state.currentAddress, 0x1400832f8n);
	});

	test('PE32 worker EIP write updates the address used by continue', async () => {
		const wrapper = Object.create(UnicornWrapper.prototype) as any;
		wrapper.architecture = 'x86';
		wrapper.state = createState();
		wrapper._arm64Worker = undefined;
		wrapper._x64ElfWorker = undefined;
		wrapper._pe32Worker = { regWrite: async () => undefined };
		wrapper.unicornModule = {
			X86_REG: { EIP: 1, EFLAGS: 2 },
		};

		await wrapper.setRegister('eip', 0x402000);
		assert.strictEqual(wrapper.state.currentAddress, 0x402000n);
	});

	test('ARM64 worker PC write updates the address used by continue', async () => {
		const wrapper = Object.create(UnicornWrapper.prototype) as any;
		wrapper.architecture = 'arm64';
		wrapper.state = createState();
		wrapper._arm64Worker = { regWrite: async () => undefined };
		wrapper._x64ElfWorker = undefined;
		wrapper._pe32Worker = undefined;
		wrapper.unicornModule = {
			ARM64_REG: { PC: 1 },
		};

		await wrapper.setRegister('PC', 0xffff000010001000n);
		assert.strictEqual(wrapper.state.currentAddress, 0xffff000010001000n);
	});

	test('deferred RIP write updates state only when applied', async () => {
		const wrapper = Object.create(UnicornWrapper.prototype) as any;
		wrapper.architecture = 'x64';
		wrapper.state = { ...createState(), isRunning: true };
		wrapper._arm64Worker = undefined;
		wrapper._x64ElfWorker = undefined;
		wrapper._pe32Worker = undefined;
		wrapper.deferredMemoryWrites = [];
		wrapper.deferredRegisterWrites = new Map();
		wrapper._insideBlockingHook = false;
		wrapper.unicornModule = {
			X86_REG: { RIP: 1 },
			ARM64_REG: {},
		};
		wrapper.uc = {
			regWrite: () => undefined,
		};

		await wrapper.setRegister('rip', 0x1401e4d35n);
		assert.strictEqual(wrapper.state.currentAddress, 0x401000n);

		wrapper.state.isRunning = false;
		wrapper.applyDeferredMutations();
		assert.strictEqual(wrapper.state.currentAddress, 0x1401e4d35n);
	});
});

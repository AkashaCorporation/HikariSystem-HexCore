'use strict';

const assert = require('assert');
const { Unicorn, ARCH, MODE, PROT, HOOK, ARM64_REG, archSupported } = require('../index.js');

async function main() {
	if (!archSupported(ARCH.ARM64)) {
		console.log('ARM64 not supported, skipping async interrupt test.');
		return;
	}

	const uc = new Unicorn(ARCH.ARM64, MODE.LITTLE_ENDIAN);
	let hook;
	let calls = 0;

	try {
		uc.memMap(0x10000n, 0x1000, PROT.ALL);
		const svc = Buffer.alloc(4);
		svc.writeUInt32LE(0xD4000001);
		uc.memWrite(0x10000n, svc);
		uc.regWrite(ARM64_REG.PC, 0x10000n);

		hook = uc.hookAdd(HOOK.INTR, (intno) => {
			assert.strictEqual(intno, 2);
			calls++;
		});

		await uc.emuStartAsync(0x10000n, 0n, 0, 1);
		assert.strictEqual(calls, 1, 'async INTR callback must complete before the promise resolves');
		console.log('Async ARM64 interrupt hook: PASS');
	} finally {
		if (hook !== undefined) {
			uc.hookDel(hook);
		}
		uc.close();
	}
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});

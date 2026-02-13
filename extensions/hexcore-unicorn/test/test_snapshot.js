const { Unicorn, ARCH, MODE, PROT } = require('../index');

try {
	console.log('Loading Unicorn...');
	const uc = new Unicorn(ARCH.X86, MODE.MODE_32);

	// Map memory
	const ADDRESS = 0x10000;
	uc.memMap(ADDRESS, 4096, PROT.ALL);

	// 1. Setup Initial State
	console.log('Setting up state...');
	uc.regWrite(3 /* EBX? X86_REG_EBX */, 42);
	uc.memWrite(ADDRESS, Buffer.from([0xAA, 0xBB, 0xCC, 0xDD]));

	// 2. Save State
	console.log('Saving state...');
	const snapshot = uc.stateSave();

	if (!snapshot.context || !snapshot.memory) {
		throw new Error('Snapshot missing context or memory fields');
	}
	console.log(`Snapshot took. Memory regions: ${snapshot.memory.length}`);

	// 3. Modify State (Corrupt it)
	console.log('Modifying state (corruption)...');
	uc.regWrite(3, 9999);
	uc.memWrite(ADDRESS, Buffer.from([0x00, 0x00, 0x00, 0x00]));

	// Verify corruption
	const regCorrupted = uc.regRead(3);
	const memCorrupted = uc.memRead(ADDRESS, 4);
	if (regCorrupted == 42 || memCorrupted[0] == 0xAA) {
		throw new Error('State was not modified!');
	}

	// 4. Restore State
	console.log('Restoring state...');
	uc.stateRestore(snapshot);

	// 5. Verify Restoration
	console.log('Verifying restoration...');
	const regRestored = uc.regRead(3);
	const memRestored = uc.memRead(ADDRESS, 4);

	console.log(`Register: ${regRestored} (Expected 42)`);
	console.log(`Memory: ${memRestored.toString('hex')} (Expected aabbccdd)`);

	if (regRestored != 42) {
		throw new Error(`Register restoration failed! Got ${regRestored}`);
	}

	if (memRestored[0] !== 0xAA || memRestored[1] !== 0xBB) {
		throw new Error(`Memory restoration failed! Got ${memRestored.toString('hex')}`);
	}

	console.log('Snapshot Test PASSED!');
	uc.close();
} catch (e) {
	console.error('FAILED:', e);
	process.exit(1);
}

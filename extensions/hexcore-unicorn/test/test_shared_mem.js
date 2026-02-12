const { Unicorn, ARCH, MODE, PROT } = require('../index');

try {
	console.log('Loading Unicorn...');
	const uc = new Unicorn(ARCH.X86, MODE.MODE_32);

	console.log('Creating Shared Memory...');
	const sab = new SharedArrayBuffer(4096);
	const uint8 = new Uint8Array(sab);
	const buffer = Buffer.from(sab); // Create Buffer view

	// Fill with pattern
	uint8.fill(0xCC);

	const ADDRESS = 0x10000;

	// Map shared memory
	console.log('Mapping memory...');
	uc.memMapPtr(ADDRESS, buffer, PROT.ALL);

	// Write to SAB from JS
	uint8[0] = 0x90; // NOP

	console.log('Reading from Unicorn (expecting 0x90)...');
	const data = uc.memRead(ADDRESS, 4);
	console.log('Read:', data);

	if (data[0] !== 0x90) {
		throw new Error(`Shared Memory failed! Expected 0x90, got 0x${data[0].toString(16)}`);
	}

	console.log('Forcing GC...');
	// Try to trigger GC to see if mapped memory stays valid
	if (global.gc) {
		global.gc();
	} else {
		console.log('GC not available (run with --expose-gc)');
	}

	// Read again
	console.log('Reading after GC...');
	const data2 = uc.memRead(ADDRESS, 4);
	console.log('Read:', data2);

	if (data2[0] !== 0x90) {
		throw new Error('Memory corrupted after GC!');
	}

	uc.close();
	console.log('PASSED');
} catch (e) {
	console.error('FAILED:', e);
	process.exit(1);
}

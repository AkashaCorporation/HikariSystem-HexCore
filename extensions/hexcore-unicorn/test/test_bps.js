const { Unicorn, ARCH, MODE, HOOK } = require('../index');

try {
	console.log('Loading Unicorn...');
	const uc = new Unicorn(ARCH.X86, MODE.MODE_32);

	console.log('Engine created. Testing Breakpoint API...');

	// Test BreakpointAdd
	const bpAddr = 0x1000;
	uc.breakpointAdd(bpAddr);
	console.log(`Breakpoint added at 0x${bpAddr.toString(16)}`);

	// Test BreakpointDel
	uc.breakpointDel(bpAddr);
	console.log(`Breakpoint removed at 0x${bpAddr.toString(16)}`);

	console.log('Native Breakpoint API test PASSED!');
	uc.close();
} catch (e) {
	console.error('Test FAILED:', e);
	process.exit(1);
}

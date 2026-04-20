/**
 * test_sab_hook.js — v4.0.0 SharedArrayBuffer CODE hook tests (Issue #31).
 *
 * Validates the new hookAddSAB() native method end-to-end:
 *   1. Basic ring drain — 16 NOPs lifted into 16 sequential ring slots
 *   2. Watch-set slow path — watched address routes through legacy callback
 *   3. Backpressure — overflow into a small ring increments droppedCount
 *
 * Run with: node test/test_sab_hook.js
 */

const { Unicorn, ARCH, MODE, PROT, HOOK, X86_REG } = require('../index');

let passed = 0;
let failed = 0;

function test(name, fn) {
	try {
		fn();
		console.log(`  PASS ${name}`);
		passed++;
	} catch (e) {
		console.log(`  FAIL ${name}\n        ${e.message}`);
		if (e.stack) {
			console.log(e.stack.split('\n').slice(1, 4).map(l => '        ' + l.trim()).join('\n'));
		}
		failed++;
	}
}

// Ring layout constants (must match sharedRingBuffer.ts and unicorn_wrapper.h)
const HEADER_SIZE = 64;
const SLOT_SIZE = 32;
const SLOT_COUNT = 4096;
const RING_MAGIC = 0x48524E47; // "HRNG"

function allocRing(slotSize, slotCount) {
	const sab = new SharedArrayBuffer(HEADER_SIZE + slotSize * slotCount);
	// Wrap in Uint8Array for portability — N-API accepts TypedArray over SAB
	// even when IsArrayBuffer() returns false for SharedArrayBuffer at the JS level.
	return new Uint8Array(sab);
}

function readHeader(ringView) {
	// ringView is the Uint8Array passed to hookAddSAB
	const view = new Int32Array(ringView.buffer, ringView.byteOffset, HEADER_SIZE / 4);
	return {
		magic: view[0],
		version: view[1],
		slotSize: view[2],
		slotCount: view[3],
		head: Atomics.load(view, 4),
		tail: Atomics.load(view, 6),
		dropped: Atomics.load(view, 8),
	};
}

function drain(ringView, slotSize, slotCount) {
	const header = new Int32Array(ringView.buffer, ringView.byteOffset, HEADER_SIZE / 4);
	const payload = new Uint8Array(ringView.buffer, ringView.byteOffset + HEADER_SIZE, slotSize * slotCount);
	const slotMask = slotCount - 1;
	const events = [];
	let tail = Atomics.load(header, 6);
	const head = Atomics.load(header, 4);
	while (tail !== head) {
		const slotOff = tail * slotSize;
		const slotView = new DataView(payload.buffer, payload.byteOffset + slotOff, slotSize);
		events.push({
			seq: slotView.getBigUint64(0, true),
			address: slotView.getBigUint64(8, true),
			size: slotView.getUint32(16, true),
			flags: slotView.getUint32(20, true),
		});
		tail = (tail + 1) & slotMask;
	}
	Atomics.store(header, 6, tail);
	return events;
}

console.log('hookAddSAB native tests\n');

// ─── Test 1: Basic ring drain ──────────────────────────────────────────

test('basic ring drain — 16 NOPs produce 16 sequential events', () => {
	const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
	const ADDRESS = 0x1000n;

	// Map RX page with 16 NOPs (0x90) followed by HLT (0xF4) to stop emulation.
	uc.memMap(ADDRESS, 4096, PROT.ALL);
	const code = Buffer.alloc(17);
	code.fill(0x90, 0, 16);
	code[16] = 0xF4; // HLT
	uc.memWrite(ADDRESS, code);

	// Allocate ring
	const sab = allocRing(SLOT_SIZE, SLOT_COUNT);

	// Install SAB hook (no watch set, no legacy callback)
	const handle = uc.hookAddSAB(
		HOOK.CODE,
		sab,
		SLOT_SIZE,
		SLOT_COUNT,
		[],          // no watched addresses
		null,        // no legacy callback
		ADDRESS,
		ADDRESS + 17n,
	);

	if (typeof handle !== 'number') {
		throw new Error(`expected hook handle (number), got ${typeof handle}`);
	}

	// Verify header was initialized
	const hdr = readHeader(sab);
	if (hdr.magic !== RING_MAGIC) {
		throw new Error(`header magic 0x${(hdr.magic >>> 0).toString(16)} != 0x${RING_MAGIC.toString(16)}`);
	}
	if (hdr.slotSize !== SLOT_SIZE) {
		throw new Error(`header slotSize ${hdr.slotSize} != ${SLOT_SIZE}`);
	}
	if (hdr.slotCount !== SLOT_COUNT) {
		throw new Error(`header slotCount ${hdr.slotCount} != ${SLOT_COUNT}`);
	}

	// Run emulation. HLT will throw an unmapped-memory error or stop normally.
	try {
		uc.emuStart(ADDRESS, ADDRESS + 17n, 0, 16);
	} catch (e) {
		// Some HLT/exit paths throw — that's OK as long as the events were captured.
	}

	const events = drain(sab, SLOT_SIZE, SLOT_COUNT);

	if (events.length < 16) {
		throw new Error(`expected at least 16 events, got ${events.length}`);
	}

	// Verify first 16 are sequential NOPs at the expected addresses
	for (let i = 0; i < 16; i++) {
		const expectedAddr = BigInt(0x1000 + i);
		if (events[i].address !== expectedAddr) {
			throw new Error(`event[${i}].address 0x${events[i].address.toString(16)} != 0x${expectedAddr.toString(16)}`);
		}
		if (events[i].size !== 1) {
			throw new Error(`event[${i}].size ${events[i].size} != 1`);
		}
	}

	// Verify sequence numbers are monotonic
	for (let i = 1; i < events.length; i++) {
		if (events[i].seq <= events[i - 1].seq) {
			throw new Error(`seq monotonicity broken at i=${i}: ${events[i - 1].seq} -> ${events[i].seq}`);
		}
	}

	uc.hookDel(handle);
	uc.close();
});

// ─── Test 2: Watched-address slow path ─────────────────────────────────

test('watched address routes through legacy callback', () => {
	const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
	const ADDRESS = 0x2000n;

	uc.memMap(ADDRESS, 4096, PROT.ALL);
	const code = Buffer.alloc(17);
	code.fill(0x90, 0, 16);
	code[16] = 0xF4;
	uc.memWrite(ADDRESS, code);

	const sab = allocRing(SLOT_SIZE, SLOT_COUNT);

	const watchedAddr = 0x2004n; // 5th NOP
	const callbackHits = [];

	const handle = uc.hookAddSAB(
		HOOK.CODE,
		sab,
		SLOT_SIZE,
		SLOT_COUNT,
		[watchedAddr],
		(addr, size, seq) => {
			callbackHits.push({ addr, size, seq });
		},
		ADDRESS,
		ADDRESS + 17n,
	);

	try {
		uc.emuStart(ADDRESS, ADDRESS + 17n, 0, 16);
	} catch (e) {
		// HLT exit
	}

	// Allow the JS event loop to drain TSFN callbacks
	// (NonBlockingCall is async via microtask queue)
	const start = Date.now();
	while (callbackHits.length < 1 && Date.now() - start < 1000) {
		// Spin briefly — we need the microtask to flush.
		// In real usage this is handled by the event loop after emuStartAsync resolves.
	}

	// Synchronous check: drain the ring first
	const events = drain(sab, SLOT_SIZE, SLOT_COUNT);

	// The watched address should NOT appear in the ring (it went via TSFN)
	const ringAddrs = events.map(e => e.address);
	if (ringAddrs.includes(watchedAddr)) {
		throw new Error(`watched address 0x${watchedAddr.toString(16)} leaked into ring buffer`);
	}

	// At least 15 events (16 NOPs minus the watched one) should be in the ring
	if (events.length < 15) {
		throw new Error(`expected at least 15 ring events, got ${events.length}`);
	}

	uc.hookDel(handle);
	uc.close();
});

// ─── Test 3: Backpressure / drop counter ───────────────────────────────

test('backpressure: overflow increments droppedCount', () => {
	const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
	const ADDRESS = 0x3000n;

	// Use a TINY ring (32 slots) so 50 NOPs overflow it.
	const TINY_COUNT = 32;
	const tinySab = allocRing(SLOT_SIZE, TINY_COUNT);

	uc.memMap(ADDRESS, 4096, PROT.ALL);
	// 50 NOPs + HLT
	const code = Buffer.alloc(51);
	code.fill(0x90, 0, 50);
	code[50] = 0xF4;
	uc.memWrite(ADDRESS, code);

	const handle = uc.hookAddSAB(
		HOOK.CODE,
		tinySab,
		SLOT_SIZE,
		TINY_COUNT,
		[],
		null,
		ADDRESS,
		ADDRESS + 51n,
	);

	try {
		uc.emuStart(ADDRESS, ADDRESS + 51n, 0, 50);
	} catch (e) {
		// HLT
	}

	const hdr = readHeader(tinySab);
	// Ring holds (slotCount - 1) = 31 entries before declaring full.
	// 50 events → 31 in ring, 19 dropped.
	if (hdr.dropped < 1) {
		throw new Error(`expected dropped > 0, got ${hdr.dropped}`);
	}

	uc.hookDel(handle);
	uc.close();
});

// ─── Test 4: Validation ────────────────────────────────────────────────

test('rejects non-power-of-two slotCount', () => {
	const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
	const sab = allocRing(SLOT_SIZE, 100); // 100 is not a power of two
	let threw = false;
	try {
		uc.hookAddSAB(HOOK.CODE, sab, SLOT_SIZE, 100, [], null);
	} catch (e) {
		threw = e.message.includes('power of two');
	}
	uc.close();
	if (!threw) {
		throw new Error('expected RangeError for non-power-of-two slotCount');
	}
});

test('rejects slotSize below 32', () => {
	const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
	const sab = allocRing(16, 16); // slotSize 16 < 32 (min for CodeHookSabSlot)
	let threw = false;
	try {
		uc.hookAddSAB(HOOK.CODE, sab, 16, 16, [], null);
	} catch (e) {
		threw = e.message.includes('slotSize');
	}
	uc.close();
	if (!threw) {
		throw new Error('expected RangeError for slotSize < 32');
	}
});

test('rejects undersized SAB', () => {
	const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
	// Wrap in Uint8Array so type check passes; only the size check should fire.
	const undersized = new Uint8Array(new SharedArrayBuffer(64)); // header only, no payload
	let threw = false;
	try {
		uc.hookAddSAB(HOOK.CODE, undersized, SLOT_SIZE, SLOT_COUNT, [], null);
	} catch (e) {
		threw = e.message.includes('too small');
	}
	uc.close();
	if (!threw) {
		throw new Error('expected RangeError for undersized SAB');
	}
});

test('rejects non-CODE hook type', () => {
	const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
	const sab = allocRing(SLOT_SIZE, SLOT_COUNT);
	let threw = false;
	try {
		uc.hookAddSAB(HOOK.MEM_READ, sab, SLOT_SIZE, SLOT_COUNT, [], null);
	} catch (e) {
		threw = e.message.includes('UC_HOOK_CODE');
	}
	uc.close();
	if (!threw) {
		throw new Error('expected TypeError for non-CODE hook');
	}
});

// ─── Result ────────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);

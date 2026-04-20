/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Zero-Copy IPC Proof of Concept
 *
 * Demonstrates SharedArrayBuffer usage with N-API native modules.
 * This PoC shows the data flow pattern without requiring the actual native module.
 *
 * NOT FOR PRODUCTION USE — feasibility study for v4.0.0
 */

/**
 * Header layout constants for the shared buffer
 * Total header size: 64 bytes (cache-line aligned)
 */
const HEADER_OFFSETS = {
	LOCK_FLAG: 0,      // int32 - 0 = unlocked, 1 = locked
	DATA_SIZE: 4,      // uint32 - actual data size in payload
	STATUS: 8,         // int32 - operation status code
	SEQUENCE_ID: 12,   // uint32 - for ordering
	TIMESTAMP: 16,     // uint64 - for debugging
	USER_DATA_1: 24,   // uint64 - extension-specific
	USER_DATA_2: 32,   // uint64 - extension-specific
	DATA_START: 64     // Payload starts here
} as const;

/**
 * Operation status codes
 */
const STATUS_CODES = {
	IDLE: 0,
	BUSY: 1,
	COMPLETE: 2,
	ERROR: -1
} as const;

/**
 * Wraps a SharedArrayBuffer with typed views and synchronization primitives.
 * Provides zero-copy data access between JavaScript and native C++ code.
 */
class SharedMemoryBuffer {
	private readonly _buffer: SharedArrayBuffer;
	private readonly _headerView: Int32Array;
	private readonly _dataView: Uint8Array;
	private readonly _size: number;

	/**
	 * Creates a new SharedMemoryBuffer with the specified payload size.
	 * Total allocation = header (64 bytes) + payload size.
	 *
	 * @param payloadSize Size of the data payload region in bytes
	 */
	constructor(payloadSize: number) {
		this._size = HEADER_OFFSETS.DATA_START + payloadSize;
		this._buffer = new SharedArrayBuffer(this._size);

		// Create header view (first 64 bytes as int32 array)
		this._headerView = new Int32Array(this._buffer, 0, HEADER_OFFSETS.DATA_START / 4);

		// Create data view (payload region only)
		this._dataView = new Uint8Array(this._buffer, HEADER_OFFSETS.DATA_START, payloadSize);

		// Initialize header
		this._initializeHeader();
	}

	/**
	 * Gets the underlying SharedArrayBuffer for passing to native code.
	 */
	get buffer(): SharedArrayBuffer {
		return this._buffer;
	}

	/**
	 * Gets the total size of the shared buffer (header + payload).
	 */
	get totalSize(): number {
		return this._size;
	}

	/**
	 * Gets the payload data size.
	 */
	get payloadSize(): number {
		return this._dataView.byteLength;
	}

	/**
	 * Gets a view of the payload data region.
	 * This is a zero-copy view into the shared memory.
	 */
	get dataView(): Uint8Array {
		return this._dataView;
	}

	/**
	 * Gets the raw header view for advanced operations.
	 */
	get headerView(): Int32Array {
		return this._headerView;
	}

	/**
	 * Acquires the lock on the shared buffer.
	 * Uses Atomics.wait for efficient blocking (in worker contexts).
	 *
	 * @param timeoutMs Optional timeout in milliseconds
	 * @returns true if lock acquired, false on timeout
	 */
	acquireLock(timeoutMs?: number): boolean {
		const lockFlag = new Int32Array(this._buffer, HEADER_OFFSETS.LOCK_FLAG, 1);

		// Spin-lock with exponential backoff for main thread
		// (Atomics.wait is only available in workers)
		const startTime = Date.now();
		let spinCount = 0;

		while (true) {
			// Try to acquire lock (compare-exchange pattern)
			const current = Atomics.load(lockFlag, 0);
			if (current === 0) {
				const acquired = Atomics.compareExchange(lockFlag, 0, 0, 1);
				if (acquired === 0) {
					return true; // Lock acquired
				}
			}

			// Check timeout
			if (timeoutMs !== undefined && (Date.now() - startTime) > timeoutMs) {
				return false;
			}

			// Exponential backoff
			spinCount++;
			if (spinCount < 10) {
				// Busy spin for first few iterations (low latency)
				continue;
			} else if (spinCount < 20) {
				// Yield to event loop
				continue;
			} else {
				// Longer sleep
				const delay = Math.min(Math.pow(2, spinCount - 20), 100);
				// In a real implementation, use setImmediate or scheduler.yield()
			}
		}
	}

	/**
	 * Releases the lock on the shared buffer.
	 * Notifies any waiters after releasing.
	 */
	releaseLock(): void {
		const lockFlag = new Int32Array(this._buffer, HEADER_OFFSETS.LOCK_FLAG, 1);
		Atomics.store(lockFlag, 0, 0);
		Atomics.notify(lockFlag, 0);
	}

	/**
	 * Gets the current data size from the header.
	 */
	getDataSize(): number {
		const sizeView = new Uint32Array(this._buffer, HEADER_OFFSETS.DATA_SIZE, 1);
		return Atomics.load(sizeView as unknown as Int32Array, 0);
	}

	/**
	 * Sets the data size in the header.
	 *
	 * @param size The data size to set
	 */
	setDataSize(size: number): void {
		const sizeView = new Uint32Array(this._buffer, HEADER_OFFSETS.DATA_SIZE, 1);
		Atomics.store(sizeView as unknown as Int32Array, 0, size);
	}

	/**
	 * Gets the current status code from the header.
	 */
	getStatus(): number {
		const statusView = new Int32Array(this._buffer, HEADER_OFFSETS.STATUS, 1);
		return Atomics.load(statusView, 0);
	}

	/**
	 * Sets the status code in the header.
	 *
	 * @param status The status code to set
	 */
	setStatus(status: number): void {
		const statusView = new Int32Array(this._buffer, HEADER_OFFSETS.STATUS, 1);
		Atomics.store(statusView, 0, status);
	}

	/**
	 * Writes data to the payload region.
	 *
	 * @param data The data to write
	 * @param offset Optional offset within payload region
	 */
	writeData(data: Uint8Array, offset: number = 0): void {
		if (offset + data.length > this._dataView.length) {
			throw new Error('Data exceeds buffer capacity');
		}
		this._dataView.set(data, offset);
		this.setDataSize(offset + data.length);
	}

	/**
	 * Reads data from the payload region.
	 *
	 * @param length Number of bytes to read
	 * @param offset Optional offset within payload region
	 * @returns A copy of the data (use dataView for zero-copy access)
	 */
	readData(length: number, offset: number = 0): Uint8Array {
		return new Uint8Array(this._dataView.buffer, this._dataView.byteOffset + offset, length);
	}

	/**
	 * Waits for the status to change from BUSY to something else.
	 * Uses Atomics.wait for efficient blocking.
	 *
	 * @param timeoutMs Optional timeout in milliseconds
	 * @returns The final status code
	 */
	waitForCompletion(timeoutMs: number = 5000): number {
		const statusView = new Int32Array(this._buffer, HEADER_OFFSETS.STATUS, 1);
		const startTime = Date.now();

		while (true) {
			const status = Atomics.load(statusView, 0);
			if (status !== STATUS_CODES.BUSY) {
				return status;
			}

			if (Date.now() - startTime > timeoutMs) {
				return STATUS_CODES.ERROR;
			}

			// Small delay to prevent busy-waiting
			// In production, use Atomics.wait in a Worker
		}
	}

	/**
	 * Initializes the header to default values.
	 */
	private _initializeHeader(): void {
		this._headerView.fill(0);
		this.setStatus(STATUS_CODES.IDLE);
	}
}

/**
 * Benchmarks the performance difference between copy-based and zero-copy patterns.
 */
class ZeroCopyBenchmark {
	private readonly _iterations: number;
	private readonly _dataSize: number;

	/**
	 * Creates a new benchmark instance.
	 *
	 * @param iterations Number of iterations to run
	 * @param dataSize Size of test data in bytes
	 */
	constructor(iterations: number = 100000, dataSize: number = 1024) {
		this._iterations = iterations;
		this._dataSize = dataSize;
	}

	/**
	 * Runs the complete benchmark suite.
	 */
	run(): BenchmarkResults {
		console.log(`\n=== Zero-Copy IPC Benchmark ===`);
		console.log(`Iterations: ${this._iterations.toLocaleString()}`);
		console.log(`Data size: ${this._dataSize} bytes\n`);

		const copyResults = this._benchmarkCopyPattern();
		const zeroCopyResults = this._benchmarkZeroCopyPattern();

		const speedup = copyResults.avgTime / zeroCopyResults.avgTime;

		return {
			iterations: this._iterations,
			dataSize: this._dataSize,
			copyPattern: copyResults,
			zeroCopyPattern: zeroCopyResults,
			speedup: speedup
		};
	}

	/**
	 * Benchmarks the current copy-based pattern.
	 * Simulates: Buffer.from() -> process -> Buffer.from()
	 */
	private _benchmarkCopyPattern(): PatternResults {
		const testData = Buffer.alloc(this._dataSize);
		for (let i = 0; i < this._dataSize; i++) {
			testData[i] = i % 256;
		}

		const times: number[] = [];

		// Warmup
		for (let i = 0; i < 1000; i++) {
			this._simulateCopyOperation(testData);
		}

		// Benchmark
		const startTotal = performance.now();
		for (let i = 0; i < this._iterations; i++) {
			const start = performance.now();
			this._simulateCopyOperation(testData);
			const end = performance.now();
			times.push(end - start);
		}
		const totalTime = performance.now() - startTotal;

		return this._calculateResults(times, totalTime);
	}

	/**
	 * Benchmarks the proposed zero-copy pattern.
	 * Simulates: SharedArrayBuffer -> direct access -> read result
	 */
	private _benchmarkZeroCopyPattern(): PatternResults {
		const sharedBuffer = new SharedMemoryBuffer(this._dataSize);
		const testData = new Uint8Array(this._dataSize);
		for (let i = 0; i < this._dataSize; i++) {
			testData[i] = i % 256;
		}
		sharedBuffer.writeData(testData);

		const times: number[] = [];

		// Warmup
		for (let i = 0; i < 1000; i++) {
			this._simulateZeroCopyOperation(sharedBuffer);
		}

		// Benchmark
		const startTotal = performance.now();
		for (let i = 0; i < this._iterations; i++) {
			const start = performance.now();
			this._simulateZeroCopyOperation(sharedBuffer);
			const end = performance.now();
			times.push(end - start);
		}
		const totalTime = performance.now() - startTotal;

		return this._calculateResults(times, totalTime);
	}

	/**
	 * Simulates a copy-based operation (current pattern).
	 */
	private _simulateCopyOperation(data: Buffer): Buffer {
		// Simulate: JS passes Buffer to N-API
		// C++ copies into std::vector<uint8_t>
		const copy1 = Buffer.from(data);  // First copy (JS -> C++)

		// Simulate processing (XOR with 0xFF)
		for (let i = 0; i < copy1.length; i++) {
			copy1[i] = copy1[i] ^ 0xFF;
		}

		// C++ copies results back as new Buffer
		const copy2 = Buffer.from(copy1);  // Second copy (C++ -> JS)

		return copy2;
	}

	/**
	 * Simulates a zero-copy operation (proposed pattern).
	 */
	private _simulateZeroCopyOperation(sharedBuffer: SharedMemoryBuffer): Uint8Array {
		// Acquire lock
		sharedBuffer.acquireLock();

		try {
			// Direct access to shared memory (no copy)
			const view = sharedBuffer.dataView;

			// Simulate processing (XOR with 0xFF) in-place
			for (let i = 0; i < view.length; i++) {
				view[i] = view[i] ^ 0xFF;
			}

			// Return view (still zero-copy)
			return view;
		} finally {
			sharedBuffer.releaseLock();
		}
	}

	/**
	 * Calculates statistics from timing data.
	 */
	private _calculateResults(times: number[], totalTime: number): PatternResults {
		times.sort((a, b) => a - b);

		const sum = times.reduce((a, b) => a + b, 0);
		const avg = sum / times.length;
		const min = times[0];
		const max = times[times.length - 1];
		const median = times[Math.floor(times.length / 2)];

		// Calculate p99
		const p99Index = Math.floor(times.length * 0.99);
		const p99 = times[p99Index];

		return {
			totalTime,
			avgTime: avg,
			minTime: min,
			maxTime: max,
			medianTime: median,
			p99Time: p99,
			opsPerSecond: this._iterations / (totalTime / 1000)
		};
	}
}

/**
 * Results for a single pattern benchmark.
 */
interface PatternResults {
	totalTime: number;
	avgTime: number;
	minTime: number;
	maxTime: number;
	medianTime: number;
	p99Time: number;
	opsPerSecond: number;
}

/**
 * Complete benchmark results.
 */
interface BenchmarkResults {
	iterations: number;
	dataSize: number;
	copyPattern: PatternResults;
	zeroCopyPattern: PatternResults;
	speedup: number;
}

/**
 * Demonstrates the N-API pattern for receiving SharedArrayBuffer in C++.
 * This function shows the conceptual pattern with comments explaining the C++ side.
 */
function demonstrateNapiPattern(): void {
	console.log('\n=== N-API SharedArrayBuffer Pattern ===\n');

	// Create a SharedArrayBuffer
	const sab = new SharedArrayBuffer(1024);
	const view = new Uint8Array(sab);
	view.set([0x48, 0x89, 0x5C, 0x24, 0x08]); // Example x86 instructions

	console.log('JavaScript side:');
	console.log('  const sab = new SharedArrayBuffer(1024);');
	console.log('  nativeFunction(sab);  // Pass to native code\n');

	console.log('C++ side (hypothetical):');
	console.log(`
// N-API function receiving SharedArrayBuffer
Napi::Value ProcessSharedBuffer(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // Get the ArrayBuffer from argument - NO COPY!
    Napi::ArrayBuffer ab = info[0].As<Napi::ArrayBuffer>();

    // Direct pointer to shared memory
    void* data = ab.Data();           // Direct pointer, no copy!
    size_t len = ab.ByteLength();     // Size in bytes

    // Cast to typed pointer for processing
    uint8_t* bytes = static_cast<uint8_t*>(data);

    // Process directly in shared memory
    // (e.g., disassemble, lift to IR, emulate)
    for (size_t i = 0; i < len; i++) {
        bytes[i] = ProcessByte(bytes[i]);
    }

    // Return status - data is already in shared buffer
    return Napi::Number::New(env, len);
}

// Alternative: Using Napi::TypedArray
Napi::Value ProcessTypedArray(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // Receive as Uint8Array
    Napi::Uint8Array arr = info[0].As<Napi::Uint8Array>();

    // Direct data access
    uint8_t* data = arr.Data();
    size_t length = arr.ElementLength();

    // Process without copying...

    return env.Undefined();
}
`);

	console.log('Key advantages:');
	console.log('  1. No memcpy between JS and C++');
	console.log('  2. Zero allocation in hot path');
	console.log('  3. Shared memory visible to both sides');
	console.log('  4. Synchronization via Atomics API\n');
}

/**
 * Prints formatted benchmark results.
 */
function printResults(results: BenchmarkResults): void {
	console.log('\n=== Results ===\n');

	console.log('Copy Pattern (Current):');
	console.log(`  Total time: ${results.copyPattern.totalTime.toFixed(2)} ms`);
	console.log(`  Avg time: ${results.copyPattern.avgTime.toFixed(4)} μs`);
	console.log(`  Min time: ${results.copyPattern.minTime.toFixed(4)} μs`);
	console.log(`  Max time: ${results.copyPattern.maxTime.toFixed(4)} μs`);
	console.log(`  Median time: ${results.copyPattern.medianTime.toFixed(4)} μs`);
	console.log(`  P99 time: ${results.copyPattern.p99Time.toFixed(4)} μs`);
	console.log(`  Ops/sec: ${results.copyPattern.opsPerSecond.toFixed(0)}`);

	console.log('\nZero-Copy Pattern (Proposed):');
	console.log(`  Total time: ${results.zeroCopyPattern.totalTime.toFixed(2)} ms`);
	console.log(`  Avg time: ${results.zeroCopyPattern.avgTime.toFixed(4)} μs`);
	console.log(`  Min time: ${results.zeroCopyPattern.minTime.toFixed(4)} μs`);
	console.log(`  Max time: ${results.zeroCopyPattern.maxTime.toFixed(4)} μs`);
	console.log(`  Median time: ${results.zeroCopyPattern.medianTime.toFixed(4)} μs`);
	console.log(`  P99 time: ${results.zeroCopyPattern.p99Time.toFixed(4)} μs`);
	console.log(`  Ops/sec: ${results.zeroCopyPattern.opsPerSecond.toFixed(0)}`);

	console.log('\n=== Speedup ===');
	console.log(`  Overall: ${results.speedup.toFixed(2)}x faster`);
	console.log(`  Latency reduction: ${(results.copyPattern.avgTime - results.zeroCopyPattern.avgTime).toFixed(4)} μs per operation`);

	// Projected emulation speedup
	console.log('\n=== Projected Emulation Impact ===');
	const currentIps = 50000; // 50K instructions/sec (current with copy overhead)
	const projectedIps = currentIps * results.speedup;
	console.log(`  Current: ${currentIps.toLocaleString()} instr/sec`);
	console.log(`  Projected: ${projectedIps.toLocaleString()} instr/sec`);
	console.log(`  Target: 10,000,000 instr/sec`);
	console.log(`  Gap to target: ${(projectedIps >= 10000000 ? 'MET' : `${(10000000 / projectedIps).toFixed(1)}x more needed`)}`);
}

/**
 * Main entry point for the PoC demonstration.
 */
async function main(): Promise<void> {
	console.log('╔════════════════════════════════════════════════════════════╗');
	console.log('║     HexCore Zero-Copy IPC Proof of Concept                 ║');
	console.log('║     SharedArrayBuffer feasibility study for v4.0.0         ║');
	console.log('╚════════════════════════════════════════════════════════════╝');

	// Demonstrate the N-API pattern
	demonstrateNapiPattern();

	// Run benchmark with different data sizes
	const scenarios = [
		{ iterations: 100000, dataSize: 16, name: 'Small (hook data)' },
		{ iterations: 50000, dataSize: 1024, name: 'Medium (block)' },
		{ iterations: 10000, dataSize: 65536, name: 'Large (page)' }
	];

	for (const scenario of scenarios) {
		console.log(`\n${'='.repeat(60)}`);
		console.log(`Scenario: ${scenario.name}`);
		console.log(`${'='.repeat(60)}`);

		const benchmark = new ZeroCopyBenchmark(scenario.iterations, scenario.dataSize);
		const results = benchmark.run();
		printResults(results);
	}

	// Demonstrate SharedMemoryBuffer usage
	console.log('\n\n=== SharedMemoryBuffer Usage Demo ===\n');

	const buffer = new SharedMemoryBuffer(256);
	console.log(`Created SharedMemoryBuffer: ${buffer.totalSize} bytes total`);
	console.log(`  Header: ${HEADER_OFFSETS.DATA_START} bytes`);
	console.log(`  Payload: ${buffer.payloadSize} bytes`);

	// Write some data
	const testData = new TextEncoder().encode('Hello, Zero-Copy IPC!');
	buffer.writeData(testData);
	console.log(`\nWrote ${testData.length} bytes: "${new TextDecoder().decode(testData)}"`);

	// Read it back
	const readBack = buffer.readData(testData.length);
	console.log(`Read back: "${new TextDecoder().decode(readBack)}"`);

	// Demonstrate lock/unlock
	console.log('\nLock demonstration:');
	const acquired = buffer.acquireLock(100);
	console.log(`  Lock acquired: ${acquired}`);
	if (acquired) {
		buffer.releaseLock();
		console.log('  Lock released');
	}

	console.log('\n\n=== PoC Complete ===');
	console.log('This demonstrates the feasibility of zero-copy IPC for HexCore v4.0.0');
	console.log('Next steps: Implement actual N-API bindings in hexcore-unicorn');
}

// Run main if executed directly
if (require.main === module) {
	main().catch(console.error);
}

// Export classes for use as module
export { SharedMemoryBuffer, ZeroCopyBenchmark, demonstrateNapiPattern, main };
export { HEADER_OFFSETS, STATUS_CODES };

// Copyright (c) HikariSystem. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.
#ifndef UNICORN_WRAPPER_H
#define UNICORN_WRAPPER_H

#include <napi.h>
#include <unicorn/unicorn.h>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <memory>
#include <vector>
#include <mutex>
#include <atomic>
#include <condition_variable>

// Forward declarations
struct HookData;
struct HookSabData; // v4.0.0 — SAB zero-copy IPC (Issue #31)
class UnicornContext;

/**
 * UnicornWrapper - N-API wrapper for Unicorn Engine
 *
 * HikariSystem HexCore - Unicorn Emulator Bindings
 * Provides CPU emulation capabilities with hook support
 */
class UnicornWrapper : public Napi::ObjectWrap<UnicornWrapper> {
public:
	static Napi::Object Init(Napi::Env env, Napi::Object exports);
	static Napi::FunctionReference constructor;

	UnicornWrapper(const Napi::CallbackInfo& info);
	~UnicornWrapper();

	// Get the engine handle (for internal use)
	uc_engine* GetEngine() const { return engine_; }
	bool IsClosed() const { return closed_; }

	// InvalidMemHookCB needs access to autoMapCount_ (BUG-UNI-006)
	friend bool InvalidMemHookCB(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
	// CodeHookCB needs access to codeHookSeq_ (BUG-UNI-007)
	friend void CodeHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	// v4.0.0 — CodeHookSabCB needs access to codeHookSeq_ for the SAB ring path (Issue #31)
	friend void CodeHookSabCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);

private:
	uc_engine* engine_;
	uc_arch arch_;
	uc_mode mode_;
	bool closed_;
	std::atomic<bool> emulating_;
	std::mutex hookMutex_;

	// Map of active hooks: hook handle -> HookData
	std::unordered_map<uc_hook, std::unique_ptr<HookData>> hooks_;
	uc_hook nextHookId_;

	// v4.0.0 — Map of SAB-backed hooks: hook handle -> HookSabData (Issue #31)
	// Lives in parallel with hooks_; HookDel and CleanupHooks check both maps.
	std::unordered_map<uc_hook, std::unique_ptr<HookSabData>> sabHooks_;

	// Native Breakpoints
	std::unordered_set<uint64_t> breakpoints_;
	uc_hook breakpointHookHandle_ = 0;
	bool hasBreakpointHook_ = false;

	// Auto-map limit for InvalidMemHookCB (BUG-UNI-006)
	static constexpr uint32_t MAX_AUTO_MAPS = 1000;
	std::atomic<uint32_t> autoMapCount_{0};

	// BUG-UNI-007: global sequence counter for CodeHookCB.
	// Incremented atomically for every CODE hook invocation so JS can detect
	// dropped or reordered deliveries caused by NonBlockingCall fire-and-forget.
	std::atomic<uint64_t> codeHookSeq_{0};

	// Shared Memory References (Keep buffers alive)
	std::map<uint64_t, Napi::ObjectReference> mappedBuffers_;

	// ============== Emulation Control ==============

	/**
	 * Start emulation
	 * @param begin - Start address
	 * @param until - End address (0 to run until error/hook stop)
	 * @param timeout - Timeout in microseconds (0 for no timeout)
	 * @param count - Number of instructions to execute (0 for unlimited)
	 */
	Napi::Value EmuStart(const Napi::CallbackInfo& info);

	/**
	 * Start emulation asynchronously
	 * Returns a Promise that resolves when emulation completes
	 */
	Napi::Value EmuStartAsync(const Napi::CallbackInfo& info);

	/**
	 * Stop emulation (can be called from hooks)
	 */
	Napi::Value EmuStop(const Napi::CallbackInfo& info);

	// ============== Memory Operations ==============

	/**
	 * Map a memory region
	 * @param address - Start address (must be aligned to 4KB)
	 * @param size - Size in bytes (must be multiple of 4KB)
	 * @param perms - Memory permissions (PROT.READ | PROT.WRITE | PROT.EXEC)
	 */
	Napi::Value MemMap(const Napi::CallbackInfo& info);

	/**
	 * Map a memory region with existing data
	 * @param address - Start address
	 * @param data - Buffer containing initial data
	 * @param perms - Memory permissions
	 */
	Napi::Value MemMapPtr(const Napi::CallbackInfo& info);

	/**
	 * Unmap a memory region
	 */
	Napi::Value MemUnmap(const Napi::CallbackInfo& info);

	/**
	 * Change memory permissions
	 */
	Napi::Value MemProtect(const Napi::CallbackInfo& info);

	/**
	 * Read memory
	 * @param address - Address to read from
	 * @param size - Number of bytes to read
	 * @returns Buffer containing the data
	 */
	Napi::Value MemRead(const Napi::CallbackInfo& info);

	/**
	 * Write memory
	 * @param address - Address to write to
	 * @param data - Buffer containing data to write
	 */
	Napi::Value MemWrite(const Napi::CallbackInfo& info);

	/**
	 * Get list of mapped memory regions
	 * @returns Array of {begin, end, perms} objects
	 */
	Napi::Value MemRegions(const Napi::CallbackInfo& info);

	// ============== Register Operations ==============

	/**
	 * Read a register value
	 * @param regId - Register ID (architecture-specific)
	 * @returns BigInt for 64-bit values, Number for smaller
	 */
	Napi::Value RegRead(const Napi::CallbackInfo& info);

	/**
	 * Write a register value
	 * @param regId - Register ID
	 * @param value - Value to write (BigInt or Number)
	 */
	Napi::Value RegWrite(const Napi::CallbackInfo& info);

	/**
	 * Read multiple registers at once
	 * @param regIds - Array of register IDs
	 * @returns Array of values
	 */
	Napi::Value RegReadBatch(const Napi::CallbackInfo& info);

	/**
	 * Write multiple registers at once
	 * @param regIds - Array of register IDs
	 * @param values - Array of values
	 */
	Napi::Value RegWriteBatch(const Napi::CallbackInfo& info);

	// ============== Hook Operations ==============

	/**
	 * Add a hook
	 * @param type - Hook type (HOOK.CODE, HOOK.MEM_READ, etc.)
	 * @param callback - JavaScript function to call
	 * @param begin - Start address (optional, default 1)
	 * @param end - End address (optional, default 0 = all addresses)
	 * @param extra - Extra argument for instruction hooks (optional)
	 * @returns Hook handle (number)
	 */
	Napi::Value HookAdd(const Napi::CallbackInfo& info);

	/**
	 * v4.0.0 — Add a SAB-backed CODE hook (Issue #31).
	 *
	 * Zero-copy alternative to HookAdd for high-frequency CODE hooks. Writes
	 * each hook event into a SharedArrayBuffer ring buffer instead of marshalling
	 * via TSFN. Watched addresses (breakpoints, API stubs) still route through
	 * the legacy callback to preserve emuStop() semantics.
	 *
	 * @param info[0] hookType (HOOK.CODE only in v4.0.0)
	 * @param info[1] sabRef    SharedArrayBuffer >= 64 + slotSize*slotCount bytes
	 * @param info[2] slotSize  bytes per slot (32 for CODE)
	 * @param info[3] slotCount power of two (4096 recommended)
	 * @param info[4] watchAddresses bigint[] — addresses that should fire via TSFN
	 * @param info[5] legacyCallback Function | null — only invoked for watched hits
	 * @param info[6] begin     start address (optional, default 1)
	 * @param info[7] end       end address (optional, default 0 = all addresses)
	 * @returns hook handle (number)
	 */
	Napi::Value HookAddSAB(const Napi::CallbackInfo& info);

	/**
	 * Remove a hook
	 * @param hookHandle - Handle returned by hookAdd
	 */
	Napi::Value HookDel(const Napi::CallbackInfo& info);

	// ============== Native Breakpoints ==============

	/**
	 * Add a native breakpoint
	 * @param address - Address to break at
	 */
	Napi::Value BreakpointAdd(const Napi::CallbackInfo& info);

	/**
	 * Remove a native breakpoint
	 * @param address - Address to remove
	 */
	Napi::Value BreakpointDel(const Napi::CallbackInfo& info);

	// ============== Context Operations ==============

	/**
	 * Save the current CPU context
	 * @returns UnicornContext object
	 */
	Napi::Value ContextSave(const Napi::CallbackInfo& info);

	/**
	 * Restore a previously saved context
	 * @param context - UnicornContext object
	 */
	Napi::Value ContextRestore(const Napi::CallbackInfo& info);

	// ============== Snapshot Operations ==============

	/**
	 * Save full emulation state (Context + Memory)
	 * @return { context: Buffer, memory: [ { address, size, perms, data } ] }
	 */
	Napi::Value StateSave(const Napi::CallbackInfo& info);

	/**
	 * Restore full emulation state
	 * @param state - The object returned by StateSave
	 */
	Napi::Value StateRestore(const Napi::CallbackInfo& info);

	// ============== Query & Control ==============

	/**
	 * Query engine information
	 * @param queryType - QUERY.MODE, QUERY.PAGE_SIZE, QUERY.ARCH
	 * @returns Query result
	 */
	Napi::Value Query(const Napi::CallbackInfo& info);

	/**
	 * Set engine option
	 * @param optType - Option type
	 * @param value - Option value
	 */
	Napi::Value CtlWrite(const Napi::CallbackInfo& info);

	/**
	 * Get engine option
	 * @param optType - Option type
	 * @returns Option value
	 */
	Napi::Value CtlRead(const Napi::CallbackInfo& info);

	/**
	 * Close the engine and free resources
	 */
	Napi::Value Close(const Napi::CallbackInfo& info);

	// ============== Property Getters ==============

	Napi::Value GetArch(const Napi::CallbackInfo& info);
	Napi::Value GetMode(const Napi::CallbackInfo& info);
	Napi::Value GetHandle(const Napi::CallbackInfo& info);
	Napi::Value GetPageSize(const Napi::CallbackInfo& info);

	// ============== Internal Helpers ==============

	void ThrowUnicornError(Napi::Env env, uc_err err, const char* context = nullptr);
	void CleanupHooks();

	// Determine register size based on architecture and register ID
	size_t GetRegisterSize(int regId);

	// Check if register is 64-bit
	bool Is64BitRegister(int regId);

public:
	// Helper for checking breakpoints from static callback
	bool IsBreakpointHit(uint64_t address) {
		std::lock_guard<std::mutex> lock(hookMutex_);
		return breakpoints_.count(address) > 0;
	}
};

/**
 * UnicornContext - Wrapper for saved CPU context
 */
class UnicornContext : public Napi::ObjectWrap<UnicornContext> {
public:
	static Napi::Object Init(Napi::Env env, Napi::Object exports);
	static Napi::FunctionReference constructor;

	UnicornContext(const Napi::CallbackInfo& info);
	~UnicornContext();

	uc_context* GetContext() const { return context_; }
	void SetContext(uc_engine* engine, uc_context* ctx) {
		engine_ = engine;
		context_ = ctx;
	}

private:
	uc_context* context_;
	uc_engine* engine_; // Keep reference for proper cleanup

	Napi::Value Free(const Napi::CallbackInfo& info);
	Napi::Value GetSize(const Napi::CallbackInfo& info);
};

// ============== Hook Data Structures ==============

/**
 * Data passed to hook callbacks
 * Uses ThreadSafeFunction for safe JS callback invocation
 */
struct HookData {
	Napi::ThreadSafeFunction tsfn;
	uc_hook handle;
	int type;
	UnicornWrapper* wrapper;
	bool active;

	HookData() : handle(0), type(0), wrapper(nullptr), active(true) {}
	~HookData() {
		if (tsfn) {
			tsfn.Release();
		}
	}
};

// Data structures for passing to JavaScript callbacks
struct CodeHookCallData {
	uint64_t address;
	uint32_t size;
	// BUG-UNI-007: sequence number for out-of-order detection by JS consumers.
	// NonBlockingCall is fire-and-forget; under a busy event loop callbacks can
	// arrive out of order or be dropped.  JS can compare consecutive seqNums to
	// detect gaps / reordering.
	uint64_t sequenceNumber;
};

struct BlockHookCallData {
	uint64_t address;
	uint32_t size;
};

struct MemHookCallData {
	int type;
	uint64_t address;
	int size;
	int64_t value;
};

struct InterruptHookCallData {
	uint32_t intno;
	// Synchronization: the native hook blocks until JS finishes the syscall handler
	std::atomic<bool> done{false};
	std::mutex mtx;
	std::condition_variable cv;
};

struct InsnHookCallData {
	uint64_t address;
	uint32_t size;
};

struct InvalidMemHookCallData {
	int type;
	uint64_t address;
	int size;
	int64_t value;
	// result is set by the C++ auto-map logic (true if mapped successfully)
	bool result{false};
};

// ============== v4.0.0 — SAB Zero-Copy IPC (Issue #31) ==============

/**
 * 64-byte cache-line aligned ring buffer header.
 *
 * MUST be byte-for-byte identical to the TypeScript layout in
 * extensions/hexcore-common/src/sharedRingBuffer.ts. Any change here MUST
 * be mirrored in the TS class. The static_asserts in unicorn_wrapper.cpp
 * catch ABI mismatches at compile time.
 */
struct alignas(64) RingHeader {
	uint32_t magic;                       // offset 0  — 0x48524E47 ("HRNG")
	uint32_t version;                     // offset 4  — 1
	uint32_t slotSize;                    // offset 8  — bytes per slot
	uint32_t slotCount;                   // offset 12 — must be power of two
	std::atomic<uint32_t> head;           // offset 16 — producer cursor
	uint32_t _pad0;                       // offset 20
	std::atomic<uint32_t> tail;           // offset 24 — consumer cursor
	uint32_t _pad1;                       // offset 28
	std::atomic<uint32_t> droppedCount;   // offset 32 — producer increments on overflow
	uint32_t producerSeqHi;               // offset 36 — reserved for 64-bit seq assembly
	uint32_t _reserved[6];                // offsets 40..63
};

/**
 * 32-byte ring slot for CODE hook events.
 * MUST match the JS-side reader in unicornWrapper.ts drain callback.
 */
struct alignas(8) CodeHookSabSlot {
	uint64_t sequenceNumber;  // offset 0  — monotonic per hook fire
	uint64_t address;         // offset 8  — instruction address
	uint32_t size;            // offset 16 — instruction size
	uint32_t flags;           // offset 20 — reserved (bit 0 = also-watched)
	uint64_t timestamp;       // offset 24 — reserved (rdtsc), zero in v4.0.0
};

/**
 * Per-hook context for SAB-backed CODE hooks.
 *
 * One instance per active hookAddSAB registration. The `sabRef` ObjectReference
 * pins the SharedArrayBuffer so V8 cannot free it while the hook is live.
 * The `header` and `payload` pointers are raw pointers into the SAB — they are
 * valid for the lifetime of the pinned reference.
 */
struct HookSabData {
	Napi::ObjectReference sabRef;            // pin the SAB (prevents GC)
	RingHeader* header;                      // pointer into SAB at offset 0
	uint8_t* payload;                        // pointer into SAB at offset 64
	uint32_t slotMask;                       // slotCount - 1 for fast modulo
	uint32_t slotStride;                     // runtime slot stride (bytes) — may exceed sizeof(CodeHookSabSlot) for cache-line padding
	std::unordered_set<uint64_t> watchSet;   // addresses routed via legacyTsfn
	Napi::ThreadSafeFunction legacyTsfn;     // only used for watched hits, may be empty
	uc_hook handle;
	int type;
	UnicornWrapper* wrapper;
	bool active;

	HookSabData()
		: header(nullptr), payload(nullptr), slotMask(0), slotStride(0),
		  handle(0), type(0), wrapper(nullptr), active(true) {}
	~HookSabData() {
		if (legacyTsfn) {
			legacyTsfn.Release();
		}
	}
};

// ============== Hook Callback Functions ==============

void CodeHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
void BlockHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
void MemHookCB(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
void InterruptHookCB(uc_engine* uc, uint32_t intno, void* user_data);
void InsnHookCB(uc_engine* uc, void* user_data);
bool InvalidMemHookCB(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
// v4.0.0 — SAB-backed CODE hook (Issue #31)
void CodeHookSabCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
void BreakpointHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);

// ============== Utility Functions ==============

Napi::Object CreateErrorObject(Napi::Env env, uc_err err);
const char* GetErrorMessage(uc_err err);

#endif // UNICORN_WRAPPER_H


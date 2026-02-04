/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
#ifndef UNICORN_WRAPPER_H
#define UNICORN_WRAPPER_H

#include <napi.h>
#include <unicorn/unicorn.h>
#include <unordered_map>
#include <memory>
#include <vector>
#include <mutex>
#include <atomic>

// Forward declarations
struct HookData;
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
	 * Remove a hook
	 * @param hookHandle - Handle returned by hookAdd
	 */
	Napi::Value HookDel(const Napi::CallbackInfo& info);

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
	void SetContext(uc_context* ctx) { context_ = ctx; }

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
};

// ============== Hook Callback Functions ==============

void CodeHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
void BlockHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
void MemHookCB(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
void InterruptHookCB(uc_engine* uc, uint32_t intno, void* user_data);
void InsnHookCB(uc_engine* uc, void* user_data);
bool InvalidMemHookCB(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

// ============== Utility Functions ==============

Napi::Object CreateErrorObject(Napi::Env env, uc_err err);
const char* GetErrorMessage(uc_err err);

#endif // UNICORN_WRAPPER_H


// Copyright (c) HikariSystem. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.
#include "unicorn_wrapper.h"
#include "emu_async_worker.h"
#include <unicorn/x86.h>
#include <unicorn/arm64.h>
#include <unicorn/arm.h>
#include <cstring>
#include <sstream>

// v4.0.0 — SAB Zero-Copy IPC ABI guarantees (Issue #31).
// These static_asserts catch any compiler that produces a layout incompatible
// with the JavaScript Int32Array reader in extensions/hexcore-common/src/sharedRingBuffer.ts.
static_assert(sizeof(RingHeader) == 64, "RingHeader must be exactly 64 bytes for cache-line alignment");
static_assert(alignof(RingHeader) == 64, "RingHeader must be 64-byte aligned");
static_assert(sizeof(CodeHookSabSlot) == 32, "CodeHookSabSlot must be exactly 32 bytes (TS layout contract)");
static_assert(sizeof(std::atomic<uint32_t>) == sizeof(uint32_t), "std::atomic<uint32_t> must be ABI-compatible with uint32_t");
static_assert(alignof(std::atomic<uint32_t>) == 4, "std::atomic<uint32_t> must be 4-byte aligned");
static_assert(offsetof(RingHeader, magic) == 0, "RingHeader.magic offset");
static_assert(offsetof(RingHeader, version) == 4, "RingHeader.version offset");
static_assert(offsetof(RingHeader, slotSize) == 8, "RingHeader.slotSize offset");
static_assert(offsetof(RingHeader, slotCount) == 12, "RingHeader.slotCount offset");
static_assert(offsetof(RingHeader, head) == 16, "RingHeader.head offset");
static_assert(offsetof(RingHeader, tail) == 24, "RingHeader.tail offset");
static_assert(offsetof(RingHeader, droppedCount) == 32, "RingHeader.droppedCount offset");
static_assert(offsetof(CodeHookSabSlot, sequenceNumber) == 0, "Slot.seq offset");
static_assert(offsetof(CodeHookSabSlot, address) == 8, "Slot.address offset");
static_assert(offsetof(CodeHookSabSlot, size) == 16, "Slot.size offset");

// Magic constant — must match RING_BUFFER_MAGIC in sharedRingBuffer.ts
constexpr uint32_t SAB_RING_MAGIC = 0x48524E47;  // "HRNG"
constexpr uint32_t SAB_RING_VERSION = 1;

Napi::FunctionReference UnicornWrapper::constructor;
Napi::FunctionReference UnicornContext::constructor;

// ============== Error Handling ==============

const char* GetErrorMessage(uc_err err) {
	return uc_strerror(err);
}

Napi::Object CreateErrorObject(Napi::Env env, uc_err err) {
	Napi::Object error = Napi::Object::New(env);
	error.Set("code", Napi::Number::New(env, static_cast<int>(err)));
	error.Set("message", Napi::String::New(env, GetErrorMessage(err)));
	return error;
}

void UnicornWrapper::ThrowUnicornError(Napi::Env env, uc_err err, const char* context) {
	std::stringstream ss;
	if (context) {
		ss << context << ": ";
	}
	ss << GetErrorMessage(err) << " (code: " << static_cast<int>(err) << ")";
	Napi::Error::New(env, ss.str()).ThrowAsJavaScriptException();
}

namespace {
void DeactivateHook(HookData* data) {
	if (!data || !data->active) {
		return;
	}

	data->active = false;
	if (data->tsfn) {
		data->tsfn.Abort();
	}
}
}

// ============== UnicornWrapper Implementation ==============

Napi::Object UnicornWrapper::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "Unicorn", {
		// Emulation control
		InstanceMethod<&UnicornWrapper::EmuStart>("emuStart"),
		InstanceMethod<&UnicornWrapper::EmuStartAsync>("emuStartAsync"),
		InstanceMethod<&UnicornWrapper::EmuStop>("emuStop"),

		// Memory operations
		InstanceMethod<&UnicornWrapper::MemMap>("memMap"),
		InstanceMethod<&UnicornWrapper::MemMapPtr>("memMapPtr"),
		InstanceMethod<&UnicornWrapper::MemUnmap>("memUnmap"),
		InstanceMethod<&UnicornWrapper::MemProtect>("memProtect"),
		InstanceMethod<&UnicornWrapper::MemRead>("memRead"),
		InstanceMethod<&UnicornWrapper::MemWrite>("memWrite"),
		InstanceMethod<&UnicornWrapper::MemRegions>("memRegions"),

		// Register operations
		InstanceMethod<&UnicornWrapper::RegRead>("regRead"),
		InstanceMethod<&UnicornWrapper::RegWrite>("regWrite"),
		InstanceMethod<&UnicornWrapper::RegReadBatch>("regReadBatch"),
		InstanceMethod<&UnicornWrapper::RegWriteBatch>("regWriteBatch"),

		// Hook operations
		InstanceMethod<&UnicornWrapper::HookAdd>("hookAdd"),
		InstanceMethod<&UnicornWrapper::HookDel>("hookDel"),
		// v4.0.0 — SAB zero-copy CODE hook (Issue #31)
		InstanceMethod<&UnicornWrapper::HookAddSAB>("hookAddSAB"),

		// Native Breakpoints
		InstanceMethod<&UnicornWrapper::BreakpointAdd>("breakpointAdd"),
		InstanceMethod<&UnicornWrapper::BreakpointDel>("breakpointDel"),

		InstanceMethod<&UnicornWrapper::ContextSave>("contextSave"),
		InstanceMethod<&UnicornWrapper::ContextRestore>("contextRestore"),

		// Snapshot operations
		InstanceMethod<&UnicornWrapper::StateSave>("stateSave"),
		InstanceMethod<&UnicornWrapper::StateRestore>("stateRestore"),

		// Query & control
		InstanceMethod<&UnicornWrapper::Query>("query"),
		InstanceMethod<&UnicornWrapper::CtlWrite>("ctlWrite"),
		InstanceMethod<&UnicornWrapper::CtlRead>("ctlRead"),
		InstanceMethod<&UnicornWrapper::Close>("close"),

		// Properties
		InstanceAccessor<&UnicornWrapper::GetArch>("arch"),
		InstanceAccessor<&UnicornWrapper::GetMode>("mode"),
		InstanceAccessor<&UnicornWrapper::GetHandle>("handle"),
		InstanceAccessor<&UnicornWrapper::GetPageSize>("pageSize"),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("Unicorn", func);
	return exports;
}

UnicornWrapper::UnicornWrapper(const Napi::CallbackInfo& info)
	: Napi::ObjectWrap<UnicornWrapper>(info)
	, engine_(nullptr)
	, arch_(UC_ARCH_X86)
	, mode_(UC_MODE_64)
	, closed_(false)
	, emulating_(false)
	, nextHookId_(1)
	, hasBreakpointHook_(false) {


	Napi::Env env = info.Env();

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected 2 arguments: arch and mode").ThrowAsJavaScriptException();
		return;
	}

	if (!info[0].IsNumber() || !info[1].IsNumber()) {
		Napi::TypeError::New(env, "arch and mode must be numbers").ThrowAsJavaScriptException();
		return;
	}

	arch_ = static_cast<uc_arch>(info[0].As<Napi::Number>().Int32Value());
	mode_ = static_cast<uc_mode>(info[1].As<Napi::Number>().Int32Value());

	uc_err err = uc_open(arch_, mode_, &engine_);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to create Unicorn engine");
		return;
	}
}

UnicornWrapper::~UnicornWrapper() {
	if (!closed_ && engine_) {
		CleanupHooks();
		mappedBuffers_.clear();
		uc_close(engine_);
		engine_ = nullptr;
		closed_ = true;
	}
}

void UnicornWrapper::CleanupHooks() {
	std::lock_guard<std::mutex> lock(hookMutex_);
	for (auto& pair : hooks_) {
		if (pair.second) {
			DeactivateHook(pair.second.get());
			uc_hook_del(engine_, pair.first);
		}
	}
	hooks_.clear();

	// v4.0.0 — Drain SAB hooks alongside the legacy hooks (Issue #31).
	for (auto& pair : sabHooks_) {
		if (pair.second) {
			pair.second->active = false;
			if (pair.second->legacyTsfn) {
				pair.second->legacyTsfn.Abort();
			}
			uc_hook_del(engine_, pair.first);
		}
	}
	sabHooks_.clear();
}

// ============== Emulation Control ==============

Napi::Value UnicornWrapper::EmuStart(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected at least 2 arguments: begin and until").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t begin, until;
	uint64_t timeout = 0;
	size_t count = 0;

	// Parse begin address
	if (info[0].IsBigInt()) {
		bool lossless;
		begin = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[0].IsNumber()) {
		begin = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "begin must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Parse until address
	if (info[1].IsBigInt()) {
		bool lossless;
		until = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[1].IsNumber()) {
		until = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "until must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Parse optional timeout
	if (info.Length() > 2 && !info[2].IsUndefined()) {
		if (info[2].IsNumber()) {
			timeout = static_cast<uint64_t>(info[2].As<Napi::Number>().Int64Value());
		} else if (info[2].IsBigInt()) {
			bool lossless;
			timeout = info[2].As<Napi::BigInt>().Uint64Value(&lossless);
		}
	}

	// Parse optional count
	if (info.Length() > 3 && !info[3].IsUndefined()) {
		if (info[3].IsNumber()) {
			count = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
		}
	}

	// Reset auto-map counter at emulation start (BUG-UNI-006)
	autoMapCount_ = 0;

	uc_err err = uc_emu_start(engine_, begin, until, timeout, count);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Emulation failed");
		return env.Undefined();
	}

	return env.Undefined();
}

Napi::Value UnicornWrapper::EmuStartAsync(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected at least 2 arguments: begin and until").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t begin, until;
	uint64_t timeout = 0;
	size_t count = 0;

	// Parse begin address
	if (info[0].IsBigInt()) {
		bool lossless;
		begin = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[0].IsNumber()) {
		begin = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "begin must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Parse until address
	if (info[1].IsBigInt()) {
		bool lossless;
		until = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[1].IsNumber()) {
		until = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "until must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Check if already emulating
	if (emulating_) {
		Napi::Error::New(env, "Emulation is already running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Parse optional timeout
	if (info.Length() > 2 && !info[2].IsUndefined()) {
		if (info[2].IsNumber()) {
			timeout = static_cast<uint64_t>(info[2].As<Napi::Number>().Int64Value());
		} else if (info[2].IsBigInt()) {
			bool lossless;
			timeout = info[2].As<Napi::BigInt>().Uint64Value(&lossless);
		}
	}

	// Parse optional count
	if (info.Length() > 3 && !info[3].IsUndefined()) {
		if (info[3].IsNumber()) {
			count = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
		}
	}

	// Set emulating state
	emulating_ = true;

	// Reset auto-map counter at emulation start (BUG-UNI-006)
	autoMapCount_ = 0;

	Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);
	EmuAsyncWorker* worker = new EmuAsyncWorker(env, deferred, engine_, begin, until, timeout, count, &emulating_);
	worker->Queue();

	return deferred.Promise();
}

Napi::Value UnicornWrapper::EmuStop(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uc_err err = uc_emu_stop(engine_);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to stop emulation");
	}

	return env.Undefined();
}

// ============== Memory Operations ==============

Napi::Value UnicornWrapper::MemMap(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Note: memMap is safe during hook callbacks because the Unicorn engine
	// is paused. The emulating_ guard was removed to allow memory mapping
	// from hook contexts (e.g. page fault handlers).

	if (info.Length() < 3) {
		Napi::TypeError::New(env, "Expected 3 arguments: address, size, perms").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t address;
	if (info[0].IsBigInt()) {
		bool lossless;
		address = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[0].IsNumber()) {
		address = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "address must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t size;
	if (info[1].IsBigInt()) {
		bool lossless;
		size = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	} else {
		size = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	}
	uint32_t perms = info[2].As<Napi::Number>().Uint32Value();

	uc_err err = uc_mem_map(engine_, address, static_cast<size_t>(size), perms);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to map memory");
	}

	return env.Undefined();
}

Napi::Value UnicornWrapper::MemMapPtr(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (emulating_) {
		Napi::Error::New(env, "Cannot map memory while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 3) {
		Napi::TypeError::New(env, "Expected 3 arguments: address, data, perms").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t address;
	if (info[0].IsBigInt()) {
		bool lossless;
		address = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[0].IsNumber()) {
		address = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "address must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (!info[1].IsBuffer()) {
		Napi::TypeError::New(env, "data must be a Buffer").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	Napi::Buffer<uint8_t> buffer = info[1].As<Napi::Buffer<uint8_t>>();
	uint32_t perms = info[2].As<Napi::Number>().Uint32Value();

	// Map memory with pointer to existing data
	uc_err err = uc_mem_map_ptr(engine_, address, buffer.Length(), perms, buffer.Data());
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to map memory with pointer");
	}

	// Keep reference to buffer prevents GC while mapped
	Napi::Object bufferObj = info[1].As<Napi::Object>();
	mappedBuffers_[address] = Napi::Persistent(bufferObj);

	return env.Undefined();
}

Napi::Value UnicornWrapper::MemUnmap(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (emulating_) {
		Napi::Error::New(env, "Cannot unmap memory while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected 2 arguments: address, size").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t address;
	if (info[0].IsBigInt()) {
		bool lossless;
		address = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[0].IsNumber()) {
		address = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "address must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t size;
	if (info[1].IsBigInt()) {
		bool lossless;
		size = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	} else {
		size = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	}

	uc_err err = uc_mem_unmap(engine_, address, static_cast<size_t>(size));
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to unmap memory");
	}

	// Remove reference if it exists
	mappedBuffers_.erase(address);

	return env.Undefined();
}

Napi::Value UnicornWrapper::MemProtect(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (emulating_) {
		Napi::Error::New(env, "Cannot protect memory while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 3) {
		Napi::TypeError::New(env, "Expected 3 arguments: address, size, perms").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t address;
	if (info[0].IsBigInt()) {
		bool lossless;
		address = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[0].IsNumber()) {
		address = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "address must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t size;
	if (info[1].IsBigInt()) {
		bool lossless;
		size = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	} else {
		size = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	}
	uint32_t perms = info[2].As<Napi::Number>().Uint32Value();

	uc_err err = uc_mem_protect(engine_, address, static_cast<size_t>(size), perms);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to change memory protection");
	}

	return env.Undefined();
}

Napi::Value UnicornWrapper::MemRead(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected 2 arguments: address, size").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t address;
	if (info[0].IsBigInt()) {
		bool lossless;
		address = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[0].IsNumber()) {
		address = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "address must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t sizeVal;
	if (info[1].IsBigInt()) {
		bool lossless;
		sizeVal = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	} else {
		sizeVal = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	}
	size_t size = static_cast<size_t>(sizeVal);

	Napi::Buffer<uint8_t> buffer = Napi::Buffer<uint8_t>::New(env, size);

	uc_err err = uc_mem_read(engine_, address, buffer.Data(), size);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to read memory");
		return env.Undefined();
	}

	return buffer;
}

Napi::Value UnicornWrapper::MemWrite(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Note: memWrite is safe during hook callbacks because the Unicorn engine
	// is paused (BlockingCall). The emulating_ guard was removed to allow
	// syscall handlers to write memory (e.g. write() syscall buffer reads).

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected 2 arguments: address, data").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t address;
	if (info[0].IsBigInt()) {
		bool lossless;
		address = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[0].IsNumber()) {
		address = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "address must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (!info[1].IsBuffer()) {
		Napi::TypeError::New(env, "data must be a Buffer").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	Napi::Buffer<uint8_t> buffer = info[1].As<Napi::Buffer<uint8_t>>();

	uc_err err = uc_mem_write(engine_, address, buffer.Data(), buffer.Length());
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to write memory");
	}

	return env.Undefined();
}

Napi::Value UnicornWrapper::MemRegions(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uc_mem_region* regions = nullptr;
	uint32_t count = 0;

	uc_err err = uc_mem_regions(engine_, &regions, &count);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to get memory regions");
		return env.Undefined();
	}

	Napi::Array result = Napi::Array::New(env, count);

	for (uint32_t i = 0; i < count; i++) {
		Napi::Object region = Napi::Object::New(env);
		region.Set("begin", Napi::BigInt::New(env, regions[i].begin));
		region.Set("end", Napi::BigInt::New(env, regions[i].end));
		region.Set("perms", Napi::Number::New(env, regions[i].perms));
		result.Set(i, region);
	}

	uc_free(regions);

	return result;
}

// ============== Register Operations ==============

// ---- Per-architecture register size lookup (BUG-UNI-002) ----

static size_t GetX86RegisterSize(int regId) {
	switch (regId) {
		// 1-byte registers
		case UC_X86_REG_AL: case UC_X86_REG_AH:
		case UC_X86_REG_BL: case UC_X86_REG_BH:
		case UC_X86_REG_CL: case UC_X86_REG_CH:
		case UC_X86_REG_DL: case UC_X86_REG_DH:
		case UC_X86_REG_SPL: case UC_X86_REG_BPL:
		case UC_X86_REG_SIL: case UC_X86_REG_DIL:
		case UC_X86_REG_R8B: case UC_X86_REG_R9B:
		case UC_X86_REG_R10B: case UC_X86_REG_R11B:
		case UC_X86_REG_R12B: case UC_X86_REG_R13B:
		case UC_X86_REG_R14B: case UC_X86_REG_R15B:
			return 1;

		// 2-byte registers
		case UC_X86_REG_AX: case UC_X86_REG_BX:
		case UC_X86_REG_CX: case UC_X86_REG_DX:
		case UC_X86_REG_SI: case UC_X86_REG_DI:
		case UC_X86_REG_BP: case UC_X86_REG_SP:
		case UC_X86_REG_IP:
		case UC_X86_REG_R8W: case UC_X86_REG_R9W:
		case UC_X86_REG_R10W: case UC_X86_REG_R11W:
		case UC_X86_REG_R12W: case UC_X86_REG_R13W:
		case UC_X86_REG_R14W: case UC_X86_REG_R15W:
		case UC_X86_REG_CS: case UC_X86_REG_DS:
		case UC_X86_REG_ES: case UC_X86_REG_FS:
		case UC_X86_REG_GS: case UC_X86_REG_SS:
		case UC_X86_REG_FLAGS:
		case UC_X86_REG_FPCW: case UC_X86_REG_FPSW:
		case UC_X86_REG_FPTAG:
			return 2;

		// 4-byte registers
		case UC_X86_REG_EAX: case UC_X86_REG_EBX:
		case UC_X86_REG_ECX: case UC_X86_REG_EDX:
		case UC_X86_REG_ESI: case UC_X86_REG_EDI:
		case UC_X86_REG_EBP: case UC_X86_REG_ESP:
		case UC_X86_REG_EIP:
		case UC_X86_REG_R8D: case UC_X86_REG_R9D:
		case UC_X86_REG_R10D: case UC_X86_REG_R11D:
		case UC_X86_REG_R12D: case UC_X86_REG_R13D:
		case UC_X86_REG_R14D: case UC_X86_REG_R15D:
		case UC_X86_REG_EFLAGS:
		case UC_X86_REG_MXCSR:
			return 4;

		// 8-byte registers (GPR 64-bit, MMX, segment bases)
		case UC_X86_REG_RAX: case UC_X86_REG_RBX:
		case UC_X86_REG_RCX: case UC_X86_REG_RDX:
		case UC_X86_REG_RSI: case UC_X86_REG_RDI:
		case UC_X86_REG_RBP: case UC_X86_REG_RSP:
		case UC_X86_REG_RIP:
		case UC_X86_REG_R8: case UC_X86_REG_R9:
		case UC_X86_REG_R10: case UC_X86_REG_R11:
		case UC_X86_REG_R12: case UC_X86_REG_R13:
		case UC_X86_REG_R14: case UC_X86_REG_R15:
		case UC_X86_REG_RFLAGS:
		case UC_X86_REG_MM0: case UC_X86_REG_MM1:
		case UC_X86_REG_MM2: case UC_X86_REG_MM3:
		case UC_X86_REG_MM4: case UC_X86_REG_MM5:
		case UC_X86_REG_MM6: case UC_X86_REG_MM7:
		case UC_X86_REG_FS_BASE: case UC_X86_REG_GS_BASE:
		case UC_X86_REG_K0: case UC_X86_REG_K1:
		case UC_X86_REG_K2: case UC_X86_REG_K3:
		case UC_X86_REG_K4: case UC_X86_REG_K5:
		case UC_X86_REG_K6: case UC_X86_REG_K7:
			return 8;

		// 10-byte registers (x87 FPU)
		case UC_X86_REG_FP0: case UC_X86_REG_FP1:
		case UC_X86_REG_FP2: case UC_X86_REG_FP3:
		case UC_X86_REG_FP4: case UC_X86_REG_FP5:
		case UC_X86_REG_FP6: case UC_X86_REG_FP7:
		case UC_X86_REG_ST0: case UC_X86_REG_ST1:
		case UC_X86_REG_ST2: case UC_X86_REG_ST3:
		case UC_X86_REG_ST4: case UC_X86_REG_ST5:
		case UC_X86_REG_ST6: case UC_X86_REG_ST7:
			return 10;

		// 16-byte registers (XMM / SSE)
		case UC_X86_REG_XMM0: case UC_X86_REG_XMM1:
		case UC_X86_REG_XMM2: case UC_X86_REG_XMM3:
		case UC_X86_REG_XMM4: case UC_X86_REG_XMM5:
		case UC_X86_REG_XMM6: case UC_X86_REG_XMM7:
		case UC_X86_REG_XMM8: case UC_X86_REG_XMM9:
		case UC_X86_REG_XMM10: case UC_X86_REG_XMM11:
		case UC_X86_REG_XMM12: case UC_X86_REG_XMM13:
		case UC_X86_REG_XMM14: case UC_X86_REG_XMM15:
		case UC_X86_REG_XMM16: case UC_X86_REG_XMM17:
		case UC_X86_REG_XMM18: case UC_X86_REG_XMM19:
		case UC_X86_REG_XMM20: case UC_X86_REG_XMM21:
		case UC_X86_REG_XMM22: case UC_X86_REG_XMM23:
		case UC_X86_REG_XMM24: case UC_X86_REG_XMM25:
		case UC_X86_REG_XMM26: case UC_X86_REG_XMM27:
		case UC_X86_REG_XMM28: case UC_X86_REG_XMM29:
		case UC_X86_REG_XMM30: case UC_X86_REG_XMM31:
			return 16;

		// 32-byte registers (YMM / AVX)
		case UC_X86_REG_YMM0: case UC_X86_REG_YMM1:
		case UC_X86_REG_YMM2: case UC_X86_REG_YMM3:
		case UC_X86_REG_YMM4: case UC_X86_REG_YMM5:
		case UC_X86_REG_YMM6: case UC_X86_REG_YMM7:
		case UC_X86_REG_YMM8: case UC_X86_REG_YMM9:
		case UC_X86_REG_YMM10: case UC_X86_REG_YMM11:
		case UC_X86_REG_YMM12: case UC_X86_REG_YMM13:
		case UC_X86_REG_YMM14: case UC_X86_REG_YMM15:
		case UC_X86_REG_YMM16: case UC_X86_REG_YMM17:
		case UC_X86_REG_YMM18: case UC_X86_REG_YMM19:
		case UC_X86_REG_YMM20: case UC_X86_REG_YMM21:
		case UC_X86_REG_YMM22: case UC_X86_REG_YMM23:
		case UC_X86_REG_YMM24: case UC_X86_REG_YMM25:
		case UC_X86_REG_YMM26: case UC_X86_REG_YMM27:
		case UC_X86_REG_YMM28: case UC_X86_REG_YMM29:
		case UC_X86_REG_YMM30: case UC_X86_REG_YMM31:
			return 32;

		// 64-byte registers (ZMM / AVX-512)
		case UC_X86_REG_ZMM0: case UC_X86_REG_ZMM1:
		case UC_X86_REG_ZMM2: case UC_X86_REG_ZMM3:
		case UC_X86_REG_ZMM4: case UC_X86_REG_ZMM5:
		case UC_X86_REG_ZMM6: case UC_X86_REG_ZMM7:
		case UC_X86_REG_ZMM8: case UC_X86_REG_ZMM9:
		case UC_X86_REG_ZMM10: case UC_X86_REG_ZMM11:
		case UC_X86_REG_ZMM12: case UC_X86_REG_ZMM13:
		case UC_X86_REG_ZMM14: case UC_X86_REG_ZMM15:
		case UC_X86_REG_ZMM16: case UC_X86_REG_ZMM17:
		case UC_X86_REG_ZMM18: case UC_X86_REG_ZMM19:
		case UC_X86_REG_ZMM20: case UC_X86_REG_ZMM21:
		case UC_X86_REG_ZMM22: case UC_X86_REG_ZMM23:
		case UC_X86_REG_ZMM24: case UC_X86_REG_ZMM25:
		case UC_X86_REG_ZMM26: case UC_X86_REG_ZMM27:
		case UC_X86_REG_ZMM28: case UC_X86_REG_ZMM29:
		case UC_X86_REG_ZMM30: case UC_X86_REG_ZMM31:
			return 64;

		// Descriptor table registers (GDTR/IDTR are 10 bytes: 2-byte limit + 8-byte base in 64-bit)
		case UC_X86_REG_GDTR: case UC_X86_REG_IDTR:
			return 10;
		// Segment selector registers (LDTR, TR are 2-byte selectors)
		case UC_X86_REG_LDTR: case UC_X86_REG_TR:
			return 2;

		// Control registers (always 64-bit in long mode, 32-bit in protected)
		case UC_X86_REG_CR0: case UC_X86_REG_CR1:
		case UC_X86_REG_CR2: case UC_X86_REG_CR3:
		case UC_X86_REG_CR4: case UC_X86_REG_CR8:
		case UC_X86_REG_DR0: case UC_X86_REG_DR1:
		case UC_X86_REG_DR2: case UC_X86_REG_DR3:
		case UC_X86_REG_DR4: case UC_X86_REG_DR5:
		case UC_X86_REG_DR6: case UC_X86_REG_DR7:
			return 8;

		default:
			return 0; // unknown — caller uses arch/mode fallback
	}
}

static size_t GetArm64RegisterSize(int regId) {
	switch (regId) {
		// 1-byte NEON sub-registers
		case UC_ARM64_REG_B0: case UC_ARM64_REG_B1:
		case UC_ARM64_REG_B2: case UC_ARM64_REG_B3:
		case UC_ARM64_REG_B4: case UC_ARM64_REG_B5:
		case UC_ARM64_REG_B6: case UC_ARM64_REG_B7:
		case UC_ARM64_REG_B8: case UC_ARM64_REG_B9:
		case UC_ARM64_REG_B10: case UC_ARM64_REG_B11:
		case UC_ARM64_REG_B12: case UC_ARM64_REG_B13:
		case UC_ARM64_REG_B14: case UC_ARM64_REG_B15:
		case UC_ARM64_REG_B16: case UC_ARM64_REG_B17:
		case UC_ARM64_REG_B18: case UC_ARM64_REG_B19:
		case UC_ARM64_REG_B20: case UC_ARM64_REG_B21:
		case UC_ARM64_REG_B22: case UC_ARM64_REG_B23:
		case UC_ARM64_REG_B24: case UC_ARM64_REG_B25:
		case UC_ARM64_REG_B26: case UC_ARM64_REG_B27:
		case UC_ARM64_REG_B28: case UC_ARM64_REG_B29:
		case UC_ARM64_REG_B30: case UC_ARM64_REG_B31:
			return 1;

		// 2-byte NEON sub-registers
		case UC_ARM64_REG_H0: case UC_ARM64_REG_H1:
		case UC_ARM64_REG_H2: case UC_ARM64_REG_H3:
		case UC_ARM64_REG_H4: case UC_ARM64_REG_H5:
		case UC_ARM64_REG_H6: case UC_ARM64_REG_H7:
		case UC_ARM64_REG_H8: case UC_ARM64_REG_H9:
		case UC_ARM64_REG_H10: case UC_ARM64_REG_H11:
		case UC_ARM64_REG_H12: case UC_ARM64_REG_H13:
		case UC_ARM64_REG_H14: case UC_ARM64_REG_H15:
		case UC_ARM64_REG_H16: case UC_ARM64_REG_H17:
		case UC_ARM64_REG_H18: case UC_ARM64_REG_H19:
		case UC_ARM64_REG_H20: case UC_ARM64_REG_H21:
		case UC_ARM64_REG_H22: case UC_ARM64_REG_H23:
		case UC_ARM64_REG_H24: case UC_ARM64_REG_H25:
		case UC_ARM64_REG_H26: case UC_ARM64_REG_H27:
		case UC_ARM64_REG_H28: case UC_ARM64_REG_H29:
		case UC_ARM64_REG_H30: case UC_ARM64_REG_H31:
			return 2;

		// 4-byte registers (W0-W30, S0-S31, WZR, WSP)
		case UC_ARM64_REG_W0: case UC_ARM64_REG_W1:
		case UC_ARM64_REG_W2: case UC_ARM64_REG_W3:
		case UC_ARM64_REG_W4: case UC_ARM64_REG_W5:
		case UC_ARM64_REG_W6: case UC_ARM64_REG_W7:
		case UC_ARM64_REG_W8: case UC_ARM64_REG_W9:
		case UC_ARM64_REG_W10: case UC_ARM64_REG_W11:
		case UC_ARM64_REG_W12: case UC_ARM64_REG_W13:
		case UC_ARM64_REG_W14: case UC_ARM64_REG_W15:
		case UC_ARM64_REG_W16: case UC_ARM64_REG_W17:
		case UC_ARM64_REG_W18: case UC_ARM64_REG_W19:
		case UC_ARM64_REG_W20: case UC_ARM64_REG_W21:
		case UC_ARM64_REG_W22: case UC_ARM64_REG_W23:
		case UC_ARM64_REG_W24: case UC_ARM64_REG_W25:
		case UC_ARM64_REG_W26: case UC_ARM64_REG_W27:
		case UC_ARM64_REG_W28: case UC_ARM64_REG_W29:
		case UC_ARM64_REG_W30:
		case UC_ARM64_REG_WZR: case UC_ARM64_REG_WSP:
		case UC_ARM64_REG_S0: case UC_ARM64_REG_S1:
		case UC_ARM64_REG_S2: case UC_ARM64_REG_S3:
		case UC_ARM64_REG_S4: case UC_ARM64_REG_S5:
		case UC_ARM64_REG_S6: case UC_ARM64_REG_S7:
		case UC_ARM64_REG_S8: case UC_ARM64_REG_S9:
		case UC_ARM64_REG_S10: case UC_ARM64_REG_S11:
		case UC_ARM64_REG_S12: case UC_ARM64_REG_S13:
		case UC_ARM64_REG_S14: case UC_ARM64_REG_S15:
		case UC_ARM64_REG_S16: case UC_ARM64_REG_S17:
		case UC_ARM64_REG_S18: case UC_ARM64_REG_S19:
		case UC_ARM64_REG_S20: case UC_ARM64_REG_S21:
		case UC_ARM64_REG_S22: case UC_ARM64_REG_S23:
		case UC_ARM64_REG_S24: case UC_ARM64_REG_S25:
		case UC_ARM64_REG_S26: case UC_ARM64_REG_S27:
		case UC_ARM64_REG_S28: case UC_ARM64_REG_S29:
		case UC_ARM64_REG_S30: case UC_ARM64_REG_S31:
		case UC_ARM64_REG_PSTATE:
			return 4;

		// 8-byte registers (X0-X28, X29/FP, X30/LR, SP, XZR, PC, D0-D31)
		case UC_ARM64_REG_X0: case UC_ARM64_REG_X1:
		case UC_ARM64_REG_X2: case UC_ARM64_REG_X3:
		case UC_ARM64_REG_X4: case UC_ARM64_REG_X5:
		case UC_ARM64_REG_X6: case UC_ARM64_REG_X7:
		case UC_ARM64_REG_X8: case UC_ARM64_REG_X9:
		case UC_ARM64_REG_X10: case UC_ARM64_REG_X11:
		case UC_ARM64_REG_X12: case UC_ARM64_REG_X13:
		case UC_ARM64_REG_X14: case UC_ARM64_REG_X15:
		case UC_ARM64_REG_X16: case UC_ARM64_REG_X17:
		case UC_ARM64_REG_X18: case UC_ARM64_REG_X19:
		case UC_ARM64_REG_X20: case UC_ARM64_REG_X21:
		case UC_ARM64_REG_X22: case UC_ARM64_REG_X23:
		case UC_ARM64_REG_X24: case UC_ARM64_REG_X25:
		case UC_ARM64_REG_X26: case UC_ARM64_REG_X27:
		case UC_ARM64_REG_X28:
		case UC_ARM64_REG_X29: case UC_ARM64_REG_X30:
		case UC_ARM64_REG_SP: case UC_ARM64_REG_XZR:
		case UC_ARM64_REG_PC:
		case UC_ARM64_REG_D0: case UC_ARM64_REG_D1:
		case UC_ARM64_REG_D2: case UC_ARM64_REG_D3:
		case UC_ARM64_REG_D4: case UC_ARM64_REG_D5:
		case UC_ARM64_REG_D6: case UC_ARM64_REG_D7:
		case UC_ARM64_REG_D8: case UC_ARM64_REG_D9:
		case UC_ARM64_REG_D10: case UC_ARM64_REG_D11:
		case UC_ARM64_REG_D12: case UC_ARM64_REG_D13:
		case UC_ARM64_REG_D14: case UC_ARM64_REG_D15:
		case UC_ARM64_REG_D16: case UC_ARM64_REG_D17:
		case UC_ARM64_REG_D18: case UC_ARM64_REG_D19:
		case UC_ARM64_REG_D20: case UC_ARM64_REG_D21:
		case UC_ARM64_REG_D22: case UC_ARM64_REG_D23:
		case UC_ARM64_REG_D24: case UC_ARM64_REG_D25:
		case UC_ARM64_REG_D26: case UC_ARM64_REG_D27:
		case UC_ARM64_REG_D28: case UC_ARM64_REG_D29:
		case UC_ARM64_REG_D30: case UC_ARM64_REG_D31:
		case UC_ARM64_REG_NZCV:
			return 8;

		// 16-byte registers (Q0-Q31 NEON/SIMD, V0-V31)
		case UC_ARM64_REG_Q0: case UC_ARM64_REG_Q1:
		case UC_ARM64_REG_Q2: case UC_ARM64_REG_Q3:
		case UC_ARM64_REG_Q4: case UC_ARM64_REG_Q5:
		case UC_ARM64_REG_Q6: case UC_ARM64_REG_Q7:
		case UC_ARM64_REG_Q8: case UC_ARM64_REG_Q9:
		case UC_ARM64_REG_Q10: case UC_ARM64_REG_Q11:
		case UC_ARM64_REG_Q12: case UC_ARM64_REG_Q13:
		case UC_ARM64_REG_Q14: case UC_ARM64_REG_Q15:
		case UC_ARM64_REG_Q16: case UC_ARM64_REG_Q17:
		case UC_ARM64_REG_Q18: case UC_ARM64_REG_Q19:
		case UC_ARM64_REG_Q20: case UC_ARM64_REG_Q21:
		case UC_ARM64_REG_Q22: case UC_ARM64_REG_Q23:
		case UC_ARM64_REG_Q24: case UC_ARM64_REG_Q25:
		case UC_ARM64_REG_Q26: case UC_ARM64_REG_Q27:
		case UC_ARM64_REG_Q28: case UC_ARM64_REG_Q29:
		case UC_ARM64_REG_Q30: case UC_ARM64_REG_Q31:
		case UC_ARM64_REG_V0: case UC_ARM64_REG_V1:
		case UC_ARM64_REG_V2: case UC_ARM64_REG_V3:
		case UC_ARM64_REG_V4: case UC_ARM64_REG_V5:
		case UC_ARM64_REG_V6: case UC_ARM64_REG_V7:
		case UC_ARM64_REG_V8: case UC_ARM64_REG_V9:
		case UC_ARM64_REG_V10: case UC_ARM64_REG_V11:
		case UC_ARM64_REG_V12: case UC_ARM64_REG_V13:
		case UC_ARM64_REG_V14: case UC_ARM64_REG_V15:
		case UC_ARM64_REG_V16: case UC_ARM64_REG_V17:
		case UC_ARM64_REG_V18: case UC_ARM64_REG_V19:
		case UC_ARM64_REG_V20: case UC_ARM64_REG_V21:
		case UC_ARM64_REG_V22: case UC_ARM64_REG_V23:
		case UC_ARM64_REG_V24: case UC_ARM64_REG_V25:
		case UC_ARM64_REG_V26: case UC_ARM64_REG_V27:
		case UC_ARM64_REG_V28: case UC_ARM64_REG_V29:
		case UC_ARM64_REG_V30: case UC_ARM64_REG_V31:
			return 16;

		default:
			return 0; // unknown — caller uses arch/mode fallback
	}
}

static size_t GetArmRegisterSize(int regId) {
	switch (regId) {
		// 4-byte GPRs and status registers
		case UC_ARM_REG_R0: case UC_ARM_REG_R1:
		case UC_ARM_REG_R2: case UC_ARM_REG_R3:
		case UC_ARM_REG_R4: case UC_ARM_REG_R5:
		case UC_ARM_REG_R6: case UC_ARM_REG_R7:
		case UC_ARM_REG_R8: case UC_ARM_REG_R9:
		case UC_ARM_REG_R10: case UC_ARM_REG_R11:
		case UC_ARM_REG_R12:
		case UC_ARM_REG_SP: case UC_ARM_REG_LR:
		case UC_ARM_REG_PC:
		case UC_ARM_REG_CPSR: case UC_ARM_REG_SPSR:
		case UC_ARM_REG_APSR: case UC_ARM_REG_APSR_NZCV:
		case UC_ARM_REG_FPEXC: case UC_ARM_REG_FPSCR:
			return 4;

		// 4-byte VFP single-precision
		case UC_ARM_REG_S0: case UC_ARM_REG_S1:
		case UC_ARM_REG_S2: case UC_ARM_REG_S3:
		case UC_ARM_REG_S4: case UC_ARM_REG_S5:
		case UC_ARM_REG_S6: case UC_ARM_REG_S7:
		case UC_ARM_REG_S8: case UC_ARM_REG_S9:
		case UC_ARM_REG_S10: case UC_ARM_REG_S11:
		case UC_ARM_REG_S12: case UC_ARM_REG_S13:
		case UC_ARM_REG_S14: case UC_ARM_REG_S15:
		case UC_ARM_REG_S16: case UC_ARM_REG_S17:
		case UC_ARM_REG_S18: case UC_ARM_REG_S19:
		case UC_ARM_REG_S20: case UC_ARM_REG_S21:
		case UC_ARM_REG_S22: case UC_ARM_REG_S23:
		case UC_ARM_REG_S24: case UC_ARM_REG_S25:
		case UC_ARM_REG_S26: case UC_ARM_REG_S27:
		case UC_ARM_REG_S28: case UC_ARM_REG_S29:
		case UC_ARM_REG_S30: case UC_ARM_REG_S31:
			return 4;

		// 8-byte VFP double-precision
		case UC_ARM_REG_D0: case UC_ARM_REG_D1:
		case UC_ARM_REG_D2: case UC_ARM_REG_D3:
		case UC_ARM_REG_D4: case UC_ARM_REG_D5:
		case UC_ARM_REG_D6: case UC_ARM_REG_D7:
		case UC_ARM_REG_D8: case UC_ARM_REG_D9:
		case UC_ARM_REG_D10: case UC_ARM_REG_D11:
		case UC_ARM_REG_D12: case UC_ARM_REG_D13:
		case UC_ARM_REG_D14: case UC_ARM_REG_D15:
		case UC_ARM_REG_D16: case UC_ARM_REG_D17:
		case UC_ARM_REG_D18: case UC_ARM_REG_D19:
		case UC_ARM_REG_D20: case UC_ARM_REG_D21:
		case UC_ARM_REG_D22: case UC_ARM_REG_D23:
		case UC_ARM_REG_D24: case UC_ARM_REG_D25:
		case UC_ARM_REG_D26: case UC_ARM_REG_D27:
		case UC_ARM_REG_D28: case UC_ARM_REG_D29:
		case UC_ARM_REG_D30: case UC_ARM_REG_D31:
			return 8;

		// 16-byte NEON quad registers
		case UC_ARM_REG_Q0: case UC_ARM_REG_Q1:
		case UC_ARM_REG_Q2: case UC_ARM_REG_Q3:
		case UC_ARM_REG_Q4: case UC_ARM_REG_Q5:
		case UC_ARM_REG_Q6: case UC_ARM_REG_Q7:
		case UC_ARM_REG_Q8: case UC_ARM_REG_Q9:
		case UC_ARM_REG_Q10: case UC_ARM_REG_Q11:
		case UC_ARM_REG_Q12: case UC_ARM_REG_Q13:
		case UC_ARM_REG_Q14: case UC_ARM_REG_Q15:
			return 16;

		default:
			return 0; // unknown — caller uses arch/mode fallback
	}
}

size_t UnicornWrapper::GetRegisterSize(int regId) {
	// Try per-register lookup first, then fall back to arch/mode default
	size_t size = 0;

	switch (arch_) {
		case UC_ARCH_X86:
			size = GetX86RegisterSize(regId);
			if (size > 0) return size;
			// Fallback for unknown x86 registers
			if (mode_ == UC_MODE_64) return 8;
			if (mode_ == UC_MODE_32) return 4;
			return 2;

		case UC_ARCH_ARM64:
			size = GetArm64RegisterSize(regId);
			if (size > 0) return size;
			return 8;

		case UC_ARCH_ARM:
			size = GetArmRegisterSize(regId);
			if (size > 0) return size;
			return 4;

		case UC_ARCH_MIPS:
			return (mode_ & UC_MODE_64) ? 8 : 4;
		case UC_ARCH_SPARC:
			return (mode_ & UC_MODE_64) ? 8 : 4;
		case UC_ARCH_PPC:
			return (mode_ & UC_MODE_64) ? 8 : 4;
		case UC_ARCH_RISCV:
			return (mode_ & UC_MODE_RISCV64) ? 8 : 4;
		default:
			return 8;
	}
}

bool UnicornWrapper::Is64BitRegister(int regId) {
	return GetRegisterSize(regId) == 8;
}

Napi::Value UnicornWrapper::RegRead(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 1) {
		Napi::TypeError::New(env, "Expected 1 argument: regId").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	int regId = info[0].As<Napi::Number>().Int32Value();
	size_t regSize = GetRegisterSize(regId);

	if (regSize > 8) {
		// Wide registers (XMM=16, YMM=32, ZMM=64, x87 FP=10, etc.)
		// Return as Buffer so JS gets the full data
		uint8_t buf[64] = {0}; // max ZMM size
		uc_err err = uc_reg_read(engine_, regId, buf);
		if (err != UC_ERR_OK) {
			ThrowUnicornError(env, err, "Failed to read register");
			return env.Undefined();
		}
		return Napi::Buffer<uint8_t>::Copy(env, buf, regSize);
	} else if (regSize == 8) {
		uint64_t value = 0;
		uc_err err = uc_reg_read(engine_, regId, &value);
		if (err != UC_ERR_OK) {
			ThrowUnicornError(env, err, "Failed to read register");
			return env.Undefined();
		}
		return Napi::BigInt::New(env, value);
	} else {
		// 1, 2, or 4 byte registers
		uint64_t value = 0;
		uc_err err = uc_reg_read(engine_, regId, &value);
		if (err != UC_ERR_OK) {
			ThrowUnicornError(env, err, "Failed to read register");
			return env.Undefined();
		}
		// Mask to actual register width to avoid returning stale upper bits
		if (regSize == 1) value &= 0xFF;
		else if (regSize == 2) value &= 0xFFFF;
		else if (regSize == 4) value &= 0xFFFFFFFF;
		return Napi::Number::New(env, static_cast<double>(value));
	}
}

Napi::Value UnicornWrapper::RegWrite(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Note: regWrite is safe during hook callbacks because the Unicorn engine
	// is paused (BlockingCall). The emulating_ guard was removed to allow
	// syscall handlers to write return values (e.g. X0) directly.

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected 2 arguments: regId, value").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	int regId = info[0].As<Napi::Number>().Int32Value();
	size_t regSize = GetRegisterSize(regId);
	uc_err err;

	if (info[1].IsBuffer()) {
		// Buffer input — for wide registers (XMM, YMM, ZMM, x87, NEON Q, etc.)
		auto buf = info[1].As<Napi::Buffer<uint8_t>>();
		uint8_t tmp[64] = {0};
		size_t copyLen = std::min(buf.Length(), std::min(regSize, (size_t)64));
		std::memcpy(tmp, buf.Data(), copyLen);
		err = uc_reg_write(engine_, regId, tmp);
	} else if (info[1].IsBigInt()) {
		bool lossless;
		uint64_t value = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
		// FIX (HEXCORE_DEFEAT FAIL 4): Mask to actual register width so a
		// negative BigInt (e.g. -1n → 0xFFFFFFFFFFFFFFFF) doesn't bleed
		// stale upper bits into smaller registers.
		if (regSize == 1) value &= 0xFFULL;
		else if (regSize == 2) value &= 0xFFFFULL;
		else if (regSize == 4) value &= 0xFFFFFFFFULL;
		err = uc_reg_write(engine_, regId, &value);
	} else if (info[1].IsNumber()) {
		// FIX (HEXCORE_DEFEAT FAIL 4): JS Number can be a negative int32 (e.g.
		// `Date.now() & 0xFFFFFFFF` produces -1849236473 when the high bit is
		// set). Int64Value() returns the signed value, then static_cast to
		// uint64 sign-extends to 0xFFFFFFFFXXXXXXXX. For sub-64-bit registers
		// this writes garbage into the upper half. Mask to actual register
		// width here too.
		uint64_t value = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
		if (regSize == 1) value &= 0xFFULL;
		else if (regSize == 2) value &= 0xFFFFULL;
		else if (regSize == 4) value &= 0xFFFFFFFFULL;
		err = uc_reg_write(engine_, regId, &value);
	} else {
		Napi::TypeError::New(env, "value must be a Buffer, BigInt, or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to write register");
	}

	return env.Undefined();
}

Napi::Value UnicornWrapper::RegReadBatch(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 1 || !info[0].IsArray()) {
		Napi::TypeError::New(env, "Expected 1 argument: array of regIds").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	Napi::Array regIds = info[0].As<Napi::Array>();
	uint32_t count = regIds.Length();

	Napi::Array result = Napi::Array::New(env, count);

	for (uint32_t i = 0; i < count; i++) {
		int regId = regIds.Get(i).As<Napi::Number>().Int32Value();
		size_t regSize = GetRegisterSize(regId);

		if (regSize > 8) {
			uint8_t buf[64] = {0};
			uc_err err = uc_reg_read(engine_, regId, buf);
			if (err != UC_ERR_OK) {
				ThrowUnicornError(env, err, "Failed to read register in batch");
				return env.Undefined();
			}
			result.Set(i, Napi::Buffer<uint8_t>::Copy(env, buf, regSize));
		} else if (regSize == 8) {
			uint64_t value = 0;
			uc_err err = uc_reg_read(engine_, regId, &value);
			if (err != UC_ERR_OK) {
				ThrowUnicornError(env, err, "Failed to read register in batch");
				return env.Undefined();
			}
			result.Set(i, Napi::BigInt::New(env, value));
		} else {
			uint64_t value = 0;
			uc_err err = uc_reg_read(engine_, regId, &value);
			if (err != UC_ERR_OK) {
				ThrowUnicornError(env, err, "Failed to read register in batch");
				return env.Undefined();
			}
			if (regSize == 1) value &= 0xFF;
			else if (regSize == 2) value &= 0xFFFF;
			else if (regSize == 4) value &= 0xFFFFFFFF;
			result.Set(i, Napi::Number::New(env, static_cast<double>(value)));
		}
	}

	return result;
}

Napi::Value UnicornWrapper::RegWriteBatch(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Note: regWriteBatch is safe during hook callbacks (Unicorn paused via BlockingCall).

	if (info.Length() < 2 || !info[0].IsArray() || !info[1].IsArray()) {
		Napi::TypeError::New(env, "Expected 2 arguments: array of regIds, array of values").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	Napi::Array regIds = info[0].As<Napi::Array>();
	Napi::Array values = info[1].As<Napi::Array>();

	if (regIds.Length() != values.Length()) {
		Napi::TypeError::New(env, "regIds and values arrays must have the same length").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint32_t count = regIds.Length();

	for (uint32_t i = 0; i < count; i++) {
		int regId = regIds.Get(i).As<Napi::Number>().Int32Value();
		size_t regSize = GetRegisterSize(regId);
		Napi::Value val = values.Get(i);
		uc_err err;

		if (val.IsBuffer()) {
			auto buf = val.As<Napi::Buffer<uint8_t>>();
			uint8_t tmp[64] = {0};
			size_t copyLen = std::min(buf.Length(), std::min(regSize, (size_t)64));
			std::memcpy(tmp, buf.Data(), copyLen);
			err = uc_reg_write(engine_, regId, tmp);
		} else if (val.IsBigInt()) {
			bool lossless;
			uint64_t value = val.As<Napi::BigInt>().Uint64Value(&lossless);
			// FIX (HEXCORE_DEFEAT FAIL 4): mask to actual register width to
			// prevent sign-extended negative BigInts from leaking upper bits.
			if (regSize == 1) value &= 0xFFULL;
			else if (regSize == 2) value &= 0xFFFFULL;
			else if (regSize == 4) value &= 0xFFFFFFFFULL;
			err = uc_reg_write(engine_, regId, &value);
		} else if (val.IsNumber()) {
			// FIX (HEXCORE_DEFEAT FAIL 4): see RegWrite for the negative-int32
			// sign-extension case. Mask to the actual register width.
			uint64_t value = static_cast<uint64_t>(val.As<Napi::Number>().Int64Value());
			if (regSize == 1) value &= 0xFFULL;
			else if (regSize == 2) value &= 0xFFFFULL;
			else if (regSize == 4) value &= 0xFFFFFFFFULL;
			err = uc_reg_write(engine_, regId, &value);
		} else {
			Napi::TypeError::New(env, "All values must be Buffer, BigInt, or Number").ThrowAsJavaScriptException();
			return env.Undefined();
		}

		if (err != UC_ERR_OK) {
			ThrowUnicornError(env, err, "Failed to write register in batch");
			return env.Undefined();
		}
	}

	return env.Undefined();
}

// ============== Hook Operations ==============

// Hook callback implementations
// BUG-UNI-007: NonBlockingCall is intentionally used here for performance —
// switching to BlockingCall would stall the emulation thread on every instruction.
// Known limitation: under a saturated Node event loop, callbacks can be delivered
// out of order or dropped entirely.  JS consumers SHOULD check the sequenceNumber
// field on each callback to detect gaps (dropped hooks) or reordering.
void CodeHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	HookData* data = static_cast<HookData*>(user_data);
	if (!data || !data->active) return;

	auto callData = std::make_unique<CodeHookCallData>();
	callData->address = address;
	callData->size = size;
	// Stamp a monotonically increasing sequence number so JS can detect drops/reordering.
	callData->sequenceNumber = data->wrapper->codeHookSeq_.fetch_add(1, std::memory_order_relaxed);

	auto* raw = callData.release();
	napi_status status = data->tsfn.NonBlockingCall(raw, [](Napi::Env env, Napi::Function callback, CodeHookCallData* data) {
		callback.Call({
			Napi::BigInt::New(env, data->address),
			Napi::Number::New(env, data->size),
			Napi::BigInt::New(env, data->sequenceNumber)
		});
		delete data;
	});
	if (status != napi_ok) {
		delete raw;
	}
}

void BlockHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	HookData* data = static_cast<HookData*>(user_data);
	if (!data || !data->active) return;

	auto callData = std::make_unique<BlockHookCallData>();
	callData->address = address;
	callData->size = size;

	auto* raw = callData.release();
	napi_status status = data->tsfn.NonBlockingCall(raw, [](Napi::Env env, Napi::Function callback, BlockHookCallData* data) {
		callback.Call({
			Napi::BigInt::New(env, data->address),
			Napi::Number::New(env, data->size)
		});
		delete data;
	});
	if (status != napi_ok) {
		delete raw;
	}
}

void MemHookCB(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
	HookData* data = static_cast<HookData*>(user_data);
	if (!data || !data->active) return;

	auto callData = std::make_unique<MemHookCallData>();
	callData->type = static_cast<int>(type);
	callData->address = address;
	callData->size = size;
	callData->value = value;

	auto* raw = callData.release();
	napi_status status = data->tsfn.NonBlockingCall(raw, [](Napi::Env env, Napi::Function callback, MemHookCallData* data) {
		callback.Call({
			Napi::Number::New(env, data->type),
			Napi::BigInt::New(env, data->address),
			Napi::Number::New(env, data->size),
			Napi::BigInt::New(env, static_cast<uint64_t>(data->value))
		});
		delete data;
	});
	if (status != napi_ok) {
		delete raw;
	}
}

void InterruptHookCB(uc_engine* uc, uint32_t intno, void* user_data) {
	HookData* data = static_cast<HookData*>(user_data);
	if (!data || !data->active) return;

	// Allocate on stack — we block until JS finishes the syscall handler.
	InterruptHookCallData callData;
	callData.intno = intno;
	callData.done.store(false);

	// Use BlockingCall so the Unicorn thread waits for JS to handle the interrupt.
	// The JS callback dispatches the syscall and writes the return value via
	// uc_reg_write (cross-thread but safe because the Unicorn thread is blocked
	// and uc_reg_write only touches the CPU context buffer).
	data->tsfn.BlockingCall(&callData, [](Napi::Env env, Napi::Function callback, InterruptHookCallData* cd) {
		callback.Call({
			Napi::Number::New(env, cd->intno)
		});

		// Signal the native thread that we're done
		{
			std::lock_guard<std::mutex> lock(cd->mtx);
			cd->done.store(true);
		}
		cd->cv.notify_one();
	});

	// Wait for JS to finish handling the interrupt
	{
		std::unique_lock<std::mutex> lock(callData.mtx);
		callData.cv.wait(lock, [&callData] { return callData.done.load(); });
	}
}

void InsnHookCB(uc_engine* uc, void* user_data) {
	HookData* data = static_cast<HookData*>(user_data);
	if (!data || !data->active) return;

	data->tsfn.NonBlockingCall([](Napi::Env env, Napi::Function callback) {
		callback.Call({});
	});
}

bool InvalidMemHookCB(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
	HookData* data = static_cast<HookData*>(user_data);
	if (!data || !data->active) return false;

	// Auto-map on fault: perform uc_mem_map directly on the Unicorn thread.
	// This avoids cross-thread uc_mem_map calls which can corrupt Unicorn state
	// when uc_emu_start is running on a different thread (EmuAsyncWorker).

	// Reject NULL page and very high addresses
	if (address < 0x1000) return false;
	if (address > 0x00007FFFFFFFFFFF) return false;

	// Enforce auto-map limit to prevent address space exhaustion (BUG-UNI-006)
	if (data->wrapper && data->wrapper->autoMapCount_ >= UnicornWrapper::MAX_AUTO_MAPS) {
		return false; // Limit reached, let the fault propagate
	}

	// Query page size
	size_t pageSize = 0;
	uc_query(uc, UC_QUERY_PAGE_SIZE, &pageSize);
	if (pageSize == 0) pageSize = 0x1000;

	// Align to page boundary
	uint64_t alignedAddr = (address / pageSize) * pageSize;
	size_t neededSize = static_cast<size_t>(address - alignedAddr) + size;
	size_t alignedSize = ((neededSize + pageSize - 1) / pageSize) * pageSize;
	if (alignedSize == 0) alignedSize = pageSize;

	// Map with full permissions (RWX) — same as JS handlePageFault
	uc_err err = uc_mem_map(uc, alignedAddr, alignedSize, UC_PROT_ALL);
	if (err != UC_ERR_OK) {
		return false; // Let emulation crash
	}

	// Increment auto-map counter (BUG-UNI-006)
	if (data->wrapper) {
		data->wrapper->autoMapCount_++;
	}

	// Notify JS asynchronously for tracking (non-blocking, fire-and-forget)
	auto callData = std::make_unique<InvalidMemHookCallData>();
	callData->type = static_cast<int>(type);
	callData->address = address;
	callData->size = size;
	callData->value = value;
	callData->result = true; // Already handled

	auto* raw = callData.release();
	napi_status status = data->tsfn.NonBlockingCall(raw, [](Napi::Env env, Napi::Function callback, InvalidMemHookCallData* cd) {
		// Call JS callback for tracking/logging only — memory is already mapped
		callback.Call({
			Napi::Number::New(env, cd->type),
			Napi::BigInt::New(env, cd->address),
			Napi::Number::New(env, cd->size),
			Napi::BigInt::New(env, static_cast<uint64_t>(cd->value))
		});
		delete cd;
	});
	if (status != napi_ok) {
		delete raw;
	}

	return true; // Fault handled, Unicorn retries the access
}

// ============== v4.0.0 — SAB Zero-Copy CODE Hook (Issue #31) ==============

/**
 * Split-path CODE hook callback. Watched addresses (breakpoints, API stubs)
 * route through the legacy TSFN slow path so emuStop() semantics are preserved.
 * Everything else writes 32 bytes to the SAB ring buffer with zero allocations
 * and zero N-API transitions on the hot path.
 *
 * This callback runs on the Unicorn worker thread (EmuAsyncWorker::Execute).
 * The release barrier on h->head.store synchronizes-with the JS-side
 * Atomics.load on the same field via SharedArrayBuffer semantics.
 */
void CodeHookSabCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	(void)uc;
	auto* data = static_cast<HookSabData*>(user_data);
	if (!data || !data->active) return;

	const uint64_t seq = data->wrapper->codeHookSeq_.fetch_add(1, std::memory_order_relaxed);

	// ── Slow path: watched address → legacy TSFN ─────────────────────
	// Preserves emuStop() correctness for breakpoints and API interception.
	if (!data->watchSet.empty() && data->watchSet.count(address) > 0) {
		if (!data->legacyTsfn) {
			return; // no callback registered, watched addresses are silently dropped
		}
		auto callData = std::make_unique<CodeHookCallData>();
		callData->address = address;
		callData->size = size;
		callData->sequenceNumber = seq;
		auto* raw = callData.release();
		napi_status status = data->legacyTsfn.NonBlockingCall(raw,
			[](Napi::Env env, Napi::Function cb, CodeHookCallData* d) {
				cb.Call({
					Napi::BigInt::New(env, d->address),
					Napi::Number::New(env, d->size),
					Napi::BigInt::New(env, d->sequenceNumber)
				});
				delete d;
			});
		if (status != napi_ok) {
			delete raw;
		}
		return;
	}

	// ── Fast path: lock-free single-producer ring write ───────────────
	// Zero allocations, zero N-API calls. ~8 instructions on x86_64.
	RingHeader* h = data->header;
	const uint32_t head = h->head.load(std::memory_order_relaxed);
	const uint32_t next = (head + 1) & data->slotMask;
	const uint32_t tail = h->tail.load(std::memory_order_acquire);
	if (next == tail) {
		// Ring full: drop newest. JS detects gap via sequenceNumber.
		h->droppedCount.fetch_add(1, std::memory_order_relaxed);
		return;
	}
	// Use runtime slotStride (not compile-time sizeof) so callers that
	// pad slots for cache-line alignment (e.g. slotSize = 64) write at
	// the same stride the JS consumer reads from h->slotSize.
	auto* slot = reinterpret_cast<CodeHookSabSlot*>(
		data->payload + head * data->slotStride);
	slot->sequenceNumber = seq;
	slot->address = address;
	slot->size = size;
	slot->flags = 0;
	slot->timestamp = 0;
	// Release: publishes the slot write to the consumer.
	h->head.store(next, std::memory_order_release);
}

Napi::Value UnicornWrapper::HookAdd(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (emulating_) {
		Napi::Error::New(env, "Cannot add hooks while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected at least 2 arguments: type, callback").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	int hookType = info[0].As<Napi::Number>().Int32Value();

	if (!info[1].IsFunction()) {
		Napi::TypeError::New(env, "callback must be a function").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	Napi::Function callback = info[1].As<Napi::Function>();

	uint64_t begin = 1;
	uint64_t end = 0;
	int arg1 = 0;

	// Parse optional begin address
	if (info.Length() > 2 && !info[2].IsUndefined()) {
		if (info[2].IsBigInt()) {
			bool lossless;
			begin = info[2].As<Napi::BigInt>().Uint64Value(&lossless);
		} else if (info[2].IsNumber()) {
			begin = static_cast<uint64_t>(info[2].As<Napi::Number>().Int64Value());
		}
	}

	// Parse optional end address
	if (info.Length() > 3 && !info[3].IsUndefined()) {
		if (info[3].IsBigInt()) {
			bool lossless;
			end = info[3].As<Napi::BigInt>().Uint64Value(&lossless);
		} else if (info[3].IsNumber()) {
			end = static_cast<uint64_t>(info[3].As<Napi::Number>().Int64Value());
		}
	}

	// Parse optional extra argument (for instruction hooks)
	if (info.Length() > 4 && !info[4].IsUndefined()) {
		arg1 = info[4].As<Napi::Number>().Int32Value();
	}

	// Create hook data
	auto hookData = std::make_unique<HookData>();
	hookData->type = hookType;
	hookData->wrapper = this;
	hookData->active = true;

	// Create ThreadSafeFunction
	hookData->tsfn = Napi::ThreadSafeFunction::New(
		env,
		callback,
		"UnicornHook",
		0,
		1,
		[](Napi::Env) {} // Release callback
	);

	uc_hook handle;
	uc_err err;

	// Add hook based on type
	if (hookType == UC_HOOK_CODE || hookType == UC_HOOK_BLOCK) {
		err = uc_hook_add(engine_, &handle, hookType,
			(hookType == UC_HOOK_CODE) ? (void*)CodeHookCB : (void*)BlockHookCB,
			hookData.get(), begin, end);
	} else if (hookType == UC_HOOK_INTR) {
		err = uc_hook_add(engine_, &handle, hookType, (void*)InterruptHookCB,
			hookData.get(), begin, end);
	} else if (hookType >= UC_HOOK_MEM_READ_UNMAPPED && hookType <= UC_HOOK_MEM_PROT) {
		// Invalid memory access hooks
		err = uc_hook_add(engine_, &handle, hookType, (void*)InvalidMemHookCB,
			hookData.get(), begin, end);
	} else if (hookType >= UC_HOOK_MEM_READ && hookType <= UC_HOOK_MEM_FETCH) {
		// Valid memory access hooks
		err = uc_hook_add(engine_, &handle, hookType, (void*)MemHookCB,
			hookData.get(), begin, end);
	} else if (hookType == UC_HOOK_INSN) {
		// Instruction hooks with extra argument
		err = uc_hook_add(engine_, &handle, hookType, (void*)InsnHookCB,
			hookData.get(), begin, end, arg1);
	} else {
		// Generic hook
		err = uc_hook_add(engine_, &handle, hookType, (void*)CodeHookCB,
			hookData.get(), begin, end);
	}

	if (err != UC_ERR_OK) {
		DeactivateHook(hookData.get());
		ThrowUnicornError(env, err, "Failed to add hook");
		return env.Undefined();
	}

	hookData->handle = handle;

	// Store hook data
	{
		std::lock_guard<std::mutex> lock(hookMutex_);
		hooks_[handle] = std::move(hookData);
	}

	return Napi::Number::New(env, static_cast<double>(handle));
}

// ============== v4.0.0 — HookAddSAB (Issue #31) ==============

Napi::Value UnicornWrapper::HookAddSAB(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	if (emulating_) {
		Napi::Error::New(env, "Cannot add hooks while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Signature: hookAddSAB(type, sabRef, slotSize, slotCount, watchAddresses[], legacyCallback?, begin?, end?)
	if (info.Length() < 5) {
		Napi::TypeError::New(env,
			"hookAddSAB: expected (type, sabRef, slotSize, slotCount, watchAddresses[, legacyCallback, begin, end])"
		).ThrowAsJavaScriptException();
		return env.Undefined();
	}

	const int hookType = info[0].As<Napi::Number>().Int32Value();
	if (hookType != UC_HOOK_CODE) {
		Napi::TypeError::New(env, "hookAddSAB v4.0.0 only supports UC_HOOK_CODE").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Accept either a plain ArrayBuffer/SharedArrayBuffer (info[1].IsArrayBuffer())
	// or a TypedArray view over a SAB (info[1].IsTypedArray()). N-API's
	// IsArrayBuffer() returns false for SharedArrayBuffer because V8 distinguishes
	// the two at the JS type level even though they share C++ storage. The same
	// pattern is used in extensions/hexcore-capstone/src/capstone_wrapper.cpp:105.
	Napi::ArrayBuffer sab;
	Napi::Object pinObject;  // The object we keep persistent — must own the SAB lifetime.
	if (info[1].IsArrayBuffer()) {
		sab = info[1].As<Napi::ArrayBuffer>();
		pinObject = info[1].As<Napi::Object>();
	} else if (info[1].IsTypedArray()) {
		Napi::TypedArray ta = info[1].As<Napi::TypedArray>();
		sab = ta.ArrayBuffer();
		// Pin the TypedArray itself — it owns the underlying SAB reference.
		pinObject = info[1].As<Napi::Object>();
	} else {
		Napi::TypeError::New(env, "hookAddSAB: sabRef must be a SharedArrayBuffer or a TypedArray over one").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	if (sab.IsDetached()) {
		Napi::Error::New(env, "hookAddSAB: SharedArrayBuffer is detached").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	const uint32_t slotSize = info[2].As<Napi::Number>().Uint32Value();
	const uint32_t slotCount = info[3].As<Napi::Number>().Uint32Value();
	if (slotSize < sizeof(CodeHookSabSlot) || (slotSize & 7) != 0) {
		Napi::RangeError::New(env, "hookAddSAB: slotSize must be >= 32 and multiple of 8").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	if (slotCount == 0 || (slotCount & (slotCount - 1)) != 0) {
		Napi::RangeError::New(env, "hookAddSAB: slotCount must be a power of two").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	const size_t requiredBytes = sizeof(RingHeader) + static_cast<size_t>(slotSize) * slotCount;
	if (sab.ByteLength() < requiredBytes) {
		std::stringstream ss;
		ss << "hookAddSAB: SAB too small (" << sab.ByteLength() << " < " << requiredBytes << ")";
		Napi::RangeError::New(env, ss.str()).ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (!info[4].IsArray()) {
		Napi::TypeError::New(env, "hookAddSAB: watchAddresses must be an array").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	Napi::Array watchArr = info[4].As<Napi::Array>();

	const bool hasLegacyCb = info.Length() > 5 && info[5].IsFunction();

	uint64_t begin = 1;
	uint64_t end = 0;
	if (info.Length() > 6 && !info[6].IsUndefined()) {
		if (info[6].IsBigInt()) {
			bool lossless;
			begin = info[6].As<Napi::BigInt>().Uint64Value(&lossless);
		} else if (info[6].IsNumber()) {
			begin = static_cast<uint64_t>(info[6].As<Napi::Number>().Int64Value());
		}
	}
	if (info.Length() > 7 && !info[7].IsUndefined()) {
		if (info[7].IsBigInt()) {
			bool lossless;
			end = info[7].As<Napi::BigInt>().Uint64Value(&lossless);
		} else if (info[7].IsNumber()) {
			end = static_cast<uint64_t>(info[7].As<Napi::Number>().Int64Value());
		}
	}

	// Build the hook data
	auto sabData = std::make_unique<HookSabData>();
	sabData->type = hookType;
	sabData->wrapper = this;
	sabData->active = true;
	sabData->slotMask = slotCount - 1;
	sabData->slotStride = slotSize; // matches h->slotSize published to consumer

	// Pin the SAB (or the TypedArray that owns it) so V8 cannot collect it
	// while the hook is live.
	sabData->sabRef = Napi::Persistent(pinObject);

	// Direct pointer access into the SAB.
	uint8_t* base = static_cast<uint8_t*>(sab.Data());
	sabData->header = reinterpret_cast<RingHeader*>(base);
	sabData->payload = base + sizeof(RingHeader);

	// Initialize the header in place. Idempotent on reuse — head/tail/dropped reset.
	RingHeader* h = sabData->header;
	h->magic = SAB_RING_MAGIC;
	h->version = SAB_RING_VERSION;
	h->slotSize = slotSize;
	h->slotCount = slotCount;
	h->head.store(0, std::memory_order_relaxed);
	h->tail.store(0, std::memory_order_relaxed);
	h->droppedCount.store(0, std::memory_order_relaxed);
	h->producerSeqHi = 0;
	for (int i = 0; i < 6; i++) h->_reserved[i] = 0;
	h->_pad0 = 0;
	h->_pad1 = 0;

	// Populate the watch set from the JS array.
	const uint32_t watchLen = watchArr.Length();
	sabData->watchSet.reserve(watchLen);
	for (uint32_t i = 0; i < watchLen; i++) {
		Napi::Value v = watchArr[i];
		uint64_t addr = 0;
		if (v.IsBigInt()) {
			bool lossless;
			addr = v.As<Napi::BigInt>().Uint64Value(&lossless);
		} else if (v.IsNumber()) {
			addr = static_cast<uint64_t>(v.As<Napi::Number>().Int64Value());
		} else {
			Napi::TypeError::New(env, "hookAddSAB: watchAddresses entries must be bigint or number").ThrowAsJavaScriptException();
			return env.Undefined();
		}
		sabData->watchSet.insert(addr);
	}

	// Create TSFN only if a legacy callback was provided.
	if (hasLegacyCb) {
		Napi::Function callback = info[5].As<Napi::Function>();
		sabData->legacyTsfn = Napi::ThreadSafeFunction::New(
			env,
			callback,
			"UnicornHookSAB",
			0,
			1,
			[](Napi::Env) {} // Release callback
		);
	}

	// Register the hook with Unicorn.
	uc_hook handle;
	uc_err err = uc_hook_add(engine_, &handle, UC_HOOK_CODE,
		(void*)CodeHookSabCB, sabData.get(), begin, end);

	if (err != UC_ERR_OK) {
		if (sabData->legacyTsfn) {
			sabData->legacyTsfn.Abort();
		}
		ThrowUnicornError(env, err, "Failed to add SAB hook");
		return env.Undefined();
	}

	sabData->handle = handle;

	// Store in the SAB hooks map.
	{
		std::lock_guard<std::mutex> lock(hookMutex_);
		sabHooks_[handle] = std::move(sabData);
	}

	return Napi::Number::New(env, static_cast<double>(handle));
}

Napi::Value UnicornWrapper::HookDel(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (emulating_) {
		Napi::Error::New(env, "Cannot delete hooks while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 1) {
		Napi::TypeError::New(env, "Expected 1 argument: hookHandle").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uc_hook handle;
	if (info[0].IsBigInt()) {
		bool lossless;
		handle = static_cast<uc_hook>(info[0].As<Napi::BigInt>().Uint64Value(&lossless));
	} else {
		handle = static_cast<uc_hook>(info[0].As<Napi::Number>().Int64Value());
	}

	// Remove from Unicorn
	uc_err err = uc_hook_del(engine_, handle);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to delete hook");
		return env.Undefined();
	}

	// Remove from whichever map owns it (legacy or v4.0.0 SAB).
	{
		std::lock_guard<std::mutex> lock(hookMutex_);
		auto legacyIt = hooks_.find(handle);
		if (legacyIt != hooks_.end()) {
			DeactivateHook(legacyIt->second.get());
			hooks_.erase(legacyIt);
		} else {
			auto sabIt = sabHooks_.find(handle);
			if (sabIt != sabHooks_.end()) {
				sabIt->second->active = false;
				if (sabIt->second->legacyTsfn) {
					sabIt->second->legacyTsfn.Abort();
				}
				sabHooks_.erase(sabIt);
			}
		}
	}

	return env.Undefined();
}

// ============== Context Operations ==============

Napi::Value UnicornWrapper::ContextSave(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (emulating_) {
		Napi::Error::New(env, "Cannot save context while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uc_context* context = nullptr;
	uc_err err = uc_context_alloc(engine_, &context);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to allocate context");
		return env.Undefined();
	}

	err = uc_context_save(engine_, context);
	if (err != UC_ERR_OK) {
		uc_context_free(context);
		ThrowUnicornError(env, err, "Failed to save context");
		return env.Undefined();
	}

	// Create UnicornContext wrapper
	Napi::Object contextObj = UnicornContext::constructor.New({});
	UnicornContext* wrapper = Napi::ObjectWrap<UnicornContext>::Unwrap(contextObj);
	wrapper->SetContext(engine_, context);

	return contextObj;
}

Napi::Value UnicornWrapper::ContextRestore(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (emulating_) {
		Napi::Error::New(env, "Cannot restore context while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 1 || !info[0].IsObject()) {
		Napi::TypeError::New(env, "Expected 1 argument: UnicornContext").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	UnicornContext* contextWrapper = Napi::ObjectWrap<UnicornContext>::Unwrap(info[0].As<Napi::Object>());
	if (!contextWrapper || !contextWrapper->GetContext()) {
		Napi::Error::New(env, "Invalid context").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uc_err err = uc_context_restore(engine_, contextWrapper->GetContext());
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to restore context");
	}

	return env.Undefined();
}

// ============== Snapshot Operations ==============

Napi::Value UnicornWrapper::StateSave(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_ || emulating_) {
		Napi::Error::New(env, "Cannot save state: Engine closed or running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	Napi::Object state = Napi::Object::New(env);

	// 1. Save Registers/Context
	uc_context* ctx = nullptr;
	uc_context_alloc(engine_, &ctx);
	uc_context_save(engine_, ctx);

	// Create context buffer (serialize context)
	// Note: Unicorn doesn't have a direct "serialize context to buffer" API exposed easily
	// except via binding specific hacks or just saving individual registers.
	// Check if we can use uc_context_reg_read/write or loop.
	// Actually, for simplicity/portability, we might rely on the user leveraging `contextSave`.
	// BUT, a full snapshot usually implies serialization.
	// Since we are inside the binding, we can expose a "serialize" method or
	// just return the opaque Context object?
	// The request was for "Snapshotting". Returning a UnicornContext object (which wraps uc_context*)
	// is valid for runtime snapshotting. But if they want to save to disk...
	// Unicorn doesn't support context serialization natively easily (opaque struct).
	// Let's stick to returning a JS object with Memory Regions contents + we will try to safe 'Context'
	// as a JS structure of all registers? No, too many.
	//
	// Wait, we already have `UnicornContext` wrapper. Let's just create one and attach it.
	// Saving to disk might require extracting all regs, which is arch specific.
	// Let's assume Runtime Snapshot for now (Visualizing/Rewind in memory).

	Napi::Object contextObj = UnicornContext::constructor.New({});
	UnicornContext* wrapper = Napi::ObjectWrap<UnicornContext>::Unwrap(contextObj);
	wrapper->SetContext(engine_, ctx); // Takes ownership

	state.Set("context", contextObj);

	// 2. Save Memory
	uc_mem_region* regions = nullptr;
	uint32_t count = 0;
	if (uc_mem_regions(engine_, &regions, &count) == UC_ERR_OK) {
		Napi::Array memArray = Napi::Array::New(env, count);
		for (uint32_t i = 0; i < count; i++) {
			Napi::Object region = Napi::Object::New(env);
			region.Set("address", Napi::BigInt::New(env, regions[i].begin));
			uint64_t size = regions[i].end - regions[i].begin + 1;
			region.Set("size", Napi::Number::New(env, size));
			region.Set("perms", Napi::Number::New(env, regions[i].perms));

			// Read content
			Napi::Buffer<uint8_t> buffer = Napi::Buffer<uint8_t>::New(env, size);
			if (uc_mem_read(engine_, regions[i].begin, buffer.Data(), size) == UC_ERR_OK) {
				region.Set("data", buffer);
			} else {
				// uc_mem_read failed (e.g. MMIO or unreadable region).
				// Still attach the zeroed buffer so StateRestore can at least re-map the
				// region rather than skipping it silently (BUG-UNI-005).
				fprintf(stderr, "[hexcore-unicorn] StateSave: uc_mem_read failed for region 0x%llx+0x%llx — attaching zeroed buffer\n",
					(unsigned long long)regions[i].begin, (unsigned long long)size);
				region.Set("data", buffer);
				region.Set("error", Napi::String::New(env, "uc_mem_read failed: region data may be unreadable (MMIO or guard page)"));
			}

			memArray.Set(i, region);
		}
		uc_free(regions);
		state.Set("memory", memArray);
	}

	return state;
}

Napi::Value UnicornWrapper::StateRestore(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_ || emulating_) {
		Napi::Error::New(env, "Cannot restore state: Engine closed or running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 1 || !info[0].IsObject()) {
		Napi::TypeError::New(env, "Expected state object").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	Napi::Object state = info[0].As<Napi::Object>();

	// Reset auto-map counter (BUG-UNI-006)
	autoMapCount_ = 0;

	// 1. Restore Memory
	// Unmap all existing regions first to avoid stale data and mapping conflicts (BUG-UNI-004)
	{
		uc_mem_region *regions = nullptr;
		uint32_t regionCount = 0;
		if (uc_mem_regions(engine_, &regions, &regionCount) == UC_ERR_OK) {
			for (uint32_t i = 0; i < regionCount; i++) {
				uc_mem_unmap(engine_, regions[i].begin, regions[i].end - regions[i].begin + 1);
			}
			uc_free(regions);
		}
	}

	if (state.Has("memory")) {
		Napi::Array memArray = state.Get("memory").As<Napi::Array>();
		uint32_t count = memArray.Length();
		for (uint32_t i = 0; i < count; i++) {
			Napi::Value val = memArray.Get(i);
			if (val.IsObject()) {
				Napi::Object region = val.As<Napi::Object>();
				bool lossless;
				uint64_t address = region.Get("address").As<Napi::BigInt>().Uint64Value(&lossless);
				uint64_t sizeRaw;
				Napi::Value sizeVal = region.Get("size");
				if (sizeVal.IsBigInt()) {
					sizeRaw = sizeVal.As<Napi::BigInt>().Uint64Value(&lossless);
				} else {
					sizeRaw = static_cast<uint64_t>(sizeVal.As<Napi::Number>().Int64Value());
				}
				size_t size = static_cast<size_t>(sizeRaw);
				uint32_t perms = region.Get("perms").As<Napi::Number>().Uint32Value();

				uc_mem_map(engine_, address, size, perms);

				if (region.Has("data")) {
					Napi::Buffer<uint8_t> buffer = region.Get("data").As<Napi::Buffer<uint8_t>>();
					uc_mem_write(engine_, address, buffer.Data(), buffer.Length());
				}
			}
		}
	}

	// 2. Restore Context
	if (state.Has("context")) {
		Napi::Object contextObj = state.Get("context").As<Napi::Object>();
		UnicornContext* contextWrapper = Napi::ObjectWrap<UnicornContext>::Unwrap(contextObj);
		if (contextWrapper && contextWrapper->GetContext()) {
			uc_context_restore(engine_, contextWrapper->GetContext());
		}
	}

	return env.Undefined();
}

Napi::Value UnicornWrapper::Query(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 1) {
		Napi::TypeError::New(env, "Expected 1 argument: queryType").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uc_query_type queryType = static_cast<uc_query_type>(info[0].As<Napi::Number>().Int32Value());
	size_t result = 0;

	uc_err err = uc_query(engine_, queryType, &result);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Query failed");
		return env.Undefined();
	}

	return Napi::Number::New(env, static_cast<double>(result));
}

Napi::Value UnicornWrapper::CtlWrite(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (emulating_) {
		Napi::Error::New(env, "Cannot write control options while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected 2 arguments: ctlType, value").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uc_control_type ctlType = static_cast<uc_control_type>(info[0].As<Napi::Number>().Int32Value());
	int value = info[1].As<Napi::Number>().Int32Value();

	uc_err err = uc_ctl(engine_, ctlType, value);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Control write failed");
	}

	return env.Undefined();
}

Napi::Value UnicornWrapper::CtlRead(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 1) {
		Napi::TypeError::New(env, "Expected 1 argument: ctlType").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uc_control_type ctlType = static_cast<uc_control_type>(info[0].As<Napi::Number>().Int32Value());
	int value = 0;

	uc_err err = uc_ctl(engine_, ctlType, &value);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Control read failed");
		return env.Undefined();
	}

	return Napi::Number::New(env, value);
}

Napi::Value UnicornWrapper::Close(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		return env.Undefined();
	}

	if (emulating_) {
		Napi::Error::New(env, "Cannot close engine while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	CleanupHooks();
	mappedBuffers_.clear();

	uc_err err = uc_close(engine_);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to close engine");
		return env.Undefined();
	}

	engine_ = nullptr;
	closed_ = true;

	return env.Undefined();
}

// ============== Native Breakpoints ==============

void BreakpointHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	UnicornWrapper* wrapper = static_cast<UnicornWrapper*>(user_data);
	// Direct C++ check using the helper method we added to header
	if (wrapper->IsBreakpointHit(address)) {
		uc_emu_stop(uc);
	}
}

Napi::Value UnicornWrapper::BreakpointAdd(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 1) {
		Napi::TypeError::New(env, "Expected 1 argument: address").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t address;
	if (info[0].IsBigInt()) {
		bool lossless;
		address = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[0].IsNumber()) {
		address = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "address must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Add to set
	{
		std::lock_guard<std::mutex> lock(hookMutex_);
		breakpoints_.insert(address);

		// Enable global hook if first breakpoint
		if (!hasBreakpointHook_) {
			uc_err err = uc_hook_add(engine_, &breakpointHookHandle_, UC_HOOK_CODE,
				(void*)BreakpointHookCB, this, 1, 0);

			if (err != UC_ERR_OK) {
				ThrowUnicornError(env, err, "Failed to enable native breakpoint hook");
				return env.Undefined();
			}
			hasBreakpointHook_ = true;
		}
	}

	return env.Undefined();
}

Napi::Value UnicornWrapper::BreakpointDel(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 1) {
		Napi::TypeError::New(env, "Expected 1 argument: address").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t address;
	if (info[0].IsBigInt()) {
		bool lossless;
		address = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info[0].IsNumber()) {
		address = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
	} else {
		Napi::TypeError::New(env, "address must be a BigInt or Number").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Remove from set
	{
		std::lock_guard<std::mutex> lock(hookMutex_);
		breakpoints_.erase(address);

		// Disable global hook if no breakpoints left
		if (breakpoints_.empty() && hasBreakpointHook_) {
			uc_hook_del(engine_, breakpointHookHandle_);
			hasBreakpointHook_ = false;
			breakpointHookHandle_ = 0;
		}
	}

	return env.Undefined();
}

// ============== Property Getters ==============

Napi::Value UnicornWrapper::GetArch(const Napi::CallbackInfo& info) {
	return Napi::Number::New(info.Env(), static_cast<int>(arch_));
}

Napi::Value UnicornWrapper::GetMode(const Napi::CallbackInfo& info) {
	return Napi::Number::New(info.Env(), static_cast<int>(mode_));
}

Napi::Value UnicornWrapper::GetHandle(const Napi::CallbackInfo& info) {
	return Napi::BigInt::New(info.Env(), reinterpret_cast<uint64_t>(engine_));
}

Napi::Value UnicornWrapper::GetPageSize(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		return Napi::Number::New(env, 4096); // Default
	}

	size_t pageSize = 0;
	uc_query(engine_, UC_QUERY_PAGE_SIZE, &pageSize);
	return Napi::Number::New(env, static_cast<double>(pageSize));
}

// ============== UnicornContext Implementation ==============

Napi::Object UnicornContext::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "UnicornContext", {
		InstanceMethod<&UnicornContext::Free>("free"),
		InstanceAccessor<&UnicornContext::GetSize>("size"),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("UnicornContext", func);
	return exports;
}

UnicornContext::UnicornContext(const Napi::CallbackInfo& info)
	: Napi::ObjectWrap<UnicornContext>(info)
	, context_(nullptr)
	, engine_(nullptr) {
}

UnicornContext::~UnicornContext() {
	if (context_) {
		uc_context_free(context_);
		context_ = nullptr;
	}
}

Napi::Value UnicornContext::Free(const Napi::CallbackInfo& info) {
	if (context_) {
		uc_context_free(context_);
		context_ = nullptr;
	}
	return info.Env().Undefined();
}

Napi::Value UnicornContext::GetSize(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (!context_ || !engine_) {
		return Napi::Number::New(env, 0);
	}

	size_t size = uc_context_size(engine_);
	return Napi::Number::New(env, static_cast<double>(size));
}


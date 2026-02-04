/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
#include "unicorn_wrapper.h"
#include "emu_async_worker.h"
#include <cstring>
#include <sstream>

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

		// Context operations
		InstanceMethod<&UnicornWrapper::ContextSave>("contextSave"),
		InstanceMethod<&UnicornWrapper::ContextRestore>("contextRestore"),

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
	, nextHookId_(1) {

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

	if (emulating_) {
		Napi::Error::New(env, "Cannot map memory while emulation is running").ThrowAsJavaScriptException();
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

	size_t size = info[1].As<Napi::Number>().Uint32Value();
	uint32_t perms = info[2].As<Napi::Number>().Uint32Value();

	uc_err err = uc_mem_map(engine_, address, size, perms);
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

	size_t size = info[1].As<Napi::Number>().Uint32Value();

	uc_err err = uc_mem_unmap(engine_, address, size);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to unmap memory");
	}

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

	size_t size = info[1].As<Napi::Number>().Uint32Value();
	uint32_t perms = info[2].As<Napi::Number>().Uint32Value();

	uc_err err = uc_mem_protect(engine_, address, size, perms);
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

	size_t size = info[1].As<Napi::Number>().Uint32Value();

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

	if (emulating_) {
		Napi::Error::New(env, "Cannot write memory while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

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

size_t UnicornWrapper::GetRegisterSize(int regId) {
	// Default to 64-bit for most cases
	// This is a simplified version - ideally we'd have a complete mapping
	switch (arch_) {
		case UC_ARCH_X86:
			// x86-64 general purpose registers
			if (mode_ == UC_MODE_64) {
				return 8; // 64-bit
			} else if (mode_ == UC_MODE_32) {
				return 4; // 32-bit
			} else {
				return 2; // 16-bit
			}
		case UC_ARCH_ARM64:
			return 8; // 64-bit
		case UC_ARCH_ARM:
			return 4; // 32-bit
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

	if (regSize == 8) {
		uint64_t value = 0;
		uc_err err = uc_reg_read(engine_, regId, &value);
		if (err != UC_ERR_OK) {
			ThrowUnicornError(env, err, "Failed to read register");
			return env.Undefined();
		}
		return Napi::BigInt::New(env, value);
	} else {
		uint32_t value = 0;
		uc_err err = uc_reg_read(engine_, regId, &value);
		if (err != UC_ERR_OK) {
			ThrowUnicornError(env, err, "Failed to read register");
			return env.Undefined();
		}
		return Napi::Number::New(env, value);
	}
}

Napi::Value UnicornWrapper::RegWrite(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Engine is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (emulating_) {
		Napi::Error::New(env, "Cannot write registers while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected 2 arguments: regId, value").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	int regId = info[0].As<Napi::Number>().Int32Value();
	uc_err err;

	if (info[1].IsBigInt()) {
		bool lossless;
		uint64_t value = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
		err = uc_reg_write(engine_, regId, &value);
	} else if (info[1].IsNumber()) {
		uint64_t value = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
		err = uc_reg_write(engine_, regId, &value);
	} else {
		Napi::TypeError::New(env, "value must be a BigInt or Number").ThrowAsJavaScriptException();
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

		if (regSize == 8) {
			uint64_t value = 0;
			uc_err err = uc_reg_read(engine_, regId, &value);
			if (err != UC_ERR_OK) {
				ThrowUnicornError(env, err, "Failed to read register in batch");
				return env.Undefined();
			}
			result.Set(i, Napi::BigInt::New(env, value));
		} else {
			uint32_t value = 0;
			uc_err err = uc_reg_read(engine_, regId, &value);
			if (err != UC_ERR_OK) {
				ThrowUnicornError(env, err, "Failed to read register in batch");
				return env.Undefined();
			}
			result.Set(i, Napi::Number::New(env, value));
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

	if (emulating_) {
		Napi::Error::New(env, "Cannot write registers while emulation is running").ThrowAsJavaScriptException();
		return env.Undefined();
	}

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
		Napi::Value val = values.Get(i);
		uc_err err;

		if (val.IsBigInt()) {
			bool lossless;
			uint64_t value = val.As<Napi::BigInt>().Uint64Value(&lossless);
			err = uc_reg_write(engine_, regId, &value);
		} else if (val.IsNumber()) {
			uint64_t value = static_cast<uint64_t>(val.As<Napi::Number>().Int64Value());
			err = uc_reg_write(engine_, regId, &value);
		} else {
			Napi::TypeError::New(env, "All values must be BigInt or Number").ThrowAsJavaScriptException();
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
void CodeHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	HookData* data = static_cast<HookData*>(user_data);
	if (!data || !data->active) return;

	auto* callData = new CodeHookCallData{address, size};

	data->tsfn.NonBlockingCall(callData, [](Napi::Env env, Napi::Function callback, CodeHookCallData* data) {
		callback.Call({
			Napi::BigInt::New(env, data->address),
			Napi::Number::New(env, data->size)
		});
		delete data;
	});
}

void BlockHookCB(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	HookData* data = static_cast<HookData*>(user_data);
	if (!data || !data->active) return;

	auto* callData = new BlockHookCallData{address, size};

	data->tsfn.NonBlockingCall(callData, [](Napi::Env env, Napi::Function callback, BlockHookCallData* data) {
		callback.Call({
			Napi::BigInt::New(env, data->address),
			Napi::Number::New(env, data->size)
		});
		delete data;
	});
}

void MemHookCB(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
	HookData* data = static_cast<HookData*>(user_data);
	if (!data || !data->active) return;

	auto* callData = new MemHookCallData{static_cast<int>(type), address, size, value};

	data->tsfn.NonBlockingCall(callData, [](Napi::Env env, Napi::Function callback, MemHookCallData* data) {
		callback.Call({
			Napi::Number::New(env, data->type),
			Napi::BigInt::New(env, data->address),
			Napi::Number::New(env, data->size),
			Napi::BigInt::New(env, static_cast<uint64_t>(data->value))
		});
		delete data;
	});
}

void InterruptHookCB(uc_engine* uc, uint32_t intno, void* user_data) {
	HookData* data = static_cast<HookData*>(user_data);
	if (!data || !data->active) return;

	auto* callData = new InterruptHookCallData{intno};

	data->tsfn.NonBlockingCall(callData, [](Napi::Env env, Napi::Function callback, InterruptHookCallData* data) {
		callback.Call({
			Napi::Number::New(env, data->intno)
		});
		delete data;
	});
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

	auto* callData = new InvalidMemHookCallData{static_cast<int>(type), address, size, value};

	// For invalid memory hooks, we use blocking call since we need the return value
	// Note: In practice, returning a meaningful value from JS callback is complex
	// This is a simplified implementation
	data->tsfn.NonBlockingCall(callData, [](Napi::Env env, Napi::Function callback, InvalidMemHookCallData* data) {
		callback.Call({
			Napi::Number::New(env, data->type),
			Napi::BigInt::New(env, data->address),
			Napi::Number::New(env, data->size),
			Napi::BigInt::New(env, static_cast<uint64_t>(data->value))
		});
		delete data;
	});

	return true; // Continue emulation by default
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

	// Remove from our map
	{
		std::lock_guard<std::mutex> lock(hookMutex_);
		auto it = hooks_.find(handle);
		if (it != hooks_.end()) {
			DeactivateHook(it->second.get());
			hooks_.erase(it);
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
	wrapper->SetContext(context);

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

// ============== Query & Control ==============

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

	uc_err err = uc_close(engine_);
	if (err != UC_ERR_OK) {
		ThrowUnicornError(env, err, "Failed to close engine");
		return env.Undefined();
	}

	engine_ = nullptr;
	closed_ = true;

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


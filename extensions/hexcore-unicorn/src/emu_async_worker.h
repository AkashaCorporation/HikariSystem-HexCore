/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
#ifndef EMU_ASYNC_WORKER_H
#define EMU_ASYNC_WORKER_H

#include <napi.h>
#include <unicorn/unicorn.h>
#include <string>
#include <sstream>
#include <atomic>

/**
 * EmuAsyncWorker - Async worker for Unicorn emulation
 *
 * Runs emulation in a separate thread to avoid blocking the main thread.
 * Returns a Promise that resolves when emulation completes.
 *
 * Note: Hooks will still call back to JavaScript via ThreadSafeFunction,
 * which may affect performance. For maximum speed, consider using sync
 * emulation without hooks.
 */
class EmuAsyncWorker : public Napi::AsyncWorker {
public:
	EmuAsyncWorker(Napi::Env env, Napi::Promise::Deferred deferred,
		uc_engine* engine, uint64_t begin, uint64_t until,
		uint64_t timeout, size_t count,
		std::atomic<bool>* emulatingState)
		: Napi::AsyncWorker(env)
		, deferred_(deferred)
		, engine_(engine)
		, begin_(begin)
		, until_(until)
		, timeout_(timeout)
		, count_(count)
		, emulatingState_(emulatingState)
		, result_(UC_ERR_OK) {}

	void Execute() override {
		// emulatingState_ is already true when we get here
		result_ = uc_emu_start(engine_, begin_, until_, timeout_, count_);
	}

	void OnOK() override {
		Napi::Env env = Env();

		// Release the lock
		if (emulatingState_) {
			*emulatingState_ = false;
		}

		if (result_ == UC_ERR_OK) {
			deferred_.Resolve(env.Undefined());
		} else {
			std::stringstream ss;
			ss << "Emulation failed: " << uc_strerror(result_)
				<< " (code: " << static_cast<int>(result_) << ")";
			deferred_.Reject(Napi::Error::New(env, ss.str()).Value());
		}
	}

	void OnError(const Napi::Error& error) override {
		// Release the lock
		if (emulatingState_) {
			*emulatingState_ = false;
		}
		deferred_.Reject(error.Value());
	}

private:
	Napi::Promise::Deferred deferred_;
	uc_engine* engine_;
	uint64_t begin_;
	uint64_t until_;
	uint64_t timeout_;
	size_t count_;
	std::atomic<bool>* emulatingState_;
	uc_err result_;
};

/**
 * MemReadAsyncWorker - Async worker for memory reads
 *
 * Useful for reading large memory regions without blocking.
 */
class MemReadAsyncWorker : public Napi::AsyncWorker {
public:
	MemReadAsyncWorker(Napi::Env env, Napi::Promise::Deferred deferred,
		uc_engine* engine, uint64_t address, size_t size)
		: Napi::AsyncWorker(env)
		, deferred_(deferred)
		, engine_(engine)
		, address_(address)
		, size_(size)
		, result_(UC_ERR_OK) {
		data_.resize(size);
	}

	void Execute() override {
		result_ = uc_mem_read(engine_, address_, data_.data(), size_);
	}

	void OnOK() override {
		Napi::Env env = Env();

		if (result_ == UC_ERR_OK) {
			Napi::Buffer<uint8_t> buffer = Napi::Buffer<uint8_t>::Copy(env, data_.data(), size_);
			deferred_.Resolve(buffer);
		} else {
			std::stringstream ss;
			ss << "Memory read failed: " << uc_strerror(result_)
				<< " (code: " << static_cast<int>(result_) << ")";
			deferred_.Reject(Napi::Error::New(env, ss.str()).Value());
		}
	}

	void OnError(const Napi::Error& error) override {
		deferred_.Reject(error.Value());
	}

private:
	Napi::Promise::Deferred deferred_;
	uc_engine* engine_;
	uint64_t address_;
	size_t size_;
	std::vector<uint8_t> data_;
	uc_err result_;
};

/**
 * MemWriteAsyncWorker - Async worker for memory writes
 *
 * Useful for writing large memory regions without blocking.
 */
class MemWriteAsyncWorker : public Napi::AsyncWorker {
public:
	MemWriteAsyncWorker(Napi::Env env, Napi::Promise::Deferred deferred,
		uc_engine* engine, uint64_t address,
		const uint8_t* data, size_t size)
		: Napi::AsyncWorker(env)
		, deferred_(deferred)
		, engine_(engine)
		, address_(address)
		, result_(UC_ERR_OK) {
		data_.assign(data, data + size);
	}

	void Execute() override {
		result_ = uc_mem_write(engine_, address_, data_.data(), data_.size());
	}

	void OnOK() override {
		Napi::Env env = Env();

		if (result_ == UC_ERR_OK) {
			deferred_.Resolve(env.Undefined());
		} else {
			std::stringstream ss;
			ss << "Memory write failed: " << uc_strerror(result_)
				<< " (code: " << static_cast<int>(result_) << ")";
			deferred_.Reject(Napi::Error::New(env, ss.str()).Value());
		}
	}

	void OnError(const Napi::Error& error) override {
		deferred_.Reject(error.Value());
	}

private:
	Napi::Promise::Deferred deferred_;
	uc_engine* engine_;
	uint64_t address_;
	std::vector<uint8_t> data_;
	uc_err result_;
};

#endif // EMU_ASYNC_WORKER_H


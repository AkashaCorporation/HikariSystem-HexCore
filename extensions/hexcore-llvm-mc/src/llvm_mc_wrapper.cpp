/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
#include "llvm_mc_wrapper.h"
#include "asm_async_worker.h"

#include <llvm/MC/MCAsmBackend.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCObjectWriter.h>
#include <llvm/MC/MCParser/MCAsmParser.h>
#include <llvm/MC/MCParser/MCTargetAsmParser.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCTargetOptions.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/TargetParser/Triple.h>

// Object file parsing for extracting code bytes
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/MachO.h>

#include <sstream>

Napi::FunctionReference LlvmMcWrapper::constructor;

Napi::Object LlvmMcWrapper::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "LlvmMc", {
		InstanceMethod("assemble", &LlvmMcWrapper::Assemble),
		InstanceMethod("assembleAsync", &LlvmMcWrapper::AssembleAsync),
		InstanceMethod("assembleMultiple", &LlvmMcWrapper::AssembleMultiple),
		InstanceMethod("setOption", &LlvmMcWrapper::SetOption),
		InstanceMethod("getTriple", &LlvmMcWrapper::GetTriple),
		InstanceMethod("getCpu", &LlvmMcWrapper::GetCpu),
		InstanceMethod("getFeatures", &LlvmMcWrapper::GetFeatures),
		InstanceMethod("close", &LlvmMcWrapper::Close),
		InstanceAccessor("isOpen", &LlvmMcWrapper::GetIsOpen, nullptr),
		InstanceAccessor("handle", &LlvmMcWrapper::GetHandle, nullptr),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("LlvmMc", func);
	return exports;
}

LlvmMcWrapper::LlvmMcWrapper(const Napi::CallbackInfo& info)
	: Napi::ObjectWrap<LlvmMcWrapper>(info),
	closed_(false),
	intelSyntax_(true),
	target_(nullptr) {

	Napi::Env env = info.Env();

	if (info.Length() < 1 || !info[0].IsString()) {
		Napi::TypeError::New(env, "Triple (string) expected as first argument")
			.ThrowAsJavaScriptException();
		return;
	}

	triple_ = info[0].As<Napi::String>().Utf8Value();
	cpu_ = info.Length() > 1 && info[1].IsString()
		? info[1].As<Napi::String>().Utf8Value()
		: "";
	features_ = info.Length() > 2 && info[2].IsString()
		? info[2].As<Napi::String>().Utf8Value()
		: "";

	// Look up target
	std::string error;
	target_ = llvm::TargetRegistry::lookupTarget(triple_, error);
	if (!target_) {
		Napi::Error::New(env, "Failed to lookup target: " + error)
			.ThrowAsJavaScriptException();
		return;
	}

	// Create target-specific info objects
	regInfo_.reset(target_->createMCRegInfo(triple_));
	if (!regInfo_) {
		Napi::Error::New(env, "Failed to create register info")
			.ThrowAsJavaScriptException();
		return;
	}

	llvm::MCTargetOptions mcOptions;
	asmInfo_.reset(target_->createMCAsmInfo(*regInfo_, triple_, mcOptions));
	if (!asmInfo_) {
		Napi::Error::New(env, "Failed to create assembly info")
			.ThrowAsJavaScriptException();
		return;
	}

	instrInfo_.reset(target_->createMCInstrInfo());
	if (!instrInfo_) {
		Napi::Error::New(env, "Failed to create instruction info")
			.ThrowAsJavaScriptException();
		return;
	}

	subtargetInfo_.reset(target_->createMCSubtargetInfo(triple_, cpu_, features_));
	if (!subtargetInfo_) {
		Napi::Error::New(env, "Failed to create subtarget info")
			.ThrowAsJavaScriptException();
		return;
	}
}

LlvmMcWrapper::~LlvmMcWrapper() {
	closed_ = true;
}

void LlvmMcWrapper::ThrowIfClosed(Napi::Env env) {
	if (closed_) {
		Napi::Error::New(env, "LlvmMc instance has been closed")
			.ThrowAsJavaScriptException();
	}
}

bool LlvmMcWrapper::AssembleCode(const std::string& code, uint64_t address,
	std::vector<uint8_t>& bytes, std::string& error) {
	if (closed_) {
		error = "LlvmMc instance has been closed";
		return false;
	}

	try {
		// Create source manager with the code
		llvm::SourceMgr srcMgr;
		auto buffer = llvm::MemoryBuffer::getMemBuffer(code, "", false);
		srcMgr.AddNewSourceBuffer(std::move(buffer), llvm::SMLoc());

		// Create MCContext
		llvm::MCTargetOptions mcOptions;
		mcOptions.MCUseDwarfDirectory = llvm::MCTargetOptions::DisableDwarfDirectory;

		llvm::Triple tripleObj(triple_);
		auto objFileInfo = std::make_unique<llvm::MCObjectFileInfo>();

		llvm::MCContext ctx(tripleObj, asmInfo_.get(), regInfo_.get(),
							subtargetInfo_.get(), &srcMgr, &mcOptions);
		objFileInfo->initMCObjectFileInfo(ctx, false, false);
		ctx.setObjectFileInfo(objFileInfo.get());

		// Create streamer that collects bytes to a vector
		llvm::SmallVector<char, 256> codeBuffer;
		llvm::raw_svector_ostream vecOS(codeBuffer);

		auto codeEmitter = std::unique_ptr<llvm::MCCodeEmitter>(
			target_->createMCCodeEmitter(*instrInfo_, ctx));
		if (!codeEmitter) {
			error = "Failed to create code emitter";
			return false;
		}

		auto asmBackend = std::unique_ptr<llvm::MCAsmBackend>(
			target_->createMCAsmBackend(*subtargetInfo_, *regInfo_, mcOptions));
		if (!asmBackend) {
			error = "Failed to create assembler backend";
			return false;
		}

		auto objectWriter = asmBackend->createObjectWriter(vecOS);
		if (!objectWriter) {
			error = "Failed to create object writer";
			return false;
		}

		auto streamer = std::unique_ptr<llvm::MCStreamer>(
			target_->createMCObjectStreamer(
				tripleObj, ctx, std::move(asmBackend),
				std::move(objectWriter), std::move(codeEmitter),
				*subtargetInfo_, true, false, false));
		if (!streamer) {
			error = "Failed to create MC streamer";
			return false;
		}

		// Set the initial address if specified
		if (address != 0) {
			// Note: LLVM MC doesn't have a direct way to set PC for standalone assembly
			// The address is typically handled through section/symbol layout
		}

		// Create parser
		auto parser = llvm::createMCAsmParser(srcMgr, ctx, *streamer, *asmInfo_);
		if (!parser) {
			error = "Failed to create parser";
			return false;
		}

		auto targetParser = std::unique_ptr<llvm::MCTargetAsmParser>(
			target_->createMCAsmParser(*subtargetInfo_, *parser, *instrInfo_, mcOptions));
		if (!targetParser) {
			error = "Failed to create target parser";
			return false;
		}

		// Set Intel syntax for x86 if requested
		if (intelSyntax_ && (triple_.find("x86") != std::string::npos ||
							triple_.find("i386") != std::string::npos ||
							triple_.find("i686") != std::string::npos)) {
			parser->setAssemblerDialect(1); // 1 = Intel syntax
		}

		parser->setTargetParser(*targetParser);

		// Run the assembly
		if (parser->Run(false)) {
			error = "Assembly failed";
			return false;
		}

		// Finalize the stream
		streamer->finish();

		// Extract just the code bytes from the object file
		if (codeBuffer.empty()) {
			error = "No code generated";
			return false;
		}

		// Create a MemoryBuffer from the assembled object
		auto objBuffer = llvm::MemoryBuffer::getMemBuffer(
			llvm::StringRef(codeBuffer.data(), codeBuffer.size()),
			"", false);

		// Parse as object file to extract .text section
		auto objOrErr = llvm::object::ObjectFile::createObjectFile(
			objBuffer->getMemBufferRef());

		if (!objOrErr) {
			// If we can't parse as object file, try to use raw bytes
			// This might happen with very simple code
			llvm::consumeError(objOrErr.takeError());
			bytes.assign(codeBuffer.begin(), codeBuffer.end());
			return true;
		}

		auto& obj = *objOrErr.get();

		// Find the .text section (or equivalent code section)
		bool foundCode = false;
		for (const auto& section : obj.sections()) {
			auto nameOrErr = section.getName();
			if (!nameOrErr) {
				llvm::consumeError(nameOrErr.takeError());
				continue;
			}

			llvm::StringRef sectionName = *nameOrErr;

			// Check for code sections by name or flags
			bool isCodeSection = sectionName == ".text" ||
				sectionName == "__text" ||  // Mach-O
				sectionName == "CODE" ||
				section.isText();

			if (isCodeSection) {
				auto contentsOrErr = section.getContents();
				if (contentsOrErr) {
					llvm::StringRef contents = *contentsOrErr;
					if (!contents.empty()) {
						bytes.assign(contents.begin(), contents.end());
						foundCode = true;
						break;
					}
				} else {
					llvm::consumeError(contentsOrErr.takeError());
				}
			}
		}

		if (!foundCode) {
			// Fallback: return all bytes if no .text section found
			// This can happen with some object formats
			bytes.assign(codeBuffer.begin(), codeBuffer.end());
		}

		return true;

	} catch (const std::exception& e) {
		error = std::string("Exception during assembly: ") + e.what();
		return false;
	}
}

Napi::Value LlvmMcWrapper::Assemble(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	ThrowIfClosed(env);
	if (env.IsExceptionPending()) return env.Undefined();

	if (info.Length() < 1 || !info[0].IsString()) {
		Napi::TypeError::New(env, "Code string expected")
			.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	std::string code = info[0].As<Napi::String>().Utf8Value();
	uint64_t address = 0;
	if (info.Length() > 1 && info[1].IsBigInt()) {
		bool lossless;
		address = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info.Length() > 1 && info[1].IsNumber()) {
		address = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	}

	std::vector<uint8_t> bytes;
	std::string error;

	if (!AssembleCode(code, address, bytes, error)) {
		Napi::Error::New(env, error).ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Create result object
	Napi::Object result = Napi::Object::New(env);
	result.Set("bytes", Napi::Buffer<uint8_t>::Copy(env, bytes.data(), bytes.size()));
	result.Set("size", Napi::Number::New(env, static_cast<double>(bytes.size())));
	result.Set("address", Napi::BigInt::New(env, address));
	result.Set("statement", info[0].As<Napi::String>());

	return result;
}

Napi::Value LlvmMcWrapper::AssembleAsync(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	ThrowIfClosed(env);
	if (env.IsExceptionPending()) return env.Undefined();

	if (info.Length() < 1 || !info[0].IsString()) {
		Napi::TypeError::New(env, "Code string expected")
			.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	std::string code = info[0].As<Napi::String>().Utf8Value();
	uint64_t address = 0;
	if (info.Length() > 1 && info[1].IsBigInt()) {
		bool lossless;
		address = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info.Length() > 1 && info[1].IsNumber()) {
		address = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	}

	Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);
	AsmAsyncWorker* worker = new AsmAsyncWorker(env, deferred, this, code, address);
	worker->Queue();

	return deferred.Promise();
}

Napi::Value LlvmMcWrapper::AssembleMultiple(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	ThrowIfClosed(env);
	if (env.IsExceptionPending()) return env.Undefined();

	if (info.Length() < 1 || !info[0].IsArray()) {
		Napi::TypeError::New(env, "Array of code strings expected")
			.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	Napi::Array inputArray = info[0].As<Napi::Array>();
	Napi::Array results = Napi::Array::New(env, inputArray.Length());

	uint64_t currentAddress = 0;
	if (info.Length() > 1 && info[1].IsBigInt()) {
		bool lossless;
		currentAddress = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	} else if (info.Length() > 1 && info[1].IsNumber()) {
		currentAddress = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	}

	try {
		for (uint32_t i = 0; i < inputArray.Length(); i++) {
			Napi::Value item = inputArray.Get(i);
			if (!item.IsString()) {
				Napi::TypeError::New(env, "All array elements must be strings")
					.ThrowAsJavaScriptException();
				return env.Undefined();
			}

			std::string code = item.As<Napi::String>().Utf8Value();
			std::vector<uint8_t> bytes;
			std::string error;
			if (!AssembleCode(code, currentAddress, bytes, error)) {
				Napi::Error::New(
					env,
					"Assembly failed at index " + std::to_string(i) + ": " + error
				).ThrowAsJavaScriptException();
				return env.Undefined();
			}

			// Create result object
			Napi::Object result = Napi::Object::New(env);
			result.Set("bytes", Napi::Buffer<uint8_t>::Copy(env, bytes.data(), bytes.size()));
			result.Set("size", Napi::Number::New(env, static_cast<double>(bytes.size())));
			result.Set("address", Napi::BigInt::New(env, currentAddress));
			result.Set("statement", item.As<Napi::String>());

			results.Set(i, result);
			currentAddress += bytes.size();
		}

	} catch (const std::exception& e) {
		Napi::Error::New(env, std::string("LLVM Assembly Error: ") + e.what()).ThrowAsJavaScriptException();
		return env.Undefined();
	}

	return results;
}

Napi::Value LlvmMcWrapper::SetOption(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	ThrowIfClosed(env);
	if (env.IsExceptionPending()) return env.Undefined();

	if (info.Length() < 2 || !info[0].IsNumber()) {
		Napi::TypeError::New(env, "Option (number) and value expected")
			.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	int option = info[0].As<Napi::Number>().Int32Value();

	// Option 0 = SYNTAX
	if (option == 0 && info[1].IsNumber()) {
		int syntax = info[1].As<Napi::Number>().Int32Value();
		intelSyntax_ = (syntax == 0); // 0 = Intel, 1 = AT&T
	}

	return env.Undefined();
}

Napi::Value LlvmMcWrapper::GetTriple(const Napi::CallbackInfo& info) {
	return Napi::String::New(info.Env(), triple_);
}

Napi::Value LlvmMcWrapper::GetCpu(const Napi::CallbackInfo& info) {
	return Napi::String::New(info.Env(), cpu_);
}

Napi::Value LlvmMcWrapper::GetFeatures(const Napi::CallbackInfo& info) {
	return Napi::String::New(info.Env(), features_);
}

Napi::Value LlvmMcWrapper::Close(const Napi::CallbackInfo& info) {
	closed_ = true;
	regInfo_.reset();
	asmInfo_.reset();
	instrInfo_.reset();
	subtargetInfo_.reset();
	target_ = nullptr;
	return info.Env().Undefined();
}

Napi::Value LlvmMcWrapper::GetIsOpen(const Napi::CallbackInfo& info) {
	return Napi::Boolean::New(info.Env(), !closed_);
}

Napi::Value LlvmMcWrapper::GetHandle(const Napi::CallbackInfo& info) {
	return Napi::BigInt::New(info.Env(), reinterpret_cast<uint64_t>(target_));
}


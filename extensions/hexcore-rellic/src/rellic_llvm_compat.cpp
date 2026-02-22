/**
 * HexCore Rellic - LLVM 16 → 18 API Compatibility Layer Implementation
 *
 * Implements the non-trivial wrappers declared in rellic_llvm_compat.h.
 * Inline functions (getPointerType, createConstantGEP, stripPointerBitCasts,
 * getInstructionModule) live entirely in the header.
 *
 * See rellic_llvm_compat.h for the full LLVM 16 → 18 migration
 * rationale and per-function documentation.
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include "rellic_llvm_compat.h"

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>

#include <vector>

namespace rellic {

// ===================================================================
// Module::getOrInsertFunction wrapper
// ===================================================================

llvm::Function *getOrInsertRellicFunction(llvm::Module &M,
                                          llvm::StringRef name,
                                          llvm::FunctionType *FTy) {
	// In LLVM 18, getOrInsertFunction returns FunctionCallee which is
	// a pair of {FunctionType*, Value*}.  The Value* is the function
	// (or a bitcast constant if the existing declaration has a
	// different signature).
	llvm::FunctionCallee callee = M.getOrInsertFunction(name, FTy);

	// Extract the underlying Value and try to cast to Function.
	// If the module already has a declaration with a different type,
	// the callee's value will be a ConstantExpr bitcast — in that
	// case we return nullptr to signal the mismatch.
	llvm::Value *V = callee.getCallee();
	return llvm::dyn_cast<llvm::Function>(V);
}

// ===================================================================
// FunctionType creation with opaque pointers
// ===================================================================

llvm::FunctionType *createFunctionType(llvm::LLVMContext &ctx,
                                       llvm::Type *retTy,
                                       llvm::ArrayRef<llvm::Type *> params,
                                       bool isVarArg) {
	// Normalize pointer parameters: replace any PointerType with an
	// opaque pointer for the given context.  In LLVM 18 this is
	// technically a no-op (all pointers are already opaque), but the
	// wrapper exists for:
	//   1. Documentation — makes the migration explicit at call sites
	//   2. Safety — catches any stale typed-pointer types that might
	//      slip through from deserialized bitcode or test fixtures
	std::vector<llvm::Type *> normalizedParams;
	normalizedParams.reserve(params.size());

	for (llvm::Type *paramTy : params) {
		if (paramTy->isPointerTy()) {
			// Replace with opaque pointer for the same context.
			// Address space is preserved from the original type.
			unsigned addrSpace = paramTy->getPointerAddressSpace();
			normalizedParams.push_back(
			    llvm::PointerType::get(ctx, addrSpace));
		} else {
			normalizedParams.push_back(paramTy);
		}
	}

	return llvm::FunctionType::get(retTy, normalizedParams, isVarArg);
}

// ===================================================================
// Clang AST compatibility helpers (STUBS)
// ===================================================================

namespace clang_compat {

// TODO: Implement once Clang 18.1.8 headers are available in
// deps/clang/include/.  The stubs below return nullptr so that
// callers can detect the "not yet implemented" state and fall back
// gracefully.
//
// The real implementation will:
//   createRellicASTContext:
//     1. Create a clang::CompilerInvocation with C11 language opts
//     2. Set up TargetInfo from the triple
//     3. Create clang::ASTContext with the TargetInfo
//     4. Create a TranslationUnitDecl as the AST root
//     5. Return an opaque handle wrapping all of the above
//
//   createRellicCompilerInstance:
//     1. Create a clang::CompilerInstance
//     2. Configure for in-memory operation (no file I/O)
//     3. Suppress diagnostics output
//     4. Link to the provided ASTContext
//     5. Return an opaque handle

RellicASTContextHandle *createRellicASTContext(const char *triple) {
	// STUB: Clang 18.1.8 headers not yet in deps/
	(void)triple;
	return nullptr;
}

RellicCompilerInstanceHandle *createRellicCompilerInstance(
    RellicASTContextHandle *astCtx) {
	// STUB: Clang 18.1.8 headers not yet in deps/
	(void)astCtx;
	return nullptr;
}

void destroyRellicASTContext(RellicASTContextHandle *handle) {
	// STUB: nothing to free yet
	(void)handle;
}

void destroyRellicCompilerInstance(RellicCompilerInstanceHandle *handle) {
	// STUB: nothing to free yet
	(void)handle;
}

}  // namespace clang_compat

}  // namespace rellic

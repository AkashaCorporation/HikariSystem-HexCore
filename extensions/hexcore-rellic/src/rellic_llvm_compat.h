/**
 * HexCore Rellic - LLVM 16 → 18 API Compatibility Layer
 *
 * Between LLVM 16 and LLVM 18, many APIs were renamed, had their
 * signatures changed, or were removed entirely.  This header provides
 * wrappers and aliases that document the migration and give Rellic
 * code a stable surface to call.
 *
 * Key changes covered:
 *
 *   Module::getOrInsertFunction  — returns FunctionCallee in LLVM 18
 *                                  instead of Constant*.
 *   Type::getPointerTo()         — deprecated in 17, removed in 18.
 *                                  Use PointerType::get(ctx, 0).
 *   ConstantExpr::getGetElementPtr — requires explicit element type.
 *   Value::stripPointerCasts()   — still exists but fewer casts to
 *                                  strip with opaque pointers.
 *   Instruction::getModule()     — added in LLVM 17, replaces the
 *                                  getParent()->getParent()->getParent()
 *                                  chain.
 *   FunctionType::get            — pointer params are now just `ptr`.
 *
 * Clang AST helpers are stubs with TODO comments — full Clang headers
 * are not yet available in deps/.
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#pragma once

#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>

namespace rellic {

// ===================================================================
// Module::getOrInsertFunction wrapper
// ===================================================================

/// Wrapper for Module::getOrInsertFunction that returns Function*.
///
/// In LLVM 16, getOrInsertFunction returned Constant* (which could be
/// a bitcast of the function).  In LLVM 18, it returns FunctionCallee
/// — a lightweight pair of {FunctionType*, Value*}.
///
/// This wrapper extracts the Function* from the FunctionCallee,
/// creating the function if it doesn't exist.  If the module already
/// contains a declaration with a *different* signature, the returned
/// pointer may be null (callers must check).
///
/// @param M     The module to query / insert into.
/// @param name  The function name.
/// @param FTy   The expected function type.
/// @return      The Function*, or nullptr if a signature mismatch
///              prevents safe extraction.
llvm::Function *getOrInsertRellicFunction(llvm::Module &M,
                                          llvm::StringRef name,
                                          llvm::FunctionType *FTy);

// ===================================================================
// Type::getPointerTo() replacement
// ===================================================================

/// Replacement for the removed Type::getPointerTo().
///
/// LLVM 16:  someType->getPointerTo(addrSpace)
/// LLVM 18:  PointerType::get(ctx, addrSpace)
///
/// In LLVM 18 all pointers are opaque — the element type is irrelevant.
/// This wrapper makes migration call sites explicit and self-documenting.
///
/// @param ctx        The LLVMContext that owns the type.
/// @param addrSpace  Address space (0 = default / generic).
/// @return           An opaque PointerType.
inline llvm::PointerType *getPointerType(llvm::LLVMContext &ctx,
                                         unsigned addrSpace = 0) {
	return llvm::PointerType::get(ctx, addrSpace);
}

// ===================================================================
// ConstantExpr::getGetElementPtr wrapper
// ===================================================================

/// Wrapper for ConstantExpr::getGetElementPtr with explicit element type.
///
/// LLVM 16 allowed inferring the element type from the pointer operand.
/// LLVM 18 requires the element type to be passed explicitly.
///
/// @param elementType  The element type for GEP arithmetic.
/// @param base         The base constant pointer.
/// @param indices      GEP index list.
/// @return             The constant GEP expression.
inline llvm::Constant *createConstantGEP(
    llvm::Type *elementType,
    llvm::Constant *base,
    llvm::ArrayRef<llvm::Constant *> indices) {
	return llvm::ConstantExpr::getGetElementPtr(elementType, base, indices);
}

// ===================================================================
// Value::stripPointerCasts() wrapper
// ===================================================================

/// Wrapper for Value::stripPointerCasts() that documents the opaque
/// pointer behavior change.
///
/// In LLVM 16 with typed pointers, stripPointerCasts() would strip
/// bitcasts between different pointer types (e.g. i32* → i8*).
/// In LLVM 18 with opaque pointers, all pointers are `ptr`, so there
/// are far fewer (often zero) casts to strip.  The function still
/// exists and works correctly — this wrapper just makes the semantic
/// change visible at call sites.
///
/// @param V  The value to strip pointer casts from.
/// @return   The underlying value with pointer casts removed.
inline llvm::Value *stripPointerBitCasts(llvm::Value *V) {
	return V ? V->stripPointerCasts() : nullptr;
}

// ===================================================================
// Instruction::getModule() wrapper
// ===================================================================

/// Uses Instruction::getModule() (LLVM 17+) instead of the old
/// getParent()->getParent()->getParent() chain.
///
/// LLVM 16:  inst->getParent()->getParent()->getParent()
/// LLVM 17+: inst->getModule()
///
/// The new API is cleaner and avoids null-pointer dereference risks
/// when the instruction is detached from a basic block.
///
/// @param I  The instruction to query.
/// @return   The parent Module, or nullptr if the instruction is
///           not attached to a function in a module.
inline llvm::Module *getInstructionModule(llvm::Instruction *I) {
	if (!I) {
		return nullptr;
	}
	return I->getModule();
}

// ===================================================================
// FunctionType creation with opaque pointers
// ===================================================================

/// Create a FunctionType ensuring all pointer params use opaque pointers.
///
/// In LLVM 16, function signatures could have typed pointer parameters
/// (e.g. `i32*`, `i8*`).  In LLVM 18, all pointer parameters are just
/// `ptr`.  This wrapper normalizes the parameter list: any PointerType
/// in the input is replaced with an opaque pointer for the given context.
///
/// Non-pointer parameter types are passed through unchanged.
///
/// @param ctx       The LLVMContext for creating opaque pointer types.
/// @param retTy     The return type of the function.
/// @param params    The parameter types (may contain old-style typed ptrs).
/// @param isVarArg  Whether the function is variadic.
/// @return          A FunctionType with all pointer params normalized.
llvm::FunctionType *createFunctionType(llvm::LLVMContext &ctx,
                                       llvm::Type *retTy,
                                       llvm::ArrayRef<llvm::Type *> params,
                                       bool isVarArg = false);

// ===================================================================
// Clang AST compatibility helpers (STUBS)
// ===================================================================
//
// The Clang AST API changed between Clang 16 and Clang 18.  These
// helpers will provide a stable interface for Rellic's AST generation
// and manipulation code.
//
// Currently stubs — full implementation requires Clang 18.1.8 headers
// in deps/clang/include/ which are not yet available.

// Forward declarations for Clang types.
// Full headers will be included once deps/ are populated.
namespace clang_compat {

/// Opaque handle for a minimal Clang ASTContext configured for Rellic.
/// The real implementation will hold:
///   - clang::ASTContext
///   - clang::TranslationUnitDecl
///   - Target info for the decompilation architecture
struct RellicASTContextHandle;

/// Opaque handle for a minimal Clang CompilerInstance.
/// The real implementation will hold:
///   - clang::CompilerInstance
///   - Configured for pseudo-C output (no actual compilation)
struct RellicCompilerInstanceHandle;

/// Create a minimal Clang ASTContext configured for Rellic's needs.
///
/// Sets up:
///   - Target triple matching the decompilation architecture
///   - Language options for C11 (Rellic's output language)
///   - A TranslationUnitDecl as the AST root
///
/// TODO: Implement once Clang 18.1.8 headers are in deps/clang/include/
///
/// @param triple  Target triple string (e.g. "x86_64-unknown-linux-gnu").
/// @return        Opaque handle, or nullptr on failure.
RellicASTContextHandle *createRellicASTContext(const char *triple);

/// Create a minimal Clang CompilerInstance for Rellic.
///
/// Configures:
///   - No actual file I/O (in-memory only)
///   - C11 language standard
///   - No warnings / diagnostics output
///   - Linked to the given ASTContext
///
/// TODO: Implement once Clang 18.1.8 headers are in deps/clang/include/
///
/// @param astCtx  The ASTContext handle from createRellicASTContext().
/// @return        Opaque handle, or nullptr on failure.
RellicCompilerInstanceHandle *createRellicCompilerInstance(
    RellicASTContextHandle *astCtx);

/// Destroy a RellicASTContext and free all associated resources.
///
/// TODO: Implement once Clang 18.1.8 headers are in deps/clang/include/
///
/// @param handle  The handle to destroy (safe to pass nullptr).
void destroyRellicASTContext(RellicASTContextHandle *handle);

/// Destroy a RellicCompilerInstance and free all associated resources.
///
/// TODO: Implement once Clang 18.1.8 headers are in deps/clang/include/
///
/// @param handle  The handle to destroy (safe to pass nullptr).
void destroyRellicCompilerInstance(RellicCompilerInstanceHandle *handle);

}  // namespace clang_compat

}  // namespace rellic

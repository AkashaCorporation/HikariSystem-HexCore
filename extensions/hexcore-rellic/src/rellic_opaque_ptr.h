/**
 * HexCore Rellic - Opaque Pointer Utilities (LLVM 16 → 18 Migration)
 *
 * LLVM 17+ made opaque pointers mandatory.  The original Rellic code
 * (targeting LLVM 16) used typed pointers extensively:
 *
 *   PointerType::get(elementType, 0)   → now PointerType::get(ctx, 0)
 *   getPointerElementType()            → removed entirely
 *   CreateGEP(ptr->getPointerElementType(), base, idx)
 *       → CreateGEP(elementType, base, idx)
 *   CreateLoad(ptr->getPointerElementType(), ptr)
 *       → CreateLoad(elementType, ptr)
 *
 * This header provides thin wrappers that make the migration explicit
 * and self-documenting.  Every call site that previously relied on
 * typed pointers should use one of these helpers instead.
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#pragma once

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>

namespace rellic {

// ===================================================================
// Opaque pointer creation
// ===================================================================

/// Create an opaque pointer type for the given context.
///
/// LLVM 16 (typed):   PointerType::get(elementType, addrSpace)
/// LLVM 18 (opaque):  PointerType::get(ctx, addrSpace)
///
/// This wrapper exists purely for documentation — it makes every
/// pointer-creation site visibly "migrated" during code review.
///
/// @param ctx        The LLVMContext that owns the type.
/// @param addrSpace  Address space (0 = default / generic).
/// @return           An opaque PointerType (ptr / ptr addrspace(N)).
inline llvm::PointerType *createOpaquePtr(llvm::LLVMContext &ctx,
                                          unsigned addrSpace = 0) {
	return llvm::PointerType::get(ctx, addrSpace);
}

// ===================================================================
// Opaque pointer queries
// ===================================================================

/// Check whether a Type is an opaque pointer.
///
/// In LLVM 18 every pointer is opaque, so this always returns true
/// for pointer types.  The function is kept for:
///   - Assertions / documentation at migration call sites
///   - Future-proofing if LLVM ever re-introduces typed pointers
///
/// @param ty  The type to check.
/// @return    true if ty is a PointerType (always opaque in LLVM 18).
inline bool isOpaquePtr(llvm::Type *ty) {
	return ty != nullptr && ty->isPointerTy();
}

// ===================================================================
// Pointee type inference
// ===================================================================

/// Attempt to infer the pointee type of a pointer Value by inspecting
/// its users.
///
/// Since getPointerElementType() was removed in LLVM 17, code that
/// needs to know "what does this pointer point to?" must look at how
/// the pointer is actually *used*.  This helper walks the use-list
/// and returns the first concrete element type it finds from:
///
///   - GetElementPtrInst  → getSourceElementType()
///   - LoadInst           → getType()  (the loaded value's type)
///   - StoreInst          → getValueOperand()->getType()
///   - CallInst / InvokeInst → function signature parameter types
///
/// If no usage provides a type, returns nullptr.
///
/// @param ptrVal  A Value whose type is a PointerType.
/// @param M       The parent Module (used for DataLayout if needed).
/// @return        The inferred pointee Type, or nullptr.
llvm::Type *getPointeeType(llvm::Value *ptrVal, llvm::Module &M);

// ===================================================================
// Typed IR builder wrappers
// ===================================================================

/// Create a GEP instruction with an explicit element type.
///
/// LLVM 16:  builder.CreateGEP(ptr->getPointerElementType(), base, idx)
/// LLVM 18:  builder.CreateGEP(elementType, base, idx)
///
/// This wrapper enforces that the caller always passes the element
/// type explicitly, preventing accidental use of the removed
/// getPointerElementType() API.
///
/// @param builder      The IRBuilder to emit into.
/// @param elementType  The element type for the GEP arithmetic.
/// @param base         The base pointer value.
/// @param indices      GEP index list.
/// @param name         Optional instruction name.
/// @return             The created GEP Value.
inline llvm::Value *createTypedGEP(llvm::IRBuilder<> &builder,
                                   llvm::Type *elementType,
                                   llvm::Value *base,
                                   llvm::ArrayRef<llvm::Value *> indices,
                                   const llvm::Twine &name = "") {
	return builder.CreateGEP(elementType, base, indices, name);
}

/// Create a Load instruction with an explicit value type.
///
/// LLVM 16:  builder.CreateLoad(ptr->getPointerElementType(), ptr)
/// LLVM 18:  builder.CreateLoad(elementType, ptr)
///
/// Same rationale as createTypedGEP — forces the caller to supply
/// the loaded type explicitly.
///
/// @param builder      The IRBuilder to emit into.
/// @param elementType  The type of the value being loaded.
/// @param ptr          The pointer to load from.
/// @param name         Optional instruction name.
/// @return             The created LoadInst Value.
inline llvm::Value *createTypedLoad(llvm::IRBuilder<> &builder,
                                    llvm::Type *elementType,
                                    llvm::Value *ptr,
                                    const llvm::Twine &name = "") {
	return builder.CreateLoad(elementType, ptr, name);
}

}  // namespace rellic

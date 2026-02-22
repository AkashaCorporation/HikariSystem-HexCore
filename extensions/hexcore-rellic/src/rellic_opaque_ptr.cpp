/**
 * HexCore Rellic - Opaque Pointer Utilities Implementation
 *
 * Implements getPointeeType() — the only non-trivial helper in the
 * opaque pointer migration layer.  All other functions are inline
 * in the header.
 *
 * See rellic_opaque_ptr.h for the full LLVM 16 → 18 migration
 * rationale and per-function documentation.
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include "rellic_opaque_ptr.h"

#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstrTypes.h>

namespace rellic {

llvm::Type *getPointeeType(llvm::Value *ptrVal, llvm::Module &M) {
	if (!ptrVal || !ptrVal->getType()->isPointerTy()) {
		return nullptr;
	}

	// Walk the use-list and return the first concrete element type
	// we can infer from how the pointer is actually used.
	for (const llvm::Use &U : ptrVal->uses()) {
		llvm::User *user = U.getUser();

		// GEP: the source element type is exactly what the old
		// getPointerElementType() would have returned.
		if (auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(user)) {
			if (GEP->getPointerOperand() == ptrVal) {
				return GEP->getSourceElementType();
			}
		}

		// Load: the loaded value's type IS the pointee type.
		if (auto *LI = llvm::dyn_cast<llvm::LoadInst>(user)) {
			if (LI->getPointerOperand() == ptrVal) {
				return LI->getType();
			}
		}

		// Store: if our pointer is the *destination*, the pointee
		// type is the type of the value being stored.
		if (auto *SI = llvm::dyn_cast<llvm::StoreInst>(user)) {
			if (SI->getPointerOperand() == ptrVal) {
				return SI->getValueOperand()->getType();
			}
		}

		// Call / Invoke: match our pointer against the callee's
		// parameter list to find the expected pointee type.
		if (auto *CB = llvm::dyn_cast<llvm::CallBase>(user)) {
			llvm::FunctionType *FTy = CB->getFunctionType();
			for (unsigned i = 0, e = CB->arg_size(); i < e; ++i) {
				if (CB->getArgOperand(i) == ptrVal && i < FTy->getNumParams()) {
					llvm::Type *paramTy = FTy->getParamType(i);
					// If the parameter is itself a pointer we can't
					// infer the pointee — skip.
					if (!paramTy->isPointerTy()) {
						return paramTy;
					}
				}
			}
		}
	}

	// No usage gave us a concrete type.
	return nullptr;
}

}  // namespace rellic

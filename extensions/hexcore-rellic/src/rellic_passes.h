/**
 * HexCore Rellic - Decompilation Passes (LLVM 18 New Pass Manager)
 *
 * All Rellic passes ported from the legacy PassManager to the new
 * PassManager introduced in LLVM 13 and made mandatory in LLVM 17+.
 *
 * Each pass inherits from llvm::PassInfoMixin<T> and implements the
 * canonical run() signature.  Passes are STUBS for now — they declare
 * the correct interface but return PreservedAnalyses::all() (no-op).
 * Real logic will be filled in Tasks 4.3/4.4.
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#pragma once

#include <llvm/IR/PassManager.h>

// Forward-declare Clang AST types used by the passes.
// Full headers will be included in the .cpp once the Rellic port is wired.
namespace clang {
class ASTContext;
class TranslationUnitDecl;
}  // namespace clang

namespace rellic {

// ===================================================================
// Module-level passes
// ===================================================================

/// GenerateASTPass — Core pass that converts LLVM IR to a Clang AST.
/// This is the entry point of the Rellic pipeline: it walks every
/// function in the module and builds an equivalent Clang AST subtree.
struct GenerateASTPass : public llvm::PassInfoMixin<GenerateASTPass> {
	llvm::PreservedAnalyses run(llvm::Module &M,
	                            llvm::ModuleAnalysisManager &MAM);

	static llvm::StringRef name() { return "GenerateASTPass"; }
};

/// ReachBasedRefinePass — Reachability-based refinement.
/// Uses dominator / post-dominator information to simplify control
/// flow in the generated AST (e.g. removing unreachable branches).
struct ReachBasedRefinePass : public llvm::PassInfoMixin<ReachBasedRefinePass> {
	llvm::PreservedAnalyses run(llvm::Module &M,
	                            llvm::ModuleAnalysisManager &MAM);

	static llvm::StringRef name() { return "ReachBasedRefinePass"; }
};

/// NestedScopeCombinePass — Combines nested scopes in the AST.
/// Flattens unnecessarily deep scope nesting produced by the initial
/// AST generation, improving readability of the pseudo-C output.
struct NestedScopeCombinePass
    : public llvm::PassInfoMixin<NestedScopeCombinePass> {
	llvm::PreservedAnalyses run(llvm::Module &M,
	                            llvm::ModuleAnalysisManager &MAM);

	static llvm::StringRef name() { return "NestedScopeCombinePass"; }
};

// ===================================================================
// Function-level passes
// ===================================================================

/// CondBasedRefinePass — Refines conditions in the AST.
/// Simplifies if/else chains by propagating known condition values
/// into nested branches.
struct CondBasedRefinePass
    : public llvm::PassInfoMixin<CondBasedRefinePass> {
	llvm::PreservedAnalyses run(llvm::Function &F,
	                            llvm::FunctionAnalysisManager &FAM);

	static llvm::StringRef name() { return "CondBasedRefinePass"; }
};

/// DeadStmtElimPass — Dead statement elimination in the AST.
/// Removes statements whose results are never used, analogous to
/// LLVM's own DCE but operating on the Clang AST level.
struct DeadStmtElimPass : public llvm::PassInfoMixin<DeadStmtElimPass> {
	llvm::PreservedAnalyses run(llvm::Function &F,
	                            llvm::FunctionAnalysisManager &FAM);

	static llvm::StringRef name() { return "DeadStmtElimPass"; }
};

/// ExprCombinePass — Expression combining / simplification using Z3.
/// Feeds sub-expressions to the Z3 solver to find algebraically
/// simpler equivalents (e.g. `(x & 0xFF) | (x & 0xFF00)` → `x & 0xFFFF`).
struct ExprCombinePass : public llvm::PassInfoMixin<ExprCombinePass> {
	llvm::PreservedAnalyses run(llvm::Function &F,
	                            llvm::FunctionAnalysisManager &FAM);

	static llvm::StringRef name() { return "ExprCombinePass"; }
};

/// LoopRefinePass — Loop structure refinement.
/// Detects while/for/do-while patterns in the AST and rewrites
/// goto-based loops into structured loop constructs.
struct LoopRefinePass : public llvm::PassInfoMixin<LoopRefinePass> {
	llvm::PreservedAnalyses run(llvm::Function &F,
	                            llvm::FunctionAnalysisManager &FAM);

	static llvm::StringRef name() { return "LoopRefinePass"; }
};

/// NestedCondPropPass — Nested condition propagation.
/// Propagates conditions from outer if-statements into nested ones,
/// enabling further simplification by Z3CondSimplify.
struct NestedCondPropPass : public llvm::PassInfoMixin<NestedCondPropPass> {
	llvm::PreservedAnalyses run(llvm::Function &F,
	                            llvm::FunctionAnalysisManager &FAM);

	static llvm::StringRef name() { return "NestedCondPropPass"; }
};

/// Z3CondSimplifyPass — Z3-based condition simplification.
/// Uses the Z3 SMT solver to simplify boolean conditions in
/// if/else/while statements to their minimal form.
struct Z3CondSimplifyPass : public llvm::PassInfoMixin<Z3CondSimplifyPass> {
	llvm::PreservedAnalyses run(llvm::Function &F,
	                            llvm::FunctionAnalysisManager &FAM);

	static llvm::StringRef name() { return "Z3CondSimplifyPass"; }
};

}  // namespace rellic

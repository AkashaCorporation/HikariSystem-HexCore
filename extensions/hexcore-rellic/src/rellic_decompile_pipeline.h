/**
 * HexCore Rellic - Decompilation Pipeline Builder
 *
 * Wires all Rellic passes together using LLVM 18 PassManager APIs
 * directly (without PassBuilder, to avoid pulling in LLVMPasses.lib
 * and its massive Instrumentation/Sanitizer/PGO dependency chain).
 *
 * The pipeline is the canonical ordering of passes that transforms
 * an LLVM Module into a Clang AST representing pseudo-C.
 *
 * Usage:
 *   rellic::runRellicPipeline(*module);
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#pragma once

#include <llvm/IR/PassManager.h>

namespace rellic {

/// Build the full Rellic decompilation pipeline.
///
/// The pass ordering is:
///   1. GenerateASTPass        — IR → Clang AST (module)
///   2. CondBasedRefinePass    — condition refinement (function)
///   3. NestedCondPropPass     — nested condition propagation (function)
///   4. NestedScopeCombinePass — scope flattening (module)
///   5. DeadStmtElimPass       — dead statement removal (function)
///   6. ExprCombinePass        — Z3 expression combining (function)
///   7. LoopRefinePass         — while/for detection (function)
///   8. ReachBasedRefinePass   — reachability refinement (module)
///   9. Z3CondSimplifyPass     — Z3 condition simplification (function)
///
/// Function-level passes are wrapped in createModuleToFunctionPassAdaptor()
/// so the entire pipeline runs as a single ModulePassManager.
///
/// @param MPM  ModulePassManager to populate
void buildRellicPipeline(llvm::ModulePassManager &MPM);

/// Convenience: create all analysis managers, register analyses,
/// build the pipeline, and run it on the given module.
///
/// Uses direct analysis registration (no PassBuilder) to avoid
/// linking LLVMPasses.lib and its Instrumentation dependencies.
///
/// @param M  The LLVM Module to decompile
/// @return   PreservedAnalyses from the pipeline run
llvm::PreservedAnalyses runRellicPipeline(llvm::Module &M);

}  // namespace rellic

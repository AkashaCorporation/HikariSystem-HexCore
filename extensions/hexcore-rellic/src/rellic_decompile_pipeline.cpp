/**
 * HexCore Rellic - Decompilation Pipeline Builder Implementation
 *
 * Wires all Rellic passes together using LLVM 18 PassManager APIs
 * directly.  We register default analyses manually instead of using
 * PassBuilder to avoid linking LLVMPasses.lib, which pulls in
 * Instrumentation/Sanitizer/PGO libs (40+ unresolved symbols).
 *
 * Function-level passes are adapted to module level via
 * createModuleToFunctionPassAdaptor() so the entire pipeline can
 * be driven by a single ModulePassManager::run() call.
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include "rellic_decompile_pipeline.h"
#include "rellic_passes.h"

// Analysis managers
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/LoopAnalysisManager.h>
#include <llvm/IR/Module.h>

// Default analysis registrations (replaces PassBuilder::register*Analyses)
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/BasicAliasAnalysis.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/DominanceFrontier.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Verifier.h>

// Proxies for cross-manager communication
#include <llvm/IR/PassManager.h>

namespace rellic {

/// Register the minimum set of analyses needed by our stub passes.
/// This replaces PassBuilder::register*Analyses() to avoid pulling
/// in LLVMPasses.lib and its massive dependency chain.
static void registerMinimalAnalyses(
    llvm::LoopAnalysisManager &LAM,
    llvm::FunctionAnalysisManager &FAM,
    llvm::CGSCCAnalysisManager &CGAM,
    llvm::ModuleAnalysisManager &MAM) {

	// --- Function analyses ---
	FAM.registerPass([&] { return llvm::DominatorTreeAnalysis(); });
	FAM.registerPass([&] { return llvm::PostDominatorTreeAnalysis(); });
	FAM.registerPass([&] { return llvm::LoopAnalysis(); });
	FAM.registerPass([&] { return llvm::TargetLibraryAnalysis(); });
	FAM.registerPass([&] { return llvm::TargetIRAnalysis(); });
	FAM.registerPass([&] { return llvm::ScalarEvolutionAnalysis(); });
	FAM.registerPass([&] { return llvm::PassInstrumentationAnalysis(); });

	// --- Module analyses ---
	MAM.registerPass([&] { return llvm::PassInstrumentationAnalysis(); });

	// --- CGSCC analyses ---
	CGAM.registerPass([&] { return llvm::PassInstrumentationAnalysis(); });

	// --- Loop analyses ---
	LAM.registerPass([&] { return llvm::PassInstrumentationAnalysis(); });

	// --- Cross-register proxies ---
	// These allow module passes to request function analyses and vice-versa.
	FAM.registerPass([&] { return llvm::LoopAnalysisManagerFunctionProxy(LAM); });
	FAM.registerPass([&] { return llvm::ModuleAnalysisManagerFunctionProxy(MAM); });
	MAM.registerPass([&] { return llvm::FunctionAnalysisManagerModuleProxy(FAM); });
	CGAM.registerPass([&] { return llvm::FunctionAnalysisManagerCGSCCProxy(); });
	CGAM.registerPass([&] { return llvm::ModuleAnalysisManagerCGSCCProxy(MAM); });
	LAM.registerPass([&] { return llvm::FunctionAnalysisManagerLoopProxy(FAM); });
}

void buildRellicPipeline(llvm::ModulePassManager &MPM) {
	// ---------------------------------------------------------------
	// Phase 1: AST Generation (module level)
	// ---------------------------------------------------------------
	MPM.addPass(GenerateASTPass());

	// ---------------------------------------------------------------
	// Phase 2: Condition refinement (function level)
	// ---------------------------------------------------------------
	{
		llvm::FunctionPassManager FPM;
		FPM.addPass(CondBasedRefinePass());
		FPM.addPass(NestedCondPropPass());
		MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(FPM)));
	}

	// ---------------------------------------------------------------
	// Phase 3: Scope flattening (module level)
	// ---------------------------------------------------------------
	MPM.addPass(NestedScopeCombinePass());

	// ---------------------------------------------------------------
	// Phase 4: Dead code + expression simplification (function level)
	// ---------------------------------------------------------------
	{
		llvm::FunctionPassManager FPM;
		FPM.addPass(DeadStmtElimPass());
		FPM.addPass(ExprCombinePass());
		MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(FPM)));
	}

	// ---------------------------------------------------------------
	// Phase 5: Loop refinement (function level)
	// ---------------------------------------------------------------
	{
		llvm::FunctionPassManager FPM;
		FPM.addPass(LoopRefinePass());
		MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(FPM)));
	}

	// ---------------------------------------------------------------
	// Phase 6: Reachability refinement (module level)
	// ---------------------------------------------------------------
	MPM.addPass(ReachBasedRefinePass());

	// ---------------------------------------------------------------
	// Phase 7: Final Z3 condition simplification (function level)
	// ---------------------------------------------------------------
	{
		llvm::FunctionPassManager FPM;
		FPM.addPass(Z3CondSimplifyPass());
		MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(FPM)));
	}
}

llvm::PreservedAnalyses runRellicPipeline(llvm::Module &M) {
	// Create all four analysis managers
	llvm::LoopAnalysisManager LAM;
	llvm::FunctionAnalysisManager FAM;
	llvm::CGSCCAnalysisManager CGAM;
	llvm::ModuleAnalysisManager MAM;

	// Register minimal analyses directly (no PassBuilder needed)
	registerMinimalAnalyses(LAM, FAM, CGAM, MAM);

	// Build and run the pipeline
	llvm::ModulePassManager MPM;
	buildRellicPipeline(MPM);
	return MPM.run(M, MAM);
}

}  // namespace rellic

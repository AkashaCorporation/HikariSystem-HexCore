/**
 * HexCore Rellic - N-API Wrapper Implementation
 * Decompiles LLVM IR to pseudo-C via Rellic
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 *
 * GenerateBasicPseudoC() walks the LLVM Module and emits readable
 * pseudo-C by translating IR instructions into C-style statements.
 * It demangles Remill semantic function names (CALL, MOV, SUB, etc.)
 * and maps register GEPs to named variables.
 */

#include "rellic_wrapper.h"
#include "rellic_decompile_pipeline.h"

#include <sstream>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <regex>
#include <algorithm>

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/CFG.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/Operator.h>

// ---------------------------------------------------------------------------
// Helper: map an LLVM Type to a C type name string
// ---------------------------------------------------------------------------

static std::string LLVMTypeToCType(llvm::Type *ty) {
	if (!ty) return "void";
	if (ty->isVoidTy()) return "void";
	if (ty->isIntegerTy(1)) return "bool";
	if (ty->isIntegerTy(8)) return "uint8_t";
	if (ty->isIntegerTy(16)) return "uint16_t";
	if (ty->isIntegerTy(32)) return "uint32_t";
	if (ty->isIntegerTy(64)) return "uint64_t";
	if (ty->isIntegerTy())
		return "uint" + std::to_string(ty->getIntegerBitWidth()) + "_t";
	if (ty->isFloatTy()) return "float";
	if (ty->isDoubleTy()) return "double";
	if (ty->isPointerTy()) return "void *";
	if (ty->isArrayTy())
		return LLVMTypeToCType(ty->getArrayElementType()) + " *";
	if (ty->isStructTy()) {
		auto *st = llvm::cast<llvm::StructType>(ty);
		if (st->hasName()) return "struct " + st->getName().str();
		return "struct { /* anon */ }";
	}
	return "/* unknown */";
}

// ---------------------------------------------------------------------------
// Helper: try to demangle a Remill semantic function name
// Returns a short mnemonic like "MOV", "ADD", "CALL", "JZ", etc.
// If not a Remill semantic, returns empty string.
// ---------------------------------------------------------------------------

static std::string demangleRemillSemantic(const std::string &name) {
	// Remill semantics are in anonymous namespace: _ZN12_GLOBAL__N_1<len><NAME>...
	// Pattern: _ZN12_GLOBAL__N_1 followed by length + name
	// "_ZN12_GLOBAL__N_1" is exactly 17 characters
	const std::string prefix = "_ZN12_GLOBAL__N_1";
	if (name.size() < 20 || name.substr(0, prefix.size()) != prefix) {
		return "";
	}

	// After "_ZN12_GLOBAL__N_1" (17 chars) we have digit(s) then the mnemonic
	size_t pos = prefix.size();
	// Read the length prefix
	std::string lenStr;
	while (pos < name.size() && name[pos] >= '0' && name[pos] <= '9') {
		lenStr += name[pos++];
	}
	if (lenStr.empty()) return "";

	int len = std::stoi(lenStr);
	if (pos + len > name.size()) return "";

	std::string mnemonic = name.substr(pos, len);

	// Convert to uppercase for readability
	for (auto &c : mnemonic) c = toupper(c);

	return mnemonic;
}

// ---------------------------------------------------------------------------
// Helper: extract register name from a GEP instruction
// Remill GEPs into %struct.State have !remill_register metadata
// ---------------------------------------------------------------------------

static std::string getRegisterName(llvm::Value *V) {
	// Check if the value has a meaningful name (Remill names GEPs after regs)
	if (V->hasName()) {
		std::string n = V->getName().str();
		// Filter out internal names
		if (n == "BRANCH_TAKEN" || n == "RETURN_PC" || n == "MONITOR" ||
		    n == "STATE" || n == "MEMORY" || n == "NEXT_PC" || n == "PC" ||
		    n == "CSBASE" || n == "SSBASE" || n == "ESBASE" || n == "DSBASE") {
			return n;
		}
		// Register names: RAX, RBX, RCX, RDX, RSP, RBP, RSI, RDI, R8-R15, etc.
		if (!n.empty()) return n;
	}
	return "";
}

// ---------------------------------------------------------------------------
// Helper: format a constant value as a C literal
// ---------------------------------------------------------------------------

static std::string formatConstant(llvm::Value *V) {
	if (auto *CI = llvm::dyn_cast<llvm::ConstantInt>(V)) {
		int64_t val = CI->getSExtValue();
		if (val >= -256 && val <= 256) {
			return std::to_string(val);
		}
		// Format as hex for large values
		std::ostringstream oss;
		if (val < 0) {
			oss << "-0x" << std::hex << (-val);
		} else {
			oss << "0x" << std::hex << val;
		}
		return oss.str();
	}
	if (llvm::isa<llvm::ConstantPointerNull>(V)) {
		return "NULL";
	}
	if (V->hasName()) {
		return V->getName().str();
	}
	return "?";
}

// ---------------------------------------------------------------------------
// Helper: get a readable name for a value (register, constant, or temp)
// ---------------------------------------------------------------------------

static std::string valueName(llvm::Value *V,
                             std::map<llvm::Value*, std::string> &tempNames,
                             int &tempCounter) {
	if (!V) return "?";

	// Constants
	if (auto *CI = llvm::dyn_cast<llvm::ConstantInt>(V)) {
		return formatConstant(CI);
	}
	if (llvm::isa<llvm::ConstantPointerNull>(V)) {
		return "NULL";
	}

	// Named values (registers, allocas)
	if (V->hasName()) {
		return V->getName().str();
	}

	// Temporary values — assign a name
	auto it = tempNames.find(V);
	if (it != tempNames.end()) {
		return it->second;
	}
	std::string name = "t" + std::to_string(tempCounter++);
	tempNames[V] = name;
	return name;
}

// ---------------------------------------------------------------------------
// Helper: format an icmp predicate as C operator
// ---------------------------------------------------------------------------

static std::string icmpPredToC(llvm::CmpInst::Predicate pred) {
	switch (pred) {
		case llvm::CmpInst::ICMP_EQ:  return "==";
		case llvm::CmpInst::ICMP_NE:  return "!=";
		case llvm::CmpInst::ICMP_UGT: return ">";
		case llvm::CmpInst::ICMP_UGE: return ">=";
		case llvm::CmpInst::ICMP_ULT: return "<";
		case llvm::CmpInst::ICMP_ULE: return "<=";
		case llvm::CmpInst::ICMP_SGT: return ">";
		case llvm::CmpInst::ICMP_SGE: return ">=";
		case llvm::CmpInst::ICMP_SLT: return "<";
		case llvm::CmpInst::ICMP_SLE: return "<=";
		default: return "??";
	}
}

// ---------------------------------------------------------------------------
// Core: Generate pseudo-C from an LLVM Module
//
// Walks each non-declaration function, translates IR instructions
// into C-style statements. Demangles Remill semantic calls into
// readable mnemonics with operands.
// ---------------------------------------------------------------------------

static std::string GenerateBasicPseudoC(llvm::Module &M, int &functionCount) {
	std::ostringstream out;
	functionCount = 0;

	out << "// Pseudo-C generated by HexCore Rellic\n";
	out << "// Module: " << M.getModuleIdentifier() << "\n";
	out << "// Target: " << M.getTargetTriple() << "\n";
	out << "\n#include <stdint.h>\n\n";

	for (auto &F : M) {
		if (F.isDeclaration()) continue;

		functionCount++;

		std::string retType = LLVMTypeToCType(F.getReturnType());
		std::string funcName = F.getName().str();

		// Parameters
		std::ostringstream params;
		bool first = true;
		unsigned argIdx = 0;
		for (auto &arg : F.args()) {
			if (!first) params << ", ";
			first = false;
			params << LLVMTypeToCType(arg.getType());
			if (arg.hasName())
				params << " " << arg.getName().str();
			else
				params << " arg" << argIdx;
			argIdx++;
		}

		out << retType << " " << funcName << "(" << params.str() << ") {\n";

		// Collect register names from GEPs for variable declarations
		std::set<std::string> declaredRegs;
		std::map<llvm::Value*, std::string> tempNames;
		int tempCounter = 0;

		// First pass: collect register GEPs
		for (auto &BB : F) {
			for (auto &I : BB) {
				if (auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {
					std::string regName = getRegisterName(GEP);
					if (!regName.empty() && regName != "PC" &&
					    regName != "NEXT_PC" && regName != "CSBASE" &&
					    regName != "SSBASE" && regName != "ESBASE" &&
					    regName != "DSBASE" && regName != "STATE" &&
					    regName != "MEMORY" && regName != "MONITOR") {
						declaredRegs.insert(regName);
					}
				}
			}
		}

		// Emit variable declarations for registers
		if (!declaredRegs.empty()) {
			out << "\t// Register variables\n";
			for (const auto &reg : declaredRegs) {
				// Determine type from name
				if (reg.size() >= 2 && reg[0] == 'E') {
					out << "\tuint32_t " << reg << ";\n";
				} else if (reg == "BRANCH_TAKEN") {
					out << "\tbool " << reg << ";\n";
				} else if (reg == "RETURN_PC") {
					out << "\tuint64_t " << reg << ";\n";
				} else {
					out << "\tuint64_t " << reg << ";\n";
				}
			}
			out << "\n";
		}

		// Second pass: emit C statements for each basic block
		int bbIndex = 0;
		for (auto &BB : F) {
			// Label for the basic block (used by branches)
			if (BB.hasName()) {
				out << "\n" << BB.getName().str() << ":\n";
			} else {
				out << "\nbb_" << bbIndex << ":\n";
			}

			for (auto &I : BB) {
				// Skip GEPs (they're register address computations)
				if (llvm::isa<llvm::GetElementPtrInst>(&I)) continue;

				// Skip allocas (they're stack frame setup)
				if (llvm::isa<llvm::AllocaInst>(&I)) continue;

				// --- Store: register/memory write ---
				if (auto *SI = llvm::dyn_cast<llvm::StoreInst>(&I)) {
					std::string dst = valueName(SI->getPointerOperand(), tempNames, tempCounter);
					std::string src = valueName(SI->getValueOperand(), tempNames, tempCounter);

					// Skip internal bookkeeping stores
					if (dst == "MONITOR" || dst == "STATE" || dst == "MEMORY" ||
					    dst == "CSBASE" || dst == "SSBASE" || dst == "ESBASE" ||
					    dst == "DSBASE") continue;

					if (dst == "PC" || dst == "NEXT_PC") {
						out << "\t" << dst << " = " << src << ";\n";
					} else {
						out << "\t" << dst << " = " << src << ";\n";
					}
					continue;
				}

				// --- Load: register/memory read ---
				if (auto *LI = llvm::dyn_cast<llvm::LoadInst>(&I)) {
					std::string src = valueName(LI->getPointerOperand(), tempNames, tempCounter);
					std::string dst = valueName(LI, tempNames, tempCounter);

					// Skip internal bookkeeping loads
					if (src == "MONITOR" || src == "STATE" ||
					    src == "CSBASE" || src == "SSBASE" ||
					    src == "ESBASE" || src == "DSBASE") continue;

					if (src == "MEMORY") {
						// Memory pointer load — internal, skip
						continue;
					}

					out << "\t" << dst << " = " << src << ";\n";
					continue;
				}

				// --- Call: Remill semantic or external function ---
				if (auto *CI = llvm::dyn_cast<llvm::CallInst>(&I)) {
					llvm::Function *callee = CI->getCalledFunction();
					if (!callee) continue;

					std::string calleeName = callee->getName().str();

					// Skip intrinsics
					if (calleeName.find("llvm.") == 0) continue;

					// Try to demangle Remill semantic
					std::string mnemonic = demangleRemillSemantic(calleeName);

					if (!mnemonic.empty()) {
						// Emit as a readable instruction comment + assignment
						std::string result = valueName(CI, tempNames, tempCounter);

						// Build operand list (skip memory/state args)
						std::vector<std::string> ops;
						for (unsigned i = 0; i < CI->arg_size(); i++) {
							llvm::Value *arg = CI->getArgOperand(i);
							std::string argName = valueName(arg, tempNames, tempCounter);
							// Skip memory and state pointers
							if (argName == "MEMORY" || argName == "state" ||
							    argName == "memory") continue;
							// Skip the state pointer type args
							if (arg->getType()->isPointerTy()) {
								std::string n = getRegisterName(arg);
								if (!n.empty()) {
									ops.push_back(n);
									continue;
								}
							}
							ops.push_back(argName);
						}

						// Emit based on mnemonic type
						if (mnemonic == "NOP_IMPL" || mnemonic == "NOP") {
							out << "\t/* nop */  // " << mnemonic << "\n";
						} else if (mnemonic == "MOV" || mnemonic == "MOVI" ||
						           mnemonic == "MOVD" || mnemonic == "MOVDI" ||
						           mnemonic == "MOVSX" || mnemonic == "MOVSXI") {
							// MOV dst, src
							if (ops.size() >= 2) {
								out << "\t" << ops[0] << " = " << ops[1] << ";";
							} else if (ops.size() == 1) {
								out << "\t" << result << " = " << ops[0] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "ADD" || mnemonic == "ADDI" ||
						           mnemonic == "ADDSS" || mnemonic == "ADDSSI") {
							if (ops.size() >= 3) {
								out << "\t" << ops[0] << " = " << ops[1] << " + " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\t" << ops[0] << " += " << ops[1] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "SUB" || mnemonic == "SUBI" ||
						           mnemonic == "SUBSS" || mnemonic == "SUBSSI") {
							if (ops.size() >= 3) {
								out << "\t" << ops[0] << " = " << ops[1] << " - " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\t" << ops[0] << " -= " << ops[1] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "XOR" || mnemonic == "XORI") {
							if (ops.size() >= 3) {
								out << "\t" << ops[0] << " = " << ops[1] << " ^ " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\t" << ops[0] << " ^= " << ops[1] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "AND" || mnemonic == "ANDI") {
							if (ops.size() >= 3) {
								out << "\t" << ops[0] << " = " << ops[1] << " & " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\t" << ops[0] << " &= " << ops[1] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "OR" || mnemonic == "ORI") {
							if (ops.size() >= 3) {
								out << "\t" << ops[0] << " = " << ops[1] << " | " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\t" << ops[0] << " |= " << ops[1] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "SHR" || mnemonic == "SHRI") {
							if (ops.size() >= 3) {
								out << "\t" << ops[0] << " = " << ops[1] << " >> " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\t" << ops[0] << " >>= " << ops[1] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "SHL" || mnemonic == "SHLI") {
							if (ops.size() >= 3) {
								out << "\t" << ops[0] << " = " << ops[1] << " << " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\t" << ops[0] << " <<= " << ops[1] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "LEA" || mnemonic == "LEAI") {
							if (ops.size() >= 2) {
								out << "\t" << ops[0] << " = &" << ops[1] << ";";
							} else if (ops.size() == 1) {
								out << "\t" << result << " = &" << ops[0] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "INC" || mnemonic == "INCI") {
							if (ops.size() >= 1) {
								out << "\t" << ops[0] << "++;";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "DEC" || mnemonic == "DECI") {
							if (ops.size() >= 1) {
								out << "\t" << ops[0] << "--;";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "IMUL" || mnemonic == "IMULI" ||
						           mnemonic == "MUL" || mnemonic == "MULI" ||
						           mnemonic == "MULSS" || mnemonic == "MULSSI") {
							if (ops.size() >= 3) {
								out << "\t" << ops[0] << " = " << ops[1] << " * " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\t" << ops[0] << " *= " << ops[1] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "MOVSS_MEM" || mnemonic == "MOVSS_MEMI") {
							// SSE store float to memory
							if (ops.size() >= 2) {
								out << "\t*(float*)(" << ops[0] << ") = " << ops[1] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "CVTDQ2PS" || mnemonic == "CVTDQ2PSI" ||
						           mnemonic == "CVTPS2DQ" || mnemonic == "CVTPS2DQI" ||
						           mnemonic == "CVTSI2SS" || mnemonic == "CVTSI2SSI" ||
						           mnemonic == "CVTSS2SI" || mnemonic == "CVTSS2SII") {
							// SSE conversion
							if (ops.size() >= 2) {
								out << "\t" << ops[0] << " = convert(" << ops[1] << ");";
							} else if (ops.size() == 1) {
								out << "\t" << result << " = convert(" << ops[0] << ");";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "CMP" || mnemonic == "CMPI") {
							if (ops.size() >= 2) {
								out << "\t/* cmp " << ops[0] << ", " << ops[1] << " */";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "TEST" || mnemonic == "TESTI") {
							if (ops.size() >= 2) {
								out << "\t/* test " << ops[0] << ", " << ops[1] << " */";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "CALL" || mnemonic == "CALLI") {
							out << "\t";
							if (!CI->getType()->isVoidTy() && !CI->getType()->isPointerTy()) {
								out << result << " = ";
							}
							out << "call(";
							for (size_t j = 0; j < ops.size(); j++) {
								if (j > 0) out << ", ";
								out << ops[j];
							}
							out << ");  // " << mnemonic << "\n";
						} else if (mnemonic == "JZ" || mnemonic == "JE") {
							if (ops.size() >= 3) {
								out << "\tif (BRANCH_TAKEN) goto " << ops[1] << "; else goto " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\tif (ZF) goto " << ops[0] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "JNZ" || mnemonic == "JNE") {
							if (ops.size() >= 3) {
								out << "\tif (!BRANCH_TAKEN) goto " << ops[1] << "; else goto " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\tif (!ZF) goto " << ops[0] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "JL" || mnemonic == "JLE" ||
						           mnemonic == "JB" || mnemonic == "JBE" ||
						           mnemonic == "JNL" || mnemonic == "JNLE" ||
						           mnemonic == "JNB" || mnemonic == "JNBE" ||
						           mnemonic == "JA" || mnemonic == "JAE" ||
						           mnemonic == "JG" || mnemonic == "JGE" ||
						           mnemonic == "JS" || mnemonic == "JNS" ||
						           mnemonic == "JO" || mnemonic == "JNO" ||
						           mnemonic == "JP" || mnemonic == "JNP") {
							// All conditional jumps: if (cond) goto taken; else goto fallthrough;
							if (ops.size() >= 3) {
								out << "\tif (BRANCH_TAKEN) goto " << ops[1] << "; else goto " << ops[2] << ";";
							} else if (ops.size() >= 2) {
								out << "\tif (BRANCH_TAKEN) goto " << ops[0] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "JMP" || mnemonic == "JMPI") {
							if (ops.size() >= 1) {
								out << "\tgoto " << ops[0] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "RET") {
							out << "\treturn;  // " << mnemonic << "\n";
						} else if (mnemonic == "PUSH") {
							if (ops.size() >= 1) {
								out << "\tRSP -= 8; *(uint64_t*)RSP = " << ops[0] << ";";
							}
							out << "  // " << mnemonic << "\n";
						} else if (mnemonic == "POP") {
							if (ops.size() >= 1) {
								out << "\t" << ops[0] << " = *(uint64_t*)RSP; RSP += 8;";
							}
							out << "  // " << mnemonic << "\n";
						} else {
							// Generic: emit as function call with mnemonic name
							out << "\t" << mnemonic << "(";
							for (size_t j = 0; j < ops.size(); j++) {
								if (j > 0) out << ", ";
								out << ops[j];
							}
							out << ");\n";
						}
					} else {
						// Non-Remill call (e.g. __remill_read_memory_*)
						if (calleeName.find("__remill_read_memory_8") != std::string::npos) {
							std::string result2 = valueName(CI, tempNames, tempCounter);
							std::string addr = CI->arg_size() >= 2 ?
								valueName(CI->getArgOperand(1), tempNames, tempCounter) : "?";
							out << "\t" << result2 << " = *(uint8_t*)(" << addr << ");\n";
						} else if (calleeName.find("__remill_read_memory_32") != std::string::npos) {
							std::string result2 = valueName(CI, tempNames, tempCounter);
							std::string addr = CI->arg_size() >= 2 ?
								valueName(CI->getArgOperand(1), tempNames, tempCounter) : "?";
							out << "\t" << result2 << " = *(uint32_t*)(" << addr << ");\n";
						} else if (calleeName.find("__remill_read_memory_64") != std::string::npos) {
							std::string result2 = valueName(CI, tempNames, tempCounter);
							std::string addr = CI->arg_size() >= 2 ?
								valueName(CI->getArgOperand(1), tempNames, tempCounter) : "?";
							out << "\t" << result2 << " = *(uint64_t*)(" << addr << ");\n";
						} else if (calleeName.find("__remill_write_memory_8") != std::string::npos) {
							std::string addr = CI->arg_size() >= 2 ?
								valueName(CI->getArgOperand(1), tempNames, tempCounter) : "?";
							std::string val = CI->arg_size() >= 3 ?
								valueName(CI->getArgOperand(2), tempNames, tempCounter) : "?";
							out << "\t*(uint8_t*)(" << addr << ") = " << val << ";\n";
						} else if (calleeName.find("__remill_write_memory_32") != std::string::npos) {
							std::string addr = CI->arg_size() >= 2 ?
								valueName(CI->getArgOperand(1), tempNames, tempCounter) : "?";
							std::string val = CI->arg_size() >= 3 ?
								valueName(CI->getArgOperand(2), tempNames, tempCounter) : "?";
							out << "\t*(uint32_t*)(" << addr << ") = " << val << ";\n";
						} else if (calleeName.find("__remill_write_memory_64") != std::string::npos) {
							std::string addr = CI->arg_size() >= 2 ?
								valueName(CI->getArgOperand(1), tempNames, tempCounter) : "?";
							std::string val = CI->arg_size() >= 3 ?
								valueName(CI->getArgOperand(2), tempNames, tempCounter) : "?";
							out << "\t*(uint64_t*)(" << addr << ") = " << val << ";\n";
						} else if (calleeName.find("__remill_flag_computation") != std::string::npos ||
						           calleeName.find("__remill_compare") != std::string::npos ||
						           calleeName.find("__remill_undefined") != std::string::npos) {
							// Flag computations — emit as comment
							std::string result2 = valueName(CI, tempNames, tempCounter);
							out << "\t" << result2 << " = " << calleeName << "(...);\n";
						} else if (calleeName.find("__remill_read_memory_f32") != std::string::npos) {
							std::string result2 = valueName(CI, tempNames, tempCounter);
							std::string addr = CI->arg_size() >= 2 ?
								valueName(CI->getArgOperand(1), tempNames, tempCounter) : "?";
							out << "\t" << result2 << " = *(float*)(" << addr << ");\n";
						} else if (calleeName.find("__remill_write_memory_f32") != std::string::npos) {
							std::string addr = CI->arg_size() >= 2 ?
								valueName(CI->getArgOperand(1), tempNames, tempCounter) : "?";
							std::string val = CI->arg_size() >= 3 ?
								valueName(CI->getArgOperand(2), tempNames, tempCounter) : "?";
							out << "\t*(float*)(" << addr << ") = " << val << ";\n";
						}
						// else: skip unknown __remill functions silently
					}
					continue;
				}

				// --- Binary arithmetic (add, sub, mul, etc.) ---
				if (auto *BO = llvm::dyn_cast<llvm::BinaryOperator>(&I)) {
					std::string dst = valueName(BO, tempNames, tempCounter);
					std::string lhs = valueName(BO->getOperand(0), tempNames, tempCounter);
					std::string rhs = valueName(BO->getOperand(1), tempNames, tempCounter);
					std::string op;
					switch (BO->getOpcode()) {
						case llvm::Instruction::Add:  op = "+"; break;
						case llvm::Instruction::Sub:  op = "-"; break;
						case llvm::Instruction::Mul:  op = "*"; break;
						case llvm::Instruction::UDiv:
						case llvm::Instruction::SDiv: op = "/"; break;
						case llvm::Instruction::URem:
						case llvm::Instruction::SRem: op = "%"; break;
						case llvm::Instruction::Shl:  op = "<<"; break;
						case llvm::Instruction::LShr:
						case llvm::Instruction::AShr: op = ">>"; break;
						case llvm::Instruction::And:  op = "&"; break;
						case llvm::Instruction::Or:   op = "|"; break;
						case llvm::Instruction::Xor:  op = "^"; break;
						default: op = "??"; break;
					}
					out << "\t" << dst << " = " << lhs << " " << op << " " << rhs << ";\n";
					continue;
				}

				// --- ICmp: comparison ---
				if (auto *IC = llvm::dyn_cast<llvm::ICmpInst>(&I)) {
					std::string dst = valueName(IC, tempNames, tempCounter);
					std::string lhs = valueName(IC->getOperand(0), tempNames, tempCounter);
					std::string rhs = valueName(IC->getOperand(1), tempNames, tempCounter);
					std::string op = icmpPredToC(IC->getPredicate());
					out << "\t" << dst << " = (" << lhs << " " << op << " " << rhs << ");\n";
					continue;
				}

				// --- ZExt / SExt / Trunc: type casts ---
				if (auto *ZE = llvm::dyn_cast<llvm::ZExtInst>(&I)) {
					std::string dst = valueName(ZE, tempNames, tempCounter);
					std::string src = valueName(ZE->getOperand(0), tempNames, tempCounter);
					out << "\t" << dst << " = (" << LLVMTypeToCType(ZE->getType()) << ")" << src << ";\n";
					continue;
				}
				if (auto *SE = llvm::dyn_cast<llvm::SExtInst>(&I)) {
					std::string dst = valueName(SE, tempNames, tempCounter);
					std::string src = valueName(SE->getOperand(0), tempNames, tempCounter);
					out << "\t" << dst << " = (int" << SE->getType()->getIntegerBitWidth() << "_t)" << src << ";\n";
					continue;
				}
				if (auto *TR = llvm::dyn_cast<llvm::TruncInst>(&I)) {
					std::string dst = valueName(TR, tempNames, tempCounter);
					std::string src = valueName(TR->getOperand(0), tempNames, tempCounter);
					out << "\t" << dst << " = (" << LLVMTypeToCType(TR->getType()) << ")" << src << ";\n";
					continue;
				}

				// --- Select: ternary operator ---
				if (auto *Sel = llvm::dyn_cast<llvm::SelectInst>(&I)) {
					std::string dst = valueName(Sel, tempNames, tempCounter);
					std::string cond = valueName(Sel->getCondition(), tempNames, tempCounter);
					std::string tv = valueName(Sel->getTrueValue(), tempNames, tempCounter);
					std::string fv = valueName(Sel->getFalseValue(), tempNames, tempCounter);
					out << "\t" << dst << " = " << cond << " ? " << tv << " : " << fv << ";\n";
					continue;
				}

				// --- Branch ---
				if (auto *BR = llvm::dyn_cast<llvm::BranchInst>(&I)) {
					if (BR->isConditional()) {
						std::string cond = valueName(BR->getCondition(), tempNames, tempCounter);
						std::string trueBB = BR->getSuccessor(0)->hasName() ?
							BR->getSuccessor(0)->getName().str() : "bb_?";
						std::string falseBB = BR->getSuccessor(1)->hasName() ?
							BR->getSuccessor(1)->getName().str() : "bb_?";
						out << "\tif (" << cond << ") goto " << trueBB
						    << "; else goto " << falseBB << ";\n";
					} else {
						std::string target = BR->getSuccessor(0)->hasName() ?
							BR->getSuccessor(0)->getName().str() : "bb_?";
						out << "\tgoto " << target << ";\n";
					}
					continue;
				}

				// --- Return ---
				if (auto *RI = llvm::dyn_cast<llvm::ReturnInst>(&I)) {
					if (RI->getReturnValue()) {
						std::string rv = valueName(RI->getReturnValue(), tempNames, tempCounter);
						out << "\treturn " << rv << ";\n";
					} else {
						out << "\treturn;\n";
					}
					continue;
				}

				// --- PHI: emit as comment ---
				if (auto *PHI = llvm::dyn_cast<llvm::PHINode>(&I)) {
					std::string dst = valueName(PHI, tempNames, tempCounter);
					out << "\t// phi: " << dst << " = phi(";
					for (unsigned i = 0; i < PHI->getNumIncomingValues(); i++) {
						if (i > 0) out << ", ";
						out << valueName(PHI->getIncomingValue(i), tempNames, tempCounter);
					}
					out << ")\n";
					continue;
				}

				// --- Switch ---
				if (auto *SW = llvm::dyn_cast<llvm::SwitchInst>(&I)) {
					std::string cond = valueName(SW->getCondition(), tempNames, tempCounter);
					out << "\tswitch (" << cond << ") {\n";
					for (auto &Case : SW->cases()) {
						out << "\t\tcase " << Case.getCaseValue()->getSExtValue() << ": goto "
						    << (Case.getCaseSuccessor()->hasName() ?
						        Case.getCaseSuccessor()->getName().str() : "bb_?")
						    << ";\n";
					}
					out << "\t\tdefault: goto "
					    << (SW->getDefaultDest()->hasName() ?
					        SW->getDefaultDest()->getName().str() : "bb_?")
					    << ";\n\t}\n";
					continue;
				}

				// Other instructions: skip silently
			}

			bbIndex++;
		}

		out << "}\n\n";
	}

	return out.str();
}

// ---------------------------------------------------------------------------
// RellicDecompiler N-API class
// ---------------------------------------------------------------------------

Napi::Object RellicDecompiler::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "RellicDecompiler", {
		InstanceMethod("decompile", &RellicDecompiler::Decompile),
		InstanceMethod("decompileAsync", &RellicDecompiler::DecompileAsync),
		InstanceMethod("close", &RellicDecompiler::Close),
		InstanceMethod("isOpen", &RellicDecompiler::IsOpen),
	});

	Napi::FunctionReference* constructor = new Napi::FunctionReference();
	*constructor = Napi::Persistent(func);
	env.SetInstanceData(constructor);

	exports.Set("RellicDecompiler", func);
	return exports;
}

RellicDecompiler::RellicDecompiler(const Napi::CallbackInfo& info)
	: Napi::ObjectWrap<RellicDecompiler>(info) {
	llvmContext_ = std::make_unique<llvm::LLVMContext>();
}

RellicDecompiler::~RellicDecompiler() {
	closed_ = true;
	llvmContext_.reset();
}

Napi::Value RellicDecompiler::Decompile(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		DecompileResult result;
		result.success = false;
		result.error = "Decompiler is closed";
		result.functionCount = 0;
		return DecompileResultToJS(env, result);
	}

	if (info.Length() < 1 || !info[0].IsString()) {
		DecompileResult result;
		result.success = false;
		result.error = "Expected string argument (LLVM IR text)";
		result.functionCount = 0;
		return DecompileResultToJS(env, result);
	}

	std::string irText = info[0].As<Napi::String>().Utf8Value();

	try {
		DecompileResult result = DoDecompile(irText);
		return DecompileResultToJS(env, result);
	} catch (const std::exception& e) {
		DecompileResult result;
		result.success = false;
		result.error = std::string("Native exception: ") + e.what();
		result.functionCount = 0;
		return DecompileResultToJS(env, result);
	} catch (...) {
		DecompileResult result;
		result.success = false;
		result.error = "Unknown native exception";
		result.functionCount = 0;
		return DecompileResultToJS(env, result);
	}
}

Napi::Value RellicDecompiler::DecompileAsync(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		auto deferred = Napi::Promise::Deferred::New(env);
		DecompileResult result;
		result.success = false;
		result.error = "Decompiler is closed";
		result.functionCount = 0;
		deferred.Resolve(DecompileResultToJS(env, result));
		return deferred.Promise();
	}

	if (info.Length() < 1 || !info[0].IsString()) {
		auto deferred = Napi::Promise::Deferred::New(env);
		DecompileResult result;
		result.success = false;
		result.error = "Expected string argument (LLVM IR text)";
		result.functionCount = 0;
		deferred.Resolve(DecompileResultToJS(env, result));
		return deferred.Promise();
	}

	std::string irText = info[0].As<Napi::String>().Utf8Value();

	auto* worker = new DecompileAsyncWorker(env, this, std::move(irText));
	auto promise = worker->GetDeferred().Promise();
	worker->Queue();
	return promise;
}

Napi::Value RellicDecompiler::Close(const Napi::CallbackInfo& info) {
	if (!closed_) {
		closed_ = true;
		llvmContext_.reset();
	}
	return info.Env().Undefined();
}

Napi::Value RellicDecompiler::IsOpen(const Napi::CallbackInfo& info) {
	return Napi::Boolean::New(info.Env(), !closed_);
}

// ---------------------------------------------------------------------------
// DoDecompile
// ---------------------------------------------------------------------------

DecompileResult RellicDecompiler::DoDecompile(const std::string& irText) {
	DecompileResult result;
	result.functionCount = 0;

	if (irText.empty()) {
		result.success = false;
		result.error = "Empty IR text";
		return result;
	}

	llvm::LLVMContext parseCtx;
	llvm::SMDiagnostic parseErr;

	auto module = llvm::parseAssemblyString(irText, parseErr, parseCtx);
	if (!module) {
		std::string errMsg;
		llvm::raw_string_ostream errStream(errMsg);
		parseErr.print("rellic", errStream);
		errStream.flush();

		result.success = false;
		result.error = "Failed to parse LLVM IR: " + errMsg;
		return result;
	}

	// Run the Rellic pipeline (stubs — no-op passes for now)
	try {
		rellic::runRellicPipeline(*module);
	} catch (const std::exception& e) {
		result.success = false;
		result.error = std::string("Rellic pipeline error: ") + e.what();
		return result;
	} catch (...) {
		result.success = false;
		result.error = "Unknown error in Rellic pipeline";
		return result;
	}

	// Generate pseudo-C by walking the LLVM Module
	int funcCount = 0;
	std::string pseudoC = GenerateBasicPseudoC(*module, funcCount);

	result.success = true;
	result.code = pseudoC;
	result.functionCount = funcCount;
	return result;
}

Napi::Object RellicDecompiler::DecompileResultToJS(
	Napi::Env env, const DecompileResult& result) {

	Napi::Object obj = Napi::Object::New(env);
	obj.Set("success", Napi::Boolean::New(env, result.success));
	obj.Set("code", Napi::String::New(env, result.code));
	obj.Set("error", Napi::String::New(env, result.error));
	obj.Set("functionCount", Napi::Number::New(env, result.functionCount));
	return obj;
}

// ---------------------------------------------------------------------------
// DecompileAsyncWorker
// ---------------------------------------------------------------------------

DecompileAsyncWorker::DecompileAsyncWorker(
	Napi::Env env,
	RellicDecompiler* decompiler,
	std::string irText)
	: Napi::AsyncWorker(env),
	  decompiler_(decompiler),
	  irText_(std::move(irText)),
	  deferred_(Napi::Promise::Deferred::New(env)) {}

void DecompileAsyncWorker::Execute() {
	try {
		result_ = decompiler_->DoDecompile(irText_);
		if (!result_.success) {
			SetError(result_.error);
		}
	} catch (const std::exception& e) {
		result_.success = false;
		result_.error = std::string("Native exception during async decompile: ") + e.what();
		result_.functionCount = 0;
		SetError(result_.error);
	} catch (...) {
		result_.success = false;
		result_.error = "Unknown native exception during async decompile";
		result_.functionCount = 0;
		SetError(result_.error);
	}
}

void DecompileAsyncWorker::OnOK() {
	Napi::Env env = Env();
	deferred_.Resolve(decompiler_->DecompileResultToJS(env, result_));
}

void DecompileAsyncWorker::OnError(const Napi::Error& error) {
	Napi::Env env = Env();
	deferred_.Resolve(decompiler_->DecompileResultToJS(env, result_));
}

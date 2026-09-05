; ModuleID = 'hexcore-remill-lift'
source_filename = "hexcore-remill-lift"
target datalayout = "e-m:x-p:32:32-i64:64-f80:32-n8:16:32-a:0:32-S32"
target triple = "i386-unknown-windows-msvc-coff"

%struct.State = type { %struct.X86State }
%struct.X86State = type { %struct.ArchState, [32 x %union.VectorReg], %struct.ArithFlags, %union.anon, %struct.Segments, %struct.AddressSpace, %struct.GPR, %struct.X87Stack, %struct.MMX, %struct.FPUStatusFlags, [8 x i8], %union.FPU, %struct.SegmentCaches, %struct.K_REG }
%struct.ArchState = type { i32, i32, %union.anon }
%union.VectorReg = type { %union.vec512_t }
%union.vec512_t = type { %struct.uint128v4_t }
%struct.uint128v4_t = type { [4 x i128] }
%struct.ArithFlags = type { i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8 }
%union.anon = type { i64 }
%struct.Segments = type { i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector }
%union.SegmentSelector = type { i16 }
%struct.AddressSpace = type { i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg }
%struct.Reg = type { %union.anon.1, i32 }
%union.anon.1 = type { i32 }
%struct.GPR = type { i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg }
%struct.X87Stack = type { [8 x %struct.anon.3] }
%struct.anon.3 = type { [6 x i8], %struct.float80_t }
%struct.float80_t = type { [10 x i8] }
%struct.MMX = type { [8 x %struct.anon.4] }
%struct.anon.4 = type { i64, %union.vec64_t }
%union.vec64_t = type { %struct.uint64v1_t }
%struct.uint64v1_t = type { [1 x i64] }
%struct.FPUStatusFlags = type { i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, [2 x i8] }
%union.FPU = type { %struct.anon.11 }
%struct.anon.11 = type { %struct.FpuFXSAVE, [96 x i8] }
%struct.FpuFXSAVE = type { %union.SegmentSelector, %union.SegmentSelector, %union.FPUAbridgedTagWord, i8, i16, i32, %union.SegmentSelector, i16, i32, %union.SegmentSelector, i16, %union.anon.1, %union.anon.1, [8 x %struct.FPUStackElem], [16 x %union.vec128_t] }
%union.FPUAbridgedTagWord = type { i8 }
%struct.FPUStackElem = type { %union.anon.9, [6 x i8] }
%union.anon.9 = type { %struct.float80_t }
%union.vec128_t = type { %struct.uint128v1_t }
%struct.uint128v1_t = type { [1 x i128] }
%struct.SegmentCaches = type { %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow }
%struct.SegmentShadow = type { %union.anon, i32, i32 }
%struct.K_REG = type { [8 x %struct.anon.16] }
%struct.anon.16 = type { i64, i64 }

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local zeroext i8 @__remill_read_memory_8(ptr noundef, i32 noundef) #0

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local ptr @__remill_write_memory_8(ptr noundef, i32 noundef, i8 noundef zeroext) #0

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local zeroext i1 @__remill_flag_computation_carry(i1 noundef zeroext, ...) #0

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare !remill.function.type !6 i8 @llvm.ctpop.i8(i8) #1

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local zeroext i1 @__remill_flag_computation_zero(i1 noundef zeroext, ...) #0

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local zeroext i1 @__remill_flag_computation_sign(i1 noundef zeroext, ...) #0

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local zeroext i1 @__remill_flag_computation_overflow(i1 noundef zeroext, ...) #0

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local i32 @__remill_read_memory_32(ptr noundef, i32 noundef) #0

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local ptr @__remill_write_memory_32(ptr noundef, i32 noundef, i32 noundef) #0

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13SUBI3RnWIjE2RnIjLb1EE2InIjEEEP6MemoryS8_R5StateT_T0_T1_(ptr noundef readnone returned, ptr nocapture noundef nonnull writeonly align 16 dereferenceable(3504), ptr nocapture writeonly, i32, i32) #2

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13SUBI3RnWIjE2RnIjLb1EES4_EEP6MemoryS6_R5StateT_T0_T1_(ptr noundef readnone returned, ptr nocapture noundef nonnull writeonly align 16 dereferenceable(3504), ptr nocapture writeonly, i32, i32) #2

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local zeroext i8 @__remill_undefined_8() #0

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13RETEP6MemoryR5State3RnWIjE(ptr noundef returned, ptr nocapture noundef nonnull align 16 dereferenceable(3504), ptr nocapture writeonly) #2

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local zeroext i1 @__remill_compare_neq(i1 noundef zeroext) #0

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !6 dso_local zeroext i1 @__remill_compare_eq(i1 noundef zeroext) #0

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13JNZEP6MemoryR5State3RnWIhE2InIjES7_S4_IjE(ptr noundef readnone returned, ptr nocapture noundef nonnull readonly align 16 dereferenceable(3504), ptr nocapture writeonly, i32, i32, ptr nocapture writeonly) #2

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_12JZEP6MemoryR5State3RnWIhE2InIjES7_S4_IjE(ptr noundef readnone returned, ptr nocapture noundef nonnull readonly align 16 dereferenceable(3504), ptr nocapture writeonly, i32, i32, ptr nocapture writeonly) #2

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13MOVI3MnWIhE2RnIhLb1EEEEP6MemoryS6_R5StateT_T0_(ptr noundef, ptr nocapture nonnull readnone align 16, i32, i32) #2

; Function Attrs: alwaysinline mustprogress nofree norecurse nosync nounwind willreturn memory(argmem: write)
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13MOVI3RnWIjE2RnIjLb1EEEEP6MemoryS6_R5StateT_T0_(ptr noundef readnone returned, ptr nocapture nonnull readnone align 16, ptr nocapture writeonly, i32) #3

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13MOVI3RnWIhE2MnIhEEEP6MemoryS6_R5StateT_T0_(ptr noundef returned, ptr nocapture nonnull readnone align 16, ptr nocapture writeonly, i32) #2

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13MOVI3RnWIjE2MnIjEEEP6MemoryS6_R5StateT_T0_(ptr noundef returned, ptr nocapture nonnull readnone align 16, ptr nocapture writeonly, i32) #2

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13XORI3RnWIjE2RnIjLb1EES4_EEP6MemoryS6_R5StateT_T0_T1_(ptr noundef readnone returned, ptr nocapture noundef nonnull writeonly align 16 dereferenceable(3504), ptr nocapture writeonly, i32, i32) #2

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_14TESTI2RnIjLb1EES2_EEP6MemoryS4_R5StateT_T0_(ptr noundef readnone returned, ptr nocapture noundef nonnull writeonly align 16 dereferenceable(3504), i32, i32) #2

; Function Attrs: alwaysinline mustprogress nofree norecurse nosync nounwind willreturn memory(argmem: write)
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13LEAI3RnWIjE2MnIhEjEEP6MemoryS6_R5StateT_T0_(ptr noundef readnone returned, ptr nocapture nonnull readnone align 16, ptr nocapture writeonly, i32) #3

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_13POPI3RnWIjEEEP6MemoryS4_R5StateT_(ptr noundef returned, ptr nocapture noundef nonnull align 16 dereferenceable(3504), ptr nocapture writeonly) #2

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local noundef ptr @_ZN12_GLOBAL__N_14PUSHI2InIjEEEP6MemoryS4_R5StateT_(ptr noundef, ptr nocapture noundef nonnull align 16 dereferenceable(3504), i32) #2

define ptr @lifted_268441120(ptr noalias %state, i32 %program_counter, ptr noalias %memory) {
bb_0:
  %DSBASE = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 5, i32 9, i32 0, i32 0, !remill_register !7
  %CL = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 6, i32 5, i32 0, i32 0, !remill_register !8
  %EDI = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 6, i32 11, i32 0, i32 0, !remill_register !9
  %ESI = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 6, i32 9, i32 0, i32 0, !remill_register !10
  %EAX = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 6, i32 1, i32 0, i32 0, !remill_register !11
  %SSBASE = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 5, i32 1, i32 0, i32 0, !remill_register !12
  %ESP = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 6, i32 13, i32 0, i32 0, !remill_register !13
  %EDX = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 6, i32 7, i32 0, i32 0, !remill_register !14
  %BRANCH_TAKEN = alloca i8, align 1
  %RETURN_PC = alloca i32, align 4
  %MONITOR = alloca i32, align 4
  store i32 0, ptr %MONITOR, align 4
  %STATE = alloca ptr, align 4
  store ptr %state, ptr %STATE, align 4
  %MEMORY = alloca ptr, align 4
  store ptr %memory, ptr %MEMORY, align 4
  %NEXT_PC = alloca i32, align 4
  store i32 %program_counter, ptr %NEXT_PC, align 4
  %PC = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 6, i32 33, i32 0, i32 0, !remill_register !15
  store i32 %program_counter, ptr %PC, align 4
  %v1 = add i32 %program_counter, 4
  store i32 %v1, ptr %NEXT_PC, align 4
  %SP18 = load i32, ptr %ESP, align 4
  %SSBASE16 = load i32, ptr %SSBASE, align 4
  %v2 = add i32 %SP18, 12
  %v3 = add i32 %v2, %SSBASE16
  %v4 = load ptr, ptr %MEMORY, align 4
  %v5 = call ptr @_ZN12_GLOBAL__N_13MOVI3RnWIjE2MnIjEEEP6MemoryS6_R5StateT_T0_(ptr %v4, ptr %state, ptr %EDX, i32 %v3)
  store ptr %v5, ptr %MEMORY, align 4
  store i32 %v1, ptr %PC, align 4
  %v6 = add i32 %v1, 2
  store i32 %v6, ptr %NEXT_PC, align 4
  %DL21 = load i32, ptr %EDX, align 4
  %DL20 = load i32, ptr %EDX, align 4
  %v7 = load ptr, ptr %MEMORY, align 4
  %v8 = call ptr @_ZN12_GLOBAL__N_14TESTI2RnIjLb1EES2_EEP6MemoryS4_R5StateT_T0_(ptr %v7, ptr %state, i32 %DL21, i32 %DL20)
  store ptr %v8, ptr %MEMORY, align 4
  store i32 %v6, ptr %PC, align 4
  %v9 = add i32 %v6, 2
  store i32 %v9, ptr %NEXT_PC, align 4
  %v10 = add i32 %v9, 33
  %v11 = load ptr, ptr %MEMORY, align 4
  %v12 = call ptr @_ZN12_GLOBAL__N_12JZEP6MemoryR5State3RnWIhE2InIjES7_S4_IjE(ptr %v11, ptr %state, ptr %BRANCH_TAKEN, i32 %v10, i32 %v9, ptr %NEXT_PC)
  store ptr %v12, ptr %MEMORY, align 4
  %branch_taken = load i8, ptr %BRANCH_TAKEN, align 1
  %branch_taken.bool = icmp ne i8 %branch_taken, 0
  br i1 %branch_taken.bool, label %bb_268441161, label %bb_268441128

bb_268441128:                                     ; preds = %bb_0
  %v13 = load i32, ptr %NEXT_PC, align 4
  store i32 %v13, ptr %PC, align 4
  %v14 = add i32 %v13, 4
  store i32 %v14, ptr %NEXT_PC, align 4
  %SP17 = load i32, ptr %ESP, align 4
  %SSBASE15 = load i32, ptr %SSBASE, align 4
  %v15 = add i32 %SP17, 4
  %v16 = add i32 %v15, %SSBASE15
  %v17 = load ptr, ptr %MEMORY, align 4
  %v18 = call ptr @_ZN12_GLOBAL__N_13MOVI3RnWIjE2MnIjEEEP6MemoryS6_R5StateT_T0_(ptr %v17, ptr %state, ptr %EAX, i32 %v16)
  store ptr %v18, ptr %MEMORY, align 4
  store i32 %v14, ptr %PC, align 4
  %v19 = add i32 %v14, 1
  store i32 %v19, ptr %NEXT_PC, align 4
  %SI8 = load i32, ptr %ESI, align 4
  %v20 = load ptr, ptr %MEMORY, align 4
  %v21 = call ptr @_ZN12_GLOBAL__N_14PUSHI2InIjEEEP6MemoryS4_R5StateT_(ptr %v20, ptr %state, i32 %SI8)
  store ptr %v21, ptr %MEMORY, align 4
  store i32 %v19, ptr %PC, align 4
  %v22 = add i32 %v19, 4
  store i32 %v22, ptr %NEXT_PC, align 4
  %SP = load i32, ptr %ESP, align 4
  %SSBASE14 = load i32, ptr %SSBASE, align 4
  %v23 = add i32 %SP, 12
  %v24 = add i32 %v23, %SSBASE14
  %v25 = load ptr, ptr %MEMORY, align 4
  %v26 = call ptr @_ZN12_GLOBAL__N_13MOVI3RnWIjE2MnIjEEEP6MemoryS6_R5StateT_T0_(ptr %v25, ptr %state, ptr %ESI, i32 %v24)
  store ptr %v26, ptr %MEMORY, align 4
  store i32 %v22, ptr %PC, align 4
  %v27 = add i32 %v22, 1
  store i32 %v27, ptr %NEXT_PC, align 4
  %DI6 = load i32, ptr %EDI, align 4
  %v28 = load ptr, ptr %MEMORY, align 4
  %v29 = call ptr @_ZN12_GLOBAL__N_14PUSHI2InIjEEEP6MemoryS4_R5StateT_(ptr %v28, ptr %state, i32 %DI6)
  store ptr %v29, ptr %MEMORY, align 4
  store i32 %v27, ptr %PC, align 4
  %v30 = add i32 %v27, 2
  store i32 %v30, ptr %NEXT_PC, align 4
  %SI7 = load i32, ptr %ESI, align 4
  %AL13 = load i32, ptr %EAX, align 4
  %v31 = load ptr, ptr %MEMORY, align 4
  %v32 = call ptr @_ZN12_GLOBAL__N_13SUBI3RnWIjE2RnIjLb1EES4_EEP6MemoryS6_R5StateT_T0_T1_(ptr %v31, ptr %state, ptr %ESI, i32 %SI7, i32 %AL13)
  store ptr %v32, ptr %MEMORY, align 4
  store i32 %v30, ptr %PC, align 4
  %v33 = add i32 %v30, 2
  store i32 %v33, ptr %NEXT_PC, align 4
  %DL19 = load i32, ptr %EDX, align 4
  %v34 = load ptr, ptr %MEMORY, align 4
  %v35 = call ptr @_ZN12_GLOBAL__N_13MOVI3RnWIjE2RnIjLb1EEEEP6MemoryS6_R5StateT_T0_(ptr %v34, ptr %state, ptr %EDI, i32 %DL19)
  store ptr %v35, ptr %MEMORY, align 4
  br label %bb_268441142

bb_268441142:                                     ; preds = %bb_268441142, %bb_268441128
  %v36 = load i32, ptr %NEXT_PC, align 4
  store i32 %v36, ptr %PC, align 4
  %v37 = add i32 %v36, 3
  store i32 %v37, ptr %NEXT_PC, align 4
  %SI = load i32, ptr %ESI, align 4
  %AL12 = load i32, ptr %EAX, align 4
  %DSBASE4 = load i32, ptr %DSBASE, align 4
  %v38 = mul i32 %AL12, 1
  %v39 = add i32 %SI, %v38
  %v40 = add i32 %v39, %DSBASE4
  %v41 = load ptr, ptr %MEMORY, align 4
  %v42 = call ptr @_ZN12_GLOBAL__N_13MOVI3RnWIhE2MnIhEEEP6MemoryS6_R5StateT_T0_(ptr %v41, ptr %state, ptr %CL, i32 %v40)
  store ptr %v42, ptr %MEMORY, align 4
  store i32 %v37, ptr %PC, align 4
  %v43 = add i32 %v37, 3
  store i32 %v43, ptr %NEXT_PC, align 4
  %AL11 = load i32, ptr %EAX, align 4
  %v44 = add i32 %AL11, 1
  %v45 = load ptr, ptr %MEMORY, align 4
  %v46 = call ptr @_ZN12_GLOBAL__N_13LEAI3RnWIjE2MnIhEjEEP6MemoryS6_R5StateT_T0_(ptr %v45, ptr %state, ptr %EAX, i32 %v44)
  store ptr %v46, ptr %MEMORY, align 4
  store i32 %v43, ptr %PC, align 4
  %v47 = add i32 %v43, 3
  store i32 %v47, ptr %NEXT_PC, align 4
  %AL10 = load i32, ptr %EAX, align 4
  %DSBASE3 = load i32, ptr %DSBASE, align 4
  %v48 = sub i32 %AL10, 1
  %v49 = add i32 %v48, %DSBASE3
  %CL5 = load i8, ptr %CL, align 1
  %v50 = zext i8 %CL5 to i32
  %v51 = load ptr, ptr %MEMORY, align 4
  %v52 = call ptr @_ZN12_GLOBAL__N_13MOVI3MnWIhE2RnIhLb1EEEEP6MemoryS6_R5StateT_T0_(ptr %v51, ptr %state, i32 %v49, i32 %v50)
  store ptr %v52, ptr %MEMORY, align 4
  store i32 %v47, ptr %PC, align 4
  %v53 = add i32 %v47, 3
  store i32 %v53, ptr %NEXT_PC, align 4
  %DL = load i32, ptr %EDX, align 4
  %v54 = load ptr, ptr %MEMORY, align 4
  %v55 = call ptr @_ZN12_GLOBAL__N_13SUBI3RnWIjE2RnIjLb1EE2InIjEEEP6MemoryS8_R5StateT_T0_T1_(ptr %v54, ptr %state, ptr %EDX, i32 %DL, i32 1)
  store ptr %v55, ptr %MEMORY, align 4
  store i32 %v53, ptr %PC, align 4
  %v56 = add i32 %v53, 2
  store i32 %v56, ptr %NEXT_PC, align 4
  %v57 = sub i32 %v56, 14
  %v58 = load ptr, ptr %MEMORY, align 4
  %v59 = call ptr @_ZN12_GLOBAL__N_13JNZEP6MemoryR5State3RnWIhE2InIjES7_S4_IjE(ptr %v58, ptr %state, ptr %BRANCH_TAKEN, i32 %v57, i32 %v56, ptr %NEXT_PC)
  store ptr %v59, ptr %MEMORY, align 4
  %branch_taken1 = load i8, ptr %BRANCH_TAKEN, align 1
  %branch_taken.bool2 = icmp ne i8 %branch_taken1, 0
  br i1 %branch_taken.bool2, label %bb_268441142, label %bb_268441156

bb_268441156:                                     ; preds = %bb_268441142
  %v60 = load i32, ptr %NEXT_PC, align 4
  store i32 %v60, ptr %PC, align 4
  %v61 = add i32 %v60, 2
  store i32 %v61, ptr %NEXT_PC, align 4
  %DI = load i32, ptr %EDI, align 4
  %v62 = load ptr, ptr %MEMORY, align 4
  %v63 = call ptr @_ZN12_GLOBAL__N_13MOVI3RnWIjE2RnIjLb1EEEEP6MemoryS6_R5StateT_T0_(ptr %v62, ptr %state, ptr %EAX, i32 %DI)
  store ptr %v63, ptr %MEMORY, align 4
  store i32 %v61, ptr %PC, align 4
  %v64 = add i32 %v61, 1
  store i32 %v64, ptr %NEXT_PC, align 4
  %v65 = load ptr, ptr %MEMORY, align 4
  %v66 = call ptr @_ZN12_GLOBAL__N_13POPI3RnWIjEEEP6MemoryS4_R5StateT_(ptr %v65, ptr %state, ptr %EDI)
  store ptr %v66, ptr %MEMORY, align 4
  store i32 %v64, ptr %PC, align 4
  %v67 = add i32 %v64, 1
  store i32 %v67, ptr %NEXT_PC, align 4
  %v68 = load ptr, ptr %MEMORY, align 4
  %v69 = call ptr @_ZN12_GLOBAL__N_13POPI3RnWIjEEEP6MemoryS4_R5StateT_(ptr %v68, ptr %state, ptr %ESI)
  store ptr %v69, ptr %MEMORY, align 4
  store i32 %v67, ptr %PC, align 4
  %v70 = add i32 %v67, 1
  store i32 %v70, ptr %NEXT_PC, align 4
  %v71 = load ptr, ptr %MEMORY, align 4
  %v72 = call ptr @_ZN12_GLOBAL__N_13RETEP6MemoryR5State3RnWIjE(ptr %v71, ptr %state, ptr %NEXT_PC)
  store ptr %v72, ptr %MEMORY, align 4
  ret ptr %memory

bb_268441161:                                     ; preds = %bb_0
  %v73 = load i32, ptr %NEXT_PC, align 4
  store i32 %v73, ptr %PC, align 4
  %v74 = add i32 %v73, 2
  store i32 %v74, ptr %NEXT_PC, align 4
  %AL9 = load i32, ptr %EAX, align 4
  %AL = load i32, ptr %EAX, align 4
  %v75 = load ptr, ptr %MEMORY, align 4
  %v76 = call ptr @_ZN12_GLOBAL__N_13XORI3RnWIjE2RnIjLb1EES4_EEP6MemoryS6_R5StateT_T0_T1_(ptr %v75, ptr %state, ptr %EAX, i32 %AL9, i32 %AL)
  store ptr %v76, ptr %MEMORY, align 4
  store i32 %v74, ptr %PC, align 4
  %v77 = add i32 %v74, 1
  store i32 %v77, ptr %NEXT_PC, align 4
  %v78 = load ptr, ptr %MEMORY, align 4
  %v79 = call ptr @_ZN12_GLOBAL__N_13RETEP6MemoryR5State3RnWIjE(ptr %v78, ptr %state, ptr %NEXT_PC)
  store ptr %v79, ptr %MEMORY, align 4
  ret ptr %memory
}

attributes #0 = { noduplicate noinline nounwind optnone "frame-pointer"="all" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { alwaysinline mustprogress nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }
attributes #3 = { alwaysinline mustprogress nofree norecurse nosync nounwind willreturn memory(argmem: write) "frame-pointer"="all" "min-legal-vector-width"="0" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }

!llvm.ident = !{!0, !0, !0, !0}
!llvm.module.flags = !{!1, !2, !3, !4, !5}

!0 = !{!"clang version 18.1.8"}
!1 = !{i32 1, !"NumRegisterParameters", i32 0}
!2 = !{i32 1, !"wchar_size", i32 4}
!3 = !{i32 7, !"frame-pointer", i32 2}
!4 = !{i32 7, !"Dwarf Version", i32 5}
!5 = !{i32 2, !"Debug Info Version", i32 3}
!6 = !{!"base.helper.semantics"}
!7 = !{[7 x i8] c"DSBASE\00"}
!8 = !{[3 x i8] c"CL\00"}
!9 = !{[4 x i8] c"EDI\00"}
!10 = !{[4 x i8] c"ESI\00"}
!11 = !{[4 x i8] c"EAX\00"}
!12 = !{[7 x i8] c"SSBASE\00"}
!13 = !{[4 x i8] c"ESP\00"}
!14 = !{[4 x i8] c"EDX\00"}
!15 = !{[3 x i8] c"PC\00"}

; ModuleID = 'hexcore_rellic_validation'
source_filename = "validation.c"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-windows-msvc"

; Reference IR for validating the Rellic decompiler.
; Expected pseudo-C output:
;   int add(int a, int b) { return a + b; }
;   int sub(int a, int b) { return a - b; }

define i32 @add(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  ret i32 %sum
}

define i32 @sub(i32 %a, i32 %b) {
entry:
  %diff = sub i32 %a, %b
  ret i32 %diff
}

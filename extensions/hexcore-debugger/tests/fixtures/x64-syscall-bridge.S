/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
	.global _start
	.section .text
_start:
	/* brk(0) */
	mov $12, %rax
	xor %rdi, %rdi
	syscall

	/* mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) */
	mov $9, %rax
	xor %rdi, %rdi
	mov $4096, %rsi
	mov $3, %rdx
	mov $0x22, %r10
	mov $-1, %r8
	xor %r9, %r9
	syscall

	/* arch_prctl(ARCH_SET_FS, mmap_result) */
	mov %rax, %rsi
	mov $0x1002, %rdi
	mov $158, %rax
	syscall

	/* write(1, "OK", 2) */
	mov $1, %rax
	mov $1, %rdi
	lea message(%rip), %rsi
	mov $2, %rdx
	syscall

	/* Unknown syscall must retain 999 and return -ENOSYS. */
	mov $999, %rax
	syscall

	/* exit(7) */
	mov $60, %rax
	mov $7, %rdi
	syscall

	.section .rodata
message:
	.ascii "OK"

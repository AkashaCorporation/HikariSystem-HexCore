;---------------------------------------------------------------------------------------------
;  Copyright (c) Akasha Corporation. All rights reserved.
;  Licensed under the MIT License. See License.txt in the project root for license information.
;---------------------------------------------------------------------------------------------

OPTION CASEMAP:NONE

.code

entrypoint PROC
    xor eax, eax
    ret
entrypoint ENDP

; Keep the hidden function at .text+0x37. It is intentionally unreferenced,
; unexported, unaligned, outside .pdata, and has no conventional prologue.
DB 34h DUP (0CCh)

hidden_function LABEL BYTE
DB 041h, 031h, 0D2h                    ; xor r10d, r10d
DB 08Dh, 044h, 051h, 007h              ; lea eax, [rcx+rdx*2+7]
DB 045h, 085h, 0C0h                    ; test r8d, r8d
DB 041h, 00Fh, 045h, 0C0h              ; cmovne eax, r8d
DB 0C3h                                ; ret
hidden_function_end LABEL BYTE

; Valid adjacent bytes are a negative boundary control and are not part of the
; hidden function.
adjacent_control LABEL BYTE
DB 048h, 083h, 0C0h, 07Fh, 0C3h       ; add rax, 0x7f; ret
adjacent_control_end LABEL BYTE

END

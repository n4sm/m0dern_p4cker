 
; * This file is part of the nasm distribution (https://github.com/n4sm/m0dern_p4cker/).
; * Copyright (c) 2019 nasm.
; * 
; * This program is free software: you can redistribute it and/or modify  
; * it under the terms of the GNU General Public License as published by  
; * the Free Software Foundation, version 3.
; *
; * This program is distributed in the hope that it will be useful, but 
; * WITHOUT ANY WARRANTY; without even the implied warranty of 
; * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
; * General Public License for more details.
; *
; * You should have received a copy of the GNU General Public License 
; * along with this program. If not, see <http://www.gnu.org/licenses/>.

section .text
    global _start

_start:
    push rdx
    mov rdi, 0x4444444444444444 ; v_addr
    mov rsi, 0x5555555555555555 ; len
    mov rdx, 0x7 ; RWX
    mov rax, 10 ; mprotect
    syscall
    mov rcx, 0x2222222222222222
    mov rsi, 0x3333333333333333
    mov rdx, 0x6666666666666666 ; random_int
    mov rdi, rsi
    jmp _loop

_loop:
    cmp rcx, 0x0
    je _end
    lodsb
    not al
    xor al, dl
    stosb
    loop _loop

_end:
    pop rdx
    mov rax, 0x1111111111111111
    jmp rax

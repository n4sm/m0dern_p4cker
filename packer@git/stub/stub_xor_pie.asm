
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
    lea r12, [rel $]
    ; sub r12, 2
    push rdx
    ; push rip ; rip - 3
    mov r8, 0x3333333333333333 ; txt_end
    ; sub r12, 2
    ; sub r12, r8
    ; mov rdi, r12 ; v_addr
    sub r12, r8 ; r12 == base address
    ; mov rdi, 0x444444444444444 ; txt_offset
    ; add rdi, r12
    mov rdi, r12
    mov rsi, 0x5555555555555555 ; len
    mov rdx, 0x7 ; RWX
    mov rax, 10 ; mprotect
    syscall
    mov rdi, 0x7777777777777777 ; ptr_text
    add rdi, r12
    push r12
    mov rcx, 0x2222222222222222 ; change pas pour le pie (len)
    mov rdx, 0x6666666666666666 ; nb aléatoire
    mov rsi, rdi
    ; push rdi
    jmp _loop

_loop:
    cmp rcx, 0x0
    je _end
    lodsb
    xor al, dl
    stosb
    loop _loop

_end:
    pop rax ; base_addr
    mov rcx, 0x1111111111111111
    add rax, rcx
    pop rdx
    jmp rax 

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
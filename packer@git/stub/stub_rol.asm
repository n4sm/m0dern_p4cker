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
    mov rdx, 0x6666666666666666
    mov rdi, rsi
    mov r14, 0x8888888888888888 ; x pour le rol
    jmp _loop

_loop:
    cmp rcx, 0x0
    je _end
    lodsb
    not al
    xor al, dl
    xor al, r14b
    not r14b
    stosb
    loop _loop

_end:
    pop rdx
    mov rax, 0x1111111111111111
    jmp rax
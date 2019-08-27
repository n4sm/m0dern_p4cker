section .text
    global _start

_start:
    push rdx
    mov rdi, 0x4444444444444444 ; v_addr
    mov rsi, 0x5555555555555555 ; len
    mov rdx, 0x7 ; RWX
    mov rax, 10 ; mprotect
    syscall
    mov rcx, rsi
    mov rsi, rdi
    mov rdx, 0x6666666666666666
    mov rdi, rsi
    jmp _loop

_loop:
    cmp rcx, 0x0
    je _end
    lodsb
    xor al, dl
    stosb
    loop _loop

_end:
    pop rdx
    mov rax, 0x1111111111111111
    jmp rax
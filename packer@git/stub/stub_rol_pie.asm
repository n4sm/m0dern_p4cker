section .text
    global _start

_start: 
    lea r12, [rel $]
    push rdx
    mov r8, 0x3333333333333333 ; txt_end
    sub r12, r8 ; r12 == base address
    mov rdi, r12
    mov rsi, 0x5555555555555555 ; len
    mov rdx, 0x7 ; RWX
    mov rax, 10 ; mprotect
    syscall
    mov rdi, 0x7777777777777777 ; ptr_text
    add rdi, r12
    mov r14, 0x2222222222222222 ; change pas pour le pie (len)
    mov rdx, 0x6666666666666666 ; nb aléatoire
    mov rcx, 0x8888888888888888 ; x pour le rol
    mov rsi, rdi
    ; push rdi
    cld
    jmp _loop

_loop:
    cmp r14, 0x0
    je _end
    lodsb
    not al
    xor al, dl
    ; rol al, cl
    ; and al, cl
    xor al, cl
    not cl
    stosb
    dec r14
    jmp _loop

_end:
    mov rax, r12 ; base_addr
    mov rcx, 0x1111111111111111
    add rax, rcx
    pop rdx
    jmp rax 
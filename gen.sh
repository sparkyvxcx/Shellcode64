#!/bin/sh

# Simple bash script to generate shellcode from assembly code
# > bash gen.sh file.asm

# > nasm -felf64 execve_sh.nasm -o a.out

nasm -felf64 $1 -o a.out && objdump -D -M intel | grep -e " 00" && echo -e "\nShellcode [\033[91mnull byte!\033[0m]:\n" ||

echo -e "Shellcode [\033[92mOK\033[0m]:\n"

for i in $(objdump -D -M intel | grep "^ " | cut -f2)
do
	echo -n "\x${i}"
done

rm a.out
echo

#!/bin/sh

# Simple bash script to generate shellcode
# bash gen.sh file.o

for i in $(objdump -D $1 -M intel | grep "^ " | cut -f2)
do
	echo -n "\x${i}"
done
echo

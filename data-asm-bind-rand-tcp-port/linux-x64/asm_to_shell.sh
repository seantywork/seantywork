#!/bin/bash

nasm -f elf64 hack.asm -o hack.o

ld hack.o -o hack.asm.out

objdump -D hack.asm.out
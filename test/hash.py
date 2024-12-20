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


if __name__ == "__main__":
    example_message = "ASHsudhajn"
    hashed_value = hash_string(example_message)
    print(f"const unsigned int targetHash = {hashed_value};")
    print(f"const char known[] = {{{to_char_array(example_message[:-4])}}};")
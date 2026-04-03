from os import PathLike


def get_file_as_bytes(f: PathLike | str) -> bytes:
    with open(f, "rb") as infile:
        base_rom_bytes = bytes(infile.read())
    return base_rom_bytes


def get_text_file(f: PathLike | str) -> str:
    with open(f, "rt") as infile:
        text = infile.read()
    return text


def get_text_file_lines(f: PathLike | str) -> list[str]:
    with open(f, "rt") as infile:
        text = infile.readlines()
    return text


def padding_with_zeros(number: int, digits: int) -> str:
    s = ""
    for d in reversed(range(digits)):
        s += str((number//10**d)%10)
    return s


def bytes_to_int(obj: bytes | bytearray, signed=False) -> int:
    if type(obj) is bytes or type(obj) is bytearray:
        return int.from_bytes(obj, "little", signed=signed)
    return int(obj)


def bytes_from_int(value: int, length: int, signed=False) -> bytes:
    return value.to_bytes(length, "little", signed=signed)


def hash_name(name: str) -> int:
    _hash = 0
    for letter in name:
        _hash = ((131 * _hash) % 0x100000000) ^ letter.encode()[0]
    return _hash


def vm_param_str(value: int, size: int) -> str:
    if 0x8000 <= value < 0x8100 or 0x4000 <= value <= 0x4200:
        return hex(value)
    elif size == 2 and value & 0x8000:
        return str(value-0x10000)
    elif size == 4 and value & 0x80000000:
        return str(value-0x100000000)
    elif size == 8 and value & 0x8000000000000000:
        return str(value-0x10000000000000000)
    else:
        return str(value)


def print_bytes_block(data: bytes, indent=0) -> list[str]:
    lines = []
    for i in range(0, len(data), 16):
        if i % 0x80 == 0:
            lines.append(f"{'':{indent}}// {hex(i)}")
        line: bytes = data[i:i+16]
        lines.append(f"{'':{indent}}" + "   ".join(line[i:i+4].hex(" ") for i in range(0, len(line), 4)))
    return lines


def read_bytes_block(text: list[str]) -> bytearray:
    data = bytearray()
    for line in text:
        line_data = bytearray()
        parts = line.split()
        for part in parts:
            if part[:2] == "//":
                break
            if len(part) > 2:
                raise Exception("Raw byte blocks have to be written in single bytes")
            line_data.append(int(part, 16))
        data.extend(line_data)
    return data


# Contains code based on
#   Universal Pokémon Randomizer FVX, copyright (C) foxoftheasterisk, voliol, Ajarmar, Dabomstew
#   pk3DS, copyright (C) Kaphotics
#   pkNX, copyright (C) Kaphotics
#   poketools, copyright (C) FireyFly
#
# Ported to Python by BlastSlimey
# Licensed under GPL v3
def decompress_bytes(data: bytearray, length: int) -> bytearray:
    code = bytearray(length)
    i = j = x = f = 0
    while i < len(code):
        b = data[f]
        f += 1
        v = b & 0x7F
        j += 1
        if j == 1:
            x = ((((1 if v >> 6 == 0 else 0) -1) << 6) | v)
        else:
            x = (x << 7) | (v & 0xFF)
        if (b & 0x80) != 0:
            continue
        code[i:i+4] = [x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF]
        i += 4
        j = 0
    return bytearray(code)


# Contains code based on
#   Universal Pokémon Randomizer FVX, copyright (C) foxoftheasterisk, voliol, Ajarmar, Dabomstew
#   pk3DS, copyright (C) Kaphotics
#   pkNX, copyright (C) Kaphotics
#   poketools, copyright (C) FireyFly
#
# Ported to Python by BlastSlimey
# Licensed under GPL v3
def compress_bytes(data: bytearray | bytes) -> bytearray | None:

    if data is None or len(data) % 4:
        return None

    pointer = 0
    ret = bytearray()
    while pointer < len(data):

        byt = bytearray()
        instruction = bytes_to_int(data[pointer:pointer+4])
        sign = (instruction & 0x80000000) > 0

        shadow = instruction ^ 0xFFFFFFFF if sign else instruction
        while True:
            least7 = instruction & 0b01111111
            byte_val = least7 & 0xFF
            if len(byt):
                byte_val |= 0x80
            byt += bytes_from_int(byte_val, 1)
            instruction >>= 7
            shadow >>= 7
            # print(shadow)
            if shadow == 0:
                break

        if len(byt) < 5:
            sign_bit = 0x40 if sign else 0
            if (byt[-1] & 0x40) != sign_bit:
                byt += bytes_from_int(0xFF if sign else 0x80, 1)

        i = 0
        while i < len(byt) / 2:
            byt[i], byt[-(i + 1)] = byt[-(i + 1)], byt[i]
            i += 1

        ret += byt
        pointer += 4

    return ret

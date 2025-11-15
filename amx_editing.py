# This python script contains only explanations for how to use it (located at the bottom)
# Other than that, there's no documentation about AMX scripting in this file


import array
import re
import os
import zipfile
from itertools import chain
from os import PathLike
from typing import NamedTuple, Self, Any, Literal
import pathlib
from enum import Enum


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


def to_int(obj) -> int:
    if type(obj) is bytes or type(obj) is bytearray:
        return int.from_bytes(obj, "little")
    return int(obj)


def vm_param_str(value: int, size: int) -> str:
    if 0x8000 <= value < 0x8100 or 0x4000 <= value <= 0x4200:
        return hex(value)
    elif size == 2 and value & 0x8000:
        return str(value-0x10000)
    elif size == 4 and value & 0x80000000:
        return str(value-0x100000000)
    else:
        return str(value)


def from_int(value: int, length: int) -> bytes:
    return value.to_bytes(length, "little")


# Contains code based on
#   Universal Pokémon Randomizer FVX, copyright (C) foxoftheasterisk, voliol, Ajarmar, Dabomstew
#   pk3DS, copyright (C) Kaphotics
#   pkNX, copyright (C) Kaphotics
#   poketools, copyright (C) FireyFly
#
# Ported to Python by BlastSlimey
# Licensed under GPL v3
class AMX:
    code_section: bytearray
    data_section: bytearray
    allocated_memory: int
    main_address: int
    public_functions: list[tuple[int, int]]
    native_functions: dict[int, int]
    libraries: dict[int, int]
    public_variables: list[tuple[int, int]]
    public_tags: list[tuple[int, int]]
    overlays: bytes  # unknown structure
    symbol_names: bytes  # unclear structure

    amx_magic = 0x0A0AF1E0
    amx_magic_debug = 0x0A0AF1EF

    amx_commands: dict[int, tuple[str, ...]]
    script_commands: dict[int, str]

    def __init__(self, data: bytearray | list[str], script_num=None):
        self.amx_commands = {}
        self.script_commands = {}
        for line in get_text_file_lines("opcodes.txt"):
            parts = line.split()
            if len(parts) and parts[0][:2] == "OP":
                self.amx_commands[int(parts[1])] = (parts[0], *parts[3:])
        for line in get_text_file_lines("commands.txt"):
            parts = line.split()
            if len(parts) == 1:
                _hash = 0
                for letter in parts[0]:
                    _hash = ((131 * _hash) % 0x100000000) ^ letter.encode()[0]
                if _hash not in self.script_commands:
                    self.script_commands[_hash] = parts[0]
                else:
                    raise Exception(f"Duplicate hash: {parts[0]} {self.script_commands[_hash]}")
        if isinstance(data, list):
            self.assemble(data)
        elif script_num is None:
            self._read_header_and_decompress(data)
        elif type(script_num) is int:
            found = 0
            for i in range(len(data)-3):
                val = to_int(data[i:i+4])
                if val == self.amx_magic:
                    if found == script_num:
                        length = to_int(data[i-4:i])
                        self._read_header_and_decompress(data[i-4:i-4+length])
                        break
                    else:
                        found += 1
            else:
                raise Exception("The file contains less scripts than script_num")
        else:
            raise Exception("script_num parameter has to either be an integer or None")

    def _read_header_and_decompress(self, enc_data: bytearray):
        length = to_int(enc_data[:4])
        magic = to_int(enc_data[4:8])
        if magic != self.amx_magic:
            raise IOError()

        code_section_start = to_int(enc_data[12:16])
        data_section_start = to_int(enc_data[16:20])
        heap_start = to_int(enc_data[20:24])
        self.allocated_memory = to_int(enc_data[24:28])
        self.main_address = to_int(enc_data[28:32])

        public_functions_start = to_int(enc_data[32:36])
        native_functions_start = to_int(enc_data[36:40])
        libraries_start = to_int(enc_data[40:44])
        public_variables_start = to_int(enc_data[44:48])
        public_tags_start = to_int(enc_data[48:52])
        overlays_start = to_int(enc_data[52:56])
        symbol_names_start = to_int(enc_data[56:60])

        header_data = enc_data[:code_section_start]
        dec_data = self._decompress_bytes(enc_data[code_section_start:length], heap_start - code_section_start)
        self.code_section = dec_data[:data_section_start-code_section_start]
        self.data_section = dec_data[data_section_start-code_section_start:]

        self.public_functions = [
            (to_int(header_data[i:i+4]), to_int(header_data[i+4:i+8]))
            for i in range(public_functions_start, native_functions_start, 8)
        ]
        self.native_functions = {
            (i-native_functions_start)//8: to_int(header_data[i+4:i+8])
            for i in range(native_functions_start, libraries_start, 8)
        }
        self.libraries = {
            (i - libraries_start) // 8: to_int(header_data[i+4:i+8])
            for i in range(libraries_start, public_variables_start, 8)
        }
        self.public_variables = [
            (to_int(header_data[i:i + 4]), to_int(header_data[i + 4:i + 8]))
            for i in range(public_variables_start, public_tags_start, 8)
        ]
        self.public_tags = [
            (to_int(header_data[i:i + 4]), to_int(header_data[i + 4:i + 8]))
            for i in range(public_tags_start, overlays_start, 8)
        ]
        self.overlays = header_data[overlays_start:symbol_names_start]
        self.symbol_names = header_data[symbol_names_start:header_data.rfind(b'\x3f\0\0\0')]

    @staticmethod
    def _decompress_bytes(data: bytearray, length: int) -> bytearray:
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

    class ByteStream:
        buffer: list[bytes | bytearray]

        def __init__(self):
            self.buffer = []

        def write(self, data: bytes | bytearray):
            self.buffer.append(data)

        def to_bytearray(self) -> bytearray:
            return bytearray(chain(*self.buffer))

    class ByteBuffer:
        buffer: bytearray
        pointer: int

        def __init__(self, capacity: int | None, pointer: int, wrap: bytearray | None):
            if wrap is None:
                self.buffer = bytearray(capacity)
            else:
                self.buffer = wrap
            self.pointer = pointer

        def put_int(self, value: int):
            self.buffer[self.pointer:self.pointer+4] = from_int(value, 4)
            self.pointer += 4

        def put_short(self, value: int):
            self.buffer[self.pointer:self.pointer+2] = from_int(value, 2)
            self.pointer += 2

        def put(self, value: bytearray | bytes):
            self.buffer[self.pointer:self.pointer+len(value)] = value
            self.pointer += len(value)

        def flip(self):
            self.buffer = self.buffer[:self.pointer]
            self.pointer = 0

        def limit(self) -> int:
            return len(self.buffer)

        def get_int(self, pos: int) -> int:
            return to_int(self.buffer[pos:pos+4])

    def get_bytes(self) -> bytes:

        bbuf = AMX.ByteBuffer(self.length*2, 0, None)

        bbuf.put_int(0)  # Put compressed length later
        bbuf.put_int(self.amx_magic)
        bbuf.put_short(0x1c)
        bbuf.put_short(8)
        bbuf.put_int(0)  # Put header length later
        bbuf.put_int(0)  # Put header and code section length later
        bbuf.put_int(0)  # Put whole decompressed length later
        bbuf.put_int(self.allocated_memory)
        bbuf.put_int(self.main_address)
        self._write_tables(bbuf)
        bbuf.buffer[12:16] = from_int(bbuf.pointer, 4)
        bbuf.buffer[16:20] = from_int(bbuf.pointer + len(self.code_section), 4)
        bbuf.buffer[20:24] = from_int(bbuf.pointer + len(self.code_section) + len(self.data_section), 4)
        bbuf.put(self._compress_script(self.code_section + self.data_section))
        bbuf.flip()
        bbuf.put_int(bbuf.limit())

        return bytes(bbuf.buffer)

    def _write_tables(self, bbuf: ByteBuffer):  # TODO
        bbuf.put_int(0)
        bbuf.put_int(0)
        bbuf.put_int(0)
        bbuf.put_int(0)
        bbuf.put_int(0)
        bbuf.put_int(0)
        bbuf.put_int(0)
        bbuf.buffer[0x20:0x24] = from_int(bbuf.pointer, 4)

        for address, name in self.public_functions:
            bbuf.put_int(address)
            bbuf.put_int(name)
        bbuf.buffer[0x24:0x28] = from_int(bbuf.pointer, 4)

        native_functions = [0] * max(self.native_functions.keys())
        for index, name in self.native_functions.items():
            native_functions[index] = name
        for name in native_functions:
            bbuf.put_int(0)
            bbuf.put_int(name)
        bbuf.buffer[0x28:0x2c] = from_int(bbuf.pointer, 4)

        libraries = [0] * max(self.libraries.keys())
        for index, name in self.libraries.items():
            libraries[index] = name
        for name in libraries:
            bbuf.put_int(0)
            bbuf.put_int(name)
        bbuf.buffer[0x2c:0x30] = from_int(bbuf.pointer, 4)

        for address, name in self.public_variables:
            bbuf.put_int(address)
            bbuf.put_int(name)
        bbuf.buffer[0x30:0x34] = from_int(bbuf.pointer, 4)

        for address, name in self.public_tags:
            bbuf.put_int(address)
            bbuf.put_int(name)
        bbuf.buffer[0x34:0x38] = from_int(bbuf.pointer, 4)

        bbuf.put(self.overlays)
        bbuf.put(self.symbol_names)
        bbuf.put(b'\x3f\0\0\0')

    def _compress_script(self, data: bytearray) -> bytearray | None:  # TODO
        if data is None or len(data) % 4 != 0:
            return None
        inbuf = AMX.ByteBuffer(None, 0, data)

        out = AMX.ByteStream()

        while inbuf.pointer < len(data):
            self._compress_bytes(inbuf, out)

        return out.to_bytearray()

    @staticmethod
    def _compress_bytes(in_buf: ByteBuffer, out: ByteStream):  # TODO
        byt = bytearray()
        instruction = in_buf.get_int(in_buf.pointer)
        sign = (instruction & 0x80000000) > 0

        shadow = instruction ^ 0xFFFFFFFF if sign else instruction
        while True:
            least7 = instruction & 0b01111111
            byte_val = least7 & 0xFF
            if not len(byt):
                byte_val |= 0x80
            byt += from_int(byte_val, 1)
            instruction >>= 7
            shadow >>= 7
            if shadow == 0:
                break

        if len(byt) < 5:
            sign_bit = 0x40 if sign else 0
            if (byt[-1] & 0x40) != sign_bit:
                byt += from_int(0xFF if sign else 0x80, 1)

        for i in range(len(byt)//2):
            byt[i], byt[-(i+1)] = byt[-(i+1)], byt[i]

        ret = byt[:]
        in_buf.pointer += 4
        out.write(ret)

    def disassemble(self) -> str:  # TODO
        return "\n".join([
            *self._print_header(),
            "",
            "",
            "",
            *self._print_disassemble(),
            "",
            "",
            "",
            "Data:",
            *self.print_bytes_block(self.data_section, 4, 7)
        ])

    def get_sysreq(self, number: int) -> str:
        if number in self.script_commands:
            return self.script_commands[number]
        else:
            return f"  #{number}"

    def get_sysreq_param(self, number: int) -> str:
        if self.native_functions[number] in self.script_commands:
            return self.script_commands[self.native_functions[number]]
        else:
            return str(number)

    @staticmethod
    def print_bytes_block(data: bytes, indent=0, address_length=3) -> list[str]:
        lines = []
        for i in range(0, len(data), 16):
            line: bytes = data[i:i+16]
            string = f"{' ' * indent}{hex(i):{address_length}}"
            for block in (line[i:i+4] for i in range(0, len(line), 4)):
                block: bytes
                string += "   " + block.hex(" ")
            lines.append(string)
        return lines


    def _print_header(self) -> list[str]:
        lines = [
            f"Allocated memory: {self.allocated_memory} ({hex(self.allocated_memory)})",
            "Main function: funcmain",
        ]
        if self.public_functions:
            lines.append("")
            lines.append("Public functions:")
            for address, name in self.public_functions:
                lines.append(f"    {hex(address)} {self.get_sysreq(name)}")
        if self.native_functions:
            lines.append("")
            lines.append("Native functions:")
            for index, name in self.native_functions.items():
                lines.append(f"    {index} {self.get_sysreq(name)}")
        if self.libraries:
            lines.append("")
            lines.append("Libraries:")
            for index, name in self.libraries.items():
                lines.append(f"    {index} {self.get_sysreq(name)}")
        if self.public_variables:
            lines.append("")
            lines.append("Public variables:")
            for address, name in self.public_variables:
                lines.append(f"    {hex(address)} {self.get_sysreq(name)}")
        if self.public_tags:
            lines.append("")
            lines.append("Public tags:")
            for address, name in self.public_tags:
                lines.append(f"    {hex(address)} {self.get_sysreq(name)}")
        if self.overlays:
            lines.append("")
            lines.append("Overlays:")
            lines.extend(self.print_bytes_block(self.overlays, 4))
        if self.symbol_names:
            lines.append("")
            lines.append("Symbol names:")
            lines.extend(self.print_bytes_block(self.symbol_names, 4))
        return lines

    class ByteType(Enum):
        UNKNOWN = 0
        RAW = 1
        OPCODE = 2
        PARAM = 3

    def _print_disassemble(self) -> list[str]:
        structure: list[AMX.ByteType] = [AMX.ByteType.UNKNOWN] * (len(self.code_section) // 4)
        links: dict[int, str] = {self.main_address: "funcmain"}
        lines = ["Code:"]

        # structure analysis
        pointer = 0
        while pointer < len(self.code_section):
            instr = to_int(self.code_section[pointer:pointer+2])
            if instr not in self.amx_commands:
                structure[pointer//4] = AMX.ByteType.RAW
            else:
                structure[pointer//4] = AMX.ByteType.OPCODE
                opcode_ptr = pointer
                for param in self.amx_commands[instr][1:]:
                    pointer += 4
                    structure[pointer // 4] = AMX.ByteType.PARAM
                    if param in ("offset", "call_offset"):
                        offset = to_int(self.code_section[pointer:pointer+4])
                        offset = offset - 0x100000000 if offset & 0x80000000 else offset
                        if (opcode_ptr+offset) not in links:
                            links[opcode_ptr+offset] = f"{'lbl' if param == 'offset' else 'func'}{len(links)}"
                if instr == 0x82:  # OP_CASETBL
                    case_count = to_int(self.code_section[pointer+4:pointer+8])
                    structure[(pointer//4)+1:(pointer//4)+1+(case_count*2)] = [AMX.ByteType.PARAM] * (2+(case_count*2))
                    for _ in range(case_count+1):
                        pointer += 4
                        offset = to_int(self.code_section[pointer+4:pointer+8])
                        offset = offset - 0x100000000 if offset & 0x80000000 else offset
                        if (pointer+offset) not in links:
                            links[pointer+offset] = f"lbl{len(links)}"
                        pointer += 4
            pointer += 4
        for address in links:
            if structure[address//4] == AMX.ByteType.PARAM:
                structure[address//4] = AMX.ByteType.RAW

        # Writing lines
        pointer = 0
        while pointer < len(self.code_section):
            instr = to_int(self.code_section[pointer:pointer+2])
            opcode_param = to_int(self.code_section[pointer+2:pointer+4])
            if pointer in links:
                lines.append("")
                lines.append(f"{'  ' if links[pointer].startswith('func') else '   '}#{links[pointer]} ({hex(pointer)})")
            if structure[pointer//4] == AMX.ByteType.RAW:
                lines.append(f"    {'raw':17} {self.code_section[pointer:pointer+4].hex(' ')}")
            else:
                line = f"    {self.amx_commands[instr][0]:17} {vm_param_str(opcode_param, 2)}"
                opcode_ptr = pointer
                for param in self.amx_commands[instr][1:]:
                    pointer += 4
                    if param in ("offset", "call_offset"):
                        offset = to_int(self.code_section[pointer:pointer+4])
                        offset = offset - 0x100000000 if offset & 0x80000000 else offset
                        line += " " + links[opcode_ptr+offset]
                    else:
                        line += " " + vm_param_str(to_int(self.code_section[pointer:pointer+4]), 4)
                if instr == 0x82:  # OP_CASETBL
                    case_count = to_int(self.code_section[pointer+4:pointer+8])
                    for _ in range(case_count+1):
                        pointer += 4
                        value = to_int(self.code_section[pointer:pointer+4])
                        offset = to_int(self.code_section[pointer+4:pointer+8])
                        offset = offset - 0x100000000 if offset & 0x80000000 else offset
                        line += f" {vm_param_str(value, 4)} {links[pointer+offset]}"
                        pointer += 4
                elif instr == 0x87:  # OP_SYSREQ_N
                    native = to_int(self.code_section[pointer+4:pointer+8])
                    pop_count = to_int(self.code_section[pointer+8:pointer+12])
                    line += f" {self.get_sysreq_param(native)} {pop_count}"
                    pointer += 8
                lines.append(line)
            pointer += 4

        return lines

    def _print_disassemble_old(self) -> list[str]:
        label_count = 0
        lines = []
        bad_jumps = []
        labels: dict[int, str] = {}  # line number to label name
        labels[(to_int(self.extra_data[:4]))//4] = "lblmain"

        i = 0
        while i < self.script_movement_start-self.script_instr_start:
            instr = to_int(self.dec_data[i:i+2])
            if instr in self.amx_commands:
                value = to_int(self.dec_data[i+2:i+4])
                if (i + self.script_instr_start) % 0x20 == 0:
                    lines.append(f"{hex(i + self.script_instr_start):12} {self.amx_commands[instr][0]:15} {vm_param_str(value, 2)}")
                else:
                    lines.append(f"{'':12} {self.amx_commands[instr][0]:15} {vm_param_str(value, 2)}")
                if self.amx_commands[instr][1] == "#":
                    offset = to_int(self.dec_data[i+4:i+8])
                    offset = offset - 0x100000000 if offset & 0x80000000 else offset
                    if (i + offset)//4 not in labels:
                        labels[(i + offset)//4] = lbl = f"lbl{label_count}"
                        label_count += 1
                    else:
                        lbl = labels[(i + offset)//4]
                    lines.append(f"{'':12} {'':15} {lbl}")
                    i += 4
                elif self.amx_commands[instr][1] == "p":
                    lines.append(f"{'':12} {'':15} {vm_param_str(to_int(self.dec_data[i+4:i+8]), 4)}")
                    i += 4
                elif self.amx_commands[instr][1].isnumeric():
                    for _ in range(int(self.amx_commands[instr][1])):
                        lines.append(f"{'':12} {'':15} {vm_param_str(to_int(self.dec_data[i+4:i+8]), 4)}")
                        i += 4
                elif instr == 0x82:  # OP_CASETBL
                    cases = to_int(self.dec_data[i+4:i+8])
                    lines.append(f"{'':12} {'':15} {vm_param_str(cases, 4)}")
                    lines.append(f"{'':12} {'':15} {vm_param_str(to_int(self.dec_data[i+8:i+12]), 4)}")
                    i += 8
                    for _ in range(cases*2):
                        lines.append(f"{'':12} {'':15} {vm_param_str(to_int(self.dec_data[i+4:i+8]), 4)}")
                        i += 4
            else:
                lines.append(f"{'':12} {'':15} x {self.dec_data[i:i+4].hex(' ')}")
            i += 4
        for line_num, lbl in labels.items():
            if line_num in range(len(lines)):
                lines[line_num] = f"{lbl:12}{lines[line_num][12:]}"
            else:
                bad_jumps.append(f"Bad jump {lbl} to {hex(line_num*4+self.script_instr_start)}")

        return lines + (["", *bad_jumps] if bad_jumps else [])

    def assemble(self, text_lines: list[str]):
        pass


if __name__ == "__main__":

    # This is just an example on how to use this python script
    disassemble = True
    if disassemble:
        with open(f"a031 analysis/17.xamx", "wt") as f:
            data = bytearray(get_file_as_bytes(f"garcs/a031_/17.bin"))
            # The AMX() constructor has an optional "script_num" argument that is needed for files
            #   that contain more data than just one AMX script, i.e. it contains extra data
            #   at the beginning/end, there are more than one AMX scripts in it, or both
            disassambled_text = AMX(data).disassemble()
            f.write(disassambled_text)

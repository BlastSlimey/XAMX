# This python script contains only explanations for how to use it (located at the bottom)
# Other than that, there's no documentation about AMX scripting in this file


from itertools import chain
from os import PathLike
from enum import Enum
from typing import ClassVar


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


def to_int_signed(obj) -> int:
    if type(obj) is bytes or type(obj) is bytearray:
        return int.from_bytes(obj, "little", signed=True)
    return int(obj)


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


def from_int(value: int, length: int, signed=False) -> bytes:
    return value.to_bytes(length, "little", signed=signed)


def hash_name(name: str) -> int:
    _hash = 0
    for letter in name:
        _hash = ((131 * _hash) % 0x100000000) ^ letter.encode()[0]
    return _hash


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
        parts = line.split()
        for part in parts:
            if part[:2] == "//":
                break
            if len(part) > 2:
                raise Exception("Raw byte blocks have to be written in single bytes")
            data.append(int(part, 16))
    return data


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
    cell_size: int
    def_size: int
    public_functions: list[tuple[int, int]]
    native_functions: dict[int, int]
    libraries: dict[int, int]
    public_variables: list[tuple[int, int]]
    public_tags: list[tuple[int, int]]
    overlays: bytes  # unknown structure
    symbol_names: bytes  # unclear structure

    amx_magic_32: ClassVar[bytes] = b'\xe0\xf1\x0a\x0a'
    amx_magic_64: ClassVar[bytes] = b'\xe1\xf1\x0a\x0a'

    amx_commands: dict[int, tuple[str, ...]]
    amx_command_ids: dict[str, int]
    script_commands: dict[int, str]

    def __init__(self, data: bytearray | list[str]):
        self.amx_commands = {}
        self.amx_command_ids = {}
        self.script_commands = {}
        for line in get_text_file_lines("opcodes.txt"):
            parts = line.split()
            if len(parts) and parts[0][:2] == "OP":
                self.amx_commands[int(parts[1])] = (parts[0], *parts[3:])
                self.amx_command_ids[parts[0]] = int(parts[1])
        for line in get_text_file_lines("commands.txt"):
            parts = line.split()
            if len(parts) and parts[0][:2] != "//":
                _hash = hash_name(parts[0])
                if _hash not in self.script_commands:
                    self.script_commands[_hash] = parts[0]
                else:
                    raise Exception(f"Duplicate hash: {parts[0]} {self.script_commands[_hash]}")
        if isinstance(data, list):
            self._assemble_text(data)
        elif isinstance(data, bytearray):
            self._read_header_and_decompress(data)
        else:
            raise Exception("Bad argument type")

    def _read_header_and_decompress(self, enc_data: bytearray):
        length = to_int(enc_data[:4])
        if enc_data[4:8] == self.amx_magic_32:
            self.cell_size = 4
        elif enc_data[4:8] == self.amx_magic_64:
            self.cell_size = 8
        else:
            raise IOError()

        self.def_size = to_int(enc_data[10:12])
        code_section_start = to_int(enc_data[12:16])
        data_section_start = to_int(enc_data[16:20])
        heap_start = to_int(enc_data[20:24])
        self.allocated_memory = to_int(enc_data[24:28])
        self.main_address = to_int_signed(enc_data[28:32])

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
            (to_int(header_data[i:i + self.cell_size]), to_int(header_data[i+self.cell_size:i+self.def_size]))
            for i in range(public_functions_start, native_functions_start, self.def_size)
        ]
        self.native_functions = {
            (i-native_functions_start) // self.def_size: to_int(header_data[i+self.cell_size:i+self.def_size])
            for i in range(native_functions_start, libraries_start, self.def_size)
        }
        self.libraries = {
            (i - libraries_start) // self.def_size: to_int(header_data[i+self.cell_size:i+self.def_size])
            for i in range(libraries_start, public_variables_start, self.def_size)
        }
        self.public_variables = [
            (to_int(header_data[i:i + self.cell_size]), to_int(header_data[i + self.cell_size:i + self.def_size]))
            for i in range(public_variables_start, public_tags_start, self.def_size)
        ]
        self.public_tags = [
            (to_int(header_data[i:i + self.cell_size]), to_int(header_data[i + self.cell_size:i + self.def_size]))
            for i in range(public_tags_start, overlays_start, self.def_size)
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
        init_capacity: int

        def __init__(self, capacity: int | None, pointer: int, wrap: bytearray | None):
            self.init_capacity = capacity
            if wrap is None:
                self.buffer = bytearray(capacity)
            else:
                self.buffer = wrap
            self.pointer = pointer

        def put_int(self, value: int, signed=False):
            self._check_buffer()
            self.buffer[self.pointer:self.pointer+4] = from_int(value, 4, signed=signed)
            self.pointer += 4

        def put_short(self, value: int, signed=False):
            self._check_buffer()
            self.buffer[self.pointer:self.pointer+2] = from_int(value, 2, signed=signed)
            self.pointer += 2

        def put(self, value: bytearray | bytes):
            self._check_buffer()
            self.buffer[self.pointer:self.pointer+len(value)] = value
            self.pointer += len(value)

        def flip(self):
            self.buffer = self.buffer[:self.pointer]
            self.pointer = 0

        def limit(self) -> int:
            return len(self.buffer)

        def get_int(self, pos: int) -> int:
            return to_int(self.buffer[pos:pos+4])

        def _check_buffer(self):
            if self.pointer >= len(self.buffer):
                self.buffer += bytearray(self.init_capacity)

    def assemble(self) -> bytes:  # TODO update with switch compatibility

        bbuf = AMX.ByteBuffer((len(self.data_section) + len(self.code_section) + 0x200) * 2, 0, None)

        self._assemble_header(bbuf)
        bbuf.put(self._compress_script(self.code_section + self.data_section))
        bbuf.flip()
        bbuf.put_int(bbuf.limit())

        return bytes(bbuf.buffer)

    def dump(self) -> bytes:

        bbuf = AMX.ByteBuffer((len(self.data_section) + len(self.code_section) + 0x200) * 2, 0, None)

        self._assemble_header(bbuf)
        bbuf.put(self.code_section)
        bbuf.put(self.data_section)
        bbuf.flip()
        bbuf.put_int(bbuf.limit())

        return bytes(bbuf.buffer)

    def _assemble_header(self, bbuf: "AMX.ByteBuffer"):
        bbuf.put_int(0)  # Put compressed length later
        bbuf.put(self.amx_magic_32)
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

    def _write_tables(self, bbuf: ByteBuffer):  # TODO update with switch compatibility
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

        native_functions = [0] * (max(self.native_functions.keys()) + 1)
        for index, name in self.native_functions.items():
            native_functions[index] = name
        for name in native_functions:
            bbuf.put_int(0)
            bbuf.put_int(name)
        bbuf.buffer[0x28:0x2c] = from_int(bbuf.pointer, 4)

        libraries = [0] * (max(self.libraries.keys()) + 1)
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
        bbuf.buffer[0x38:0x3c] = from_int(bbuf.pointer, 4)
        bbuf.put(self.symbol_names)
        bbuf.put(b'\x3f\0\0\0')

    def _compress_script(self, data: bytearray) -> bytearray | None:
        if data is None or len(data) % 4 != 0:
            return None
        inbuf = AMX.ByteBuffer(None, 0, data)

        out = AMX.ByteStream()

        while inbuf.pointer < len(data):
            self._compress_bytes(inbuf, out)

        return out.to_bytearray()

    @staticmethod
    def _compress_bytes(in_buf: ByteBuffer, out: ByteStream):
        byt = bytearray()
        instruction = in_buf.get_int(in_buf.pointer)
        sign = (instruction & 0x80000000) > 0

        shadow = instruction ^ 0xFFFFFFFF if sign else instruction
        while True:
            least7 = instruction & 0b01111111
            byte_val = least7 & 0xFF
            if len(byt):
                byte_val |= 0x80
            byt += from_int(byte_val, 1)
            instruction >>= 7
            shadow >>= 7
            print(shadow)
            if shadow == 0:
                break

        if len(byt) < 5:
            sign_bit = 0x40 if sign else 0
            if (byt[-1] & 0x40) != sign_bit:
                byt += from_int(0xFF if sign else 0x80, 1)

        i = 0
        while i < len(byt) / 2:
            byt[i], byt[-(i+1)] = byt[-(i+1)], byt[i]
            i += 1

        ret = byt[:]
        in_buf.pointer += 4
        out.write(ret)

    def disassemble(self) -> str:
        header, links = self._print_header()
        return "\n".join([
            *header,
            "",
            "",
            "",
            *self._print_disassemble(links),
            "",
            "",
            "",
            "Data:",
            *print_bytes_block(self.data_section, 4),
            "",
        ])

    def decompile(self) -> str:
        header, links = self._print_header()
        return "\n".join([
            *header,
            "",
            "",
            "",
            *self._print_decompile(links),
            "",
            "",
            "",
            "Data:",
            *print_bytes_block(self.data_section, 4),
            "",
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

    def _print_header(self) -> tuple[list[str], dict[int, str]]:
        lines = [
            f"Allocated memory: {self.allocated_memory} //{hex(self.allocated_memory)}",
            "Main function: funcmain",
            f"Cell size: {self.cell_size}",
            f"Table record size: {self.def_size}",
        ]
        links = {}
        if self.public_functions:
            lines.append("")
            lines.append("Public functions:")
            for address, name in self.public_functions:
                func_name = f"func_{self.script_commands.get(name, f'pub{name}')}"
                lines.append(f"    #{func_name} {self.get_sysreq(name)}")
                links[address] = func_name
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
            lines.extend(print_bytes_block(self.overlays, 4))
        if self.symbol_names:
            lines.append("")
            lines.append("Symbol names:")
            lines.extend(print_bytes_block(self.symbol_names, 4))
        return lines, links

    class ByteType(Enum):
        UNKNOWN = 0
        RAW = 1
        OPCODE = 2
        PARAM = 3

    def _print_disassemble(self, links: dict[int, str]) -> list[str]:
        lines = ["Code:"]
        structure: list[AMX.ByteType]
        structure = self._analyze_disassemble(links)

        # Writing lines
        pointer = 0
        while pointer < len(self.code_section):
            instr = to_int(self.code_section[pointer:pointer+2])
            opcode_param = to_int(self.code_section[pointer+2:pointer+4])
            if pointer in links:
                lines.append("")
                lines.append(f"{'  ' if links[pointer].startswith('func') else '   '}#{links[pointer]} //{hex(pointer)}")
            if structure[pointer//4] == AMX.ByteType.RAW:
                lines.append(f"    {'raw':17} {self.code_section[pointer:pointer+4].hex(' ')}")
            else:
                line = f"    {self.amx_commands[instr][0]:17} {vm_param_str(opcode_param, 2)}"
                opcode_ptr = pointer
                for param in self.amx_commands[instr][1:]:
                    pointer += 4
                    if param in ("offset", "call_offset"):
                        offset = to_int_signed(self.code_section[pointer:pointer+4])
                        line += " " + links[opcode_ptr+offset]
                    else:
                        line += " " + vm_param_str(to_int(self.code_section[pointer:pointer+4]), 4)
                if instr == 0x82:  # OP_CASETBL
                    case_count = to_int(self.code_section[pointer+4:pointer+8])
                    for _ in range(case_count+1):
                        pointer += 4
                        value = to_int(self.code_section[pointer:pointer+4])
                        offset = to_int_signed(self.code_section[pointer+4:pointer+8])
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

    class Instruction:
        address: int
        opcode: int
        params: list[int]

        def __init__(self, a, o, p):
            self.address = a
            self.opcode = o
            self.params = p

    def _print_decompile(self, links: dict[int, str]) -> list[str]:
        lines = ["Code:"]
        structure: list[AMX.ByteType] = self._analyze_disassemble(links)
        # (address, opcode, params), address is -1 if merged into other instruction
        instructions: list[AMX.Instruction] = []

        for address in range(0, len(structure)*4, 4):
            match structure[address//4]:
                case AMX.ByteType.OPCODE:
                    instructions.append(AMX.Instruction(
                        address,
                        to_int(self.code_section[address:address+2]),
                        [to_int(self.code_section[address+2:address+4])]
                    ))
                case AMX.ByteType.PARAM:
                    instructions[-1].params.append(to_int_signed(self.code_section[address:address+4]))
                case AMX.ByteType.RAW:
                    instructions.append(AMX.Instruction(
                        address,
                        -1,
                        [self.code_section[address+i] for i in range(4)]
                    ))

        for instr in range(len(instructions)):
            instruct = instructions[instr]
            if instruct.address == -1:
                continue
            if instruct.opcode == 0x31 and instr > 0:  # OP_CALL
                pcount_instr = instructions[instr-1]
                pcount = pcount_instr.params[0]
                if pcount_instr.opcode != 0xbc:  # OP_PUSH_P_C
                    continue
                if instr <= pcount // 4:
                    continue
                if any(instructions[instr-2-i].opcode not in (0xbc, 0xbd, 0xbe, 0xd4) for i in range(pcount)):
                    continue
                for instr_ in range(pcount+1):
                    instructions[instr-1-instr_].address = -1
                # TODO that shit is complicated

        return []

    def _analyze_disassemble(self, links: dict[int, str]) -> list:
        structure: list[AMX.ByteType] = [AMX.ByteType.UNKNOWN] * (len(self.code_section) // 4)
        if self.main_address != -1:
            links[self.main_address] = "funcmain"

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
                        offset = to_int_signed(self.code_section[pointer:pointer+4])
                        if (opcode_ptr+offset) not in links:
                            links[opcode_ptr+offset] = f"{'lbl' if param == 'offset' else 'func'}{len(links)}"
                if instr == 0x82:  # OP_CASETBL
                    case_count = to_int(self.code_section[pointer+4:pointer+8])
                    structure[(pointer//4)+1:(pointer//4)+1+(case_count*2)] = [AMX.ByteType.PARAM] * (2+(case_count*2))
                    for _ in range(case_count+1):
                        pointer += 4
                        offset = to_int_signed(self.code_section[pointer+4:pointer+8])
                        if (pointer+offset) not in links:
                            links[pointer+offset] = f"lbl{len(links)}"
                        pointer += 4
                elif instr == 0x87:  # OP_SYSREQ_N
                    structure[(pointer//4)+1] = structure[(pointer//4)+2] = AMX.ByteType.PARAM
                    pointer += 8
            pointer += 4
        for address in links:
            if structure[address//4] == AMX.ByteType.PARAM:
                structure[address//4] = AMX.ByteType.RAW

        return structure

    def _assemble_text(self, text_lines: list[str]):
        lines_iter = iter(text_lines)
        self.allocated_memory = 0
        self.cell_size = 0
        self.def_size = 0
        main_func_name = "funcmain"
        self.public_functions = []
        self.native_functions = {}
        self.libraries = {}
        self.public_variables = []
        self.public_tags = []
        self.overlays = b''
        self.symbol_names = b''
        pub_func_defs: list[tuple[str, int]] = []  # (function name, native function hash)
        label_defs: dict[str, int] = {}  # {name: address}
        label_calls: list[tuple[int, int, str]] = []  # [(opcode/record address, param address, label name)]
        sysreq_calls: list[tuple[int, str]] = []  # [(param address, command name)]
        native_function_by_hash: dict[int, int] = {}
        code_sec_buf = AMX.ByteBuffer(0x1000, 0, None)
        self.data_section = bytearray()

        def next_line() -> list[str]:
            while True:
                nl = next(lines_iter) + "//"
                nll = nl[:nl.index("//")].split()
                if len(nll):
                    return nll

        try:
            while True:
                line = next_line()
                if line[:2] == ["Allocated", "memory:"]:
                    self.allocated_memory = int(line[2])
                    line = next_line()
                if line[:2] == ["Main", "function:"]:
                    main_func_name = line[2]
                    line = next_line()
                if line[:2] == ["Cell", "size:"]:
                    self.cell_size = int(line[2])
                    line = next_line()
                if line[:3] == ["Table", "record", "size:"]:
                    self.def_size = int(line[3])
                    line = next_line()
                if line[:2] == ["Public", "functions:"]:
                    while True:
                        line = next_line()
                        if len(line) != 2 or line[0][0] != "#":
                            break
                        pub_func_defs.append((
                            line[0][1:],
                            int(line[1][1:]) if line[1][:1] == "#" else hash_name(line[1])
                        ))
                if line[:2] == ["Native", "functions:"]:
                    while True:
                        line = next_line()
                        if len(line) != 2 or not line[0].isnumeric():
                            break
                        num = int(line[0])
                        _hash = int(line[1][1:]) if line[1][:1] == "#" else hash_name(line[1])
                        self.native_functions[num] = _hash
                        native_function_by_hash[_hash] = num
                if line[:1] == ["Libraries:"]:
                    while True:
                        line = next_line()
                        if len(line) != 2 or not line[0].isnumeric():
                            break
                        self.libraries[int(line[0])] = int(line[1][1:]) if line[1][:1] == "#" else hash_name(line[1])
                if line[:2] == ["Public", "variables:"]:
                    while True:
                        line = next_line()
                        if len(line) != 2 or line[0][:2] != "0x":
                            break
                        self.public_variables.append((
                            int(line[0], 16),
                            int(line[1][1:]) if line[1][:1] == "#" else hash_name(line[1])
                        ))
                if line[:2] == ["Public", "tags:"]:
                    while True:
                        line = next_line()
                        if len(line) != 2 or line[0][:2] != "0x":
                            break
                        self.public_tags.append((
                            int(line[0], 16),
                            int(line[1][1:]) if line[1][:1] == "#" else hash_name(line[1])
                        ))
                if line[:1] == ["Overlays:"]:
                    overlay_lines = []
                    try:
                        while True:
                            line = next_line()
                            if not all(letter in "0123456789abcdefABCDEFx" for word in line for letter in word):
                                break
                            overlay_lines.append(" ".join(line))
                        self.overlays += read_bytes_block(overlay_lines)
                    except StopIteration as e:
                        self.overlays += read_bytes_block(overlay_lines)
                        raise e
                if line[:2] == ["Symbol", "names:"]:
                    symbol_lines = []
                    try:
                        while True:
                            line = next_line()
                            if not all(letter in "0123456789abcdefABCDEFx" for word in line for letter in word):
                                break
                            symbol_lines.append(" ".join(line))
                        self.symbol_names += read_bytes_block(symbol_lines)
                    except StopIteration as e:
                        self.symbol_names += read_bytes_block(symbol_lines)
                        raise e
                if line[:1] == ["Code:"]:
                    while True:
                        line = next_line()
                        if line[0][:1] == "#":
                            if line[0][1:] in label_defs:
                                raise Exception(f"Duplicate label definition: {line[0]}")
                            label_defs[line[0][1:]] = code_sec_buf.pointer
                        elif len(line) == 5 and line[0] == "raw":
                            code_sec_buf.put(bytes([int(byt, 16) for byt in line[1:]]))
                        elif line[0] in self.amx_command_ids and len(line) > 1:
                            opcode_ptr = code_sec_buf.pointer
                            code_sec_buf.put_short(self.amx_command_ids[line[0]])
                            if line[1][:2] == "0x":
                                code_sec_buf.put_short(int(line[1], 16), signed=False)
                            else:
                                code_sec_buf.put_short(int(line[1]), signed=True)
                            for param in line[2:]:
                                if param.isnumeric() or (param[:1] == "-" and param[1:].isnumeric()):
                                    code_sec_buf.put_int(int(param), signed=True)
                                elif param[:2] == "0x":
                                    code_sec_buf.put_int(int(param, 16), signed=False)
                                elif param in self.script_commands.values():
                                    sysreq_calls.append((  # That will be done afterwards in case native functions were defined below the code section
                                        code_sec_buf.pointer,
                                        param
                                    ))
                                    code_sec_buf.put_int(0)
                                else:
                                    label_calls.append((
                                        opcode_ptr if line[0] != "OP_CASETBL" else code_sec_buf.pointer-4,
                                        code_sec_buf.pointer,
                                        param
                                    ))
                                    code_sec_buf.put_int(0)
                        else:
                            break  # Do not advance line
                if line[:1] == ["Data:"]:
                    data_lines = []
                    try:
                        while True:
                            line = next_line()
                            if not all(letter in "0123456789abcdefABCDEFx" for word in line for letter in word):
                                break
                            data_lines.append(" ".join(line))
                        self.data_section += read_bytes_block(data_lines)
                    except StopIteration as e:
                        self.data_section += read_bytes_block(data_lines)
                        raise e
        except StopIteration:
            pass
        if self.allocated_memory == 0:
            raise Exception("Allocated memory not defined")
        if self.cell_size == 0:
            raise Exception("Cell size not defined")
        if self.def_size == 0:
            raise Exception("Table record size not defined")
        for address, name in sysreq_calls:
            _hash = hash_name(name)
            if _hash not in self.native_functions.values():
                raise Exception("Calling native function that was not imported: "+name)
            code_sec_buf.buffer[address:address+4] = from_int(native_function_by_hash[_hash], 4)
        for name, _hash in pub_func_defs:
            if name not in label_defs:
                raise Exception(f"Label {name} not defined")
            self.public_functions.append((label_defs[name], _hash))
        for calling_addr, param_addr, lbl_name in label_calls:
            if lbl_name not in label_defs:
                raise Exception(f"Label {lbl_name} not defined")
            offset = label_defs[lbl_name] - calling_addr
            code_sec_buf.buffer[param_addr:param_addr+4] = from_int(offset, 4, signed=True)
        if main_func_name not in label_defs:
            raise Exception(f"main function label {main_func_name} not defined")
        self.main_address = label_defs[main_func_name]
        code_sec_buf.flip()
        self.code_section = code_sec_buf.buffer


class XAMXFile:
    file_parts: list[AMX | bytearray]

    def __init__(self, data: bytearray | list[str]):
        self.file_parts = []
        if isinstance(data, list):
            data: list[str]
            start = 0
            section = None
            for line_num in range(len(data)):
                parts = data[line_num].split()
                if len(parts) == 0 or parts[0][:2] == "//":
                    continue
                if len(parts) > 2 and parts[:3] == ["---", "AMX", "Section"]:
                    if section == None:
                        start = line_num + 1
                        section = "amx"
                    elif section == "amx":
                        self.file_parts.append(AMX(data[start:line_num-1]))
                        start = line_num + 1
                        section = "amx"
                    elif section == "data":
                        self.file_parts.append(read_bytes_block(data[start:line_num-1]))
                        start = line_num + 1
                        section = "amx"
                elif len(parts) > 2 and parts[:3] == ["---", "Data", "Section"]:
                    if section is None:
                        start = line_num + 1
                        section = "data"
                    elif section == "amx":
                        self.file_parts.append(AMX(data[start:line_num-1]))
                        start = line_num + 1
                        section = "data"
                    elif section == "data":
                        self.file_parts.append(read_bytes_block(data[start:line_num-1]))
                        start = line_num + 1
                        section = "data"
            if section == "amx":
                self.file_parts.append(AMX(data[start:]))
            elif section == "data":
                self.file_parts.append(read_bytes_block(data[start:]))
        elif isinstance(data, bytearray):
            last_end = 0
            while True:
                address = data.find(AMX.amx_magic_32 + b'\x1c\0\x08\0', last_end)
                if address == -1:
                    if len(data) - last_end >= 4:
                        self.file_parts.append(data[last_end:])
                    break
                if address-4 - last_end >= 4:
                    self.file_parts.append(data[last_end:address-4])
                length = to_int(data[address-4:address])
                self.file_parts.append(AMX(data[address-4:address-4+length]))
                last_end = address-4+length

    def assemble(self) -> bytes:
        data = b''
        for part in self.file_parts:
            if isinstance(part, bytearray):
                data += part
            elif isinstance(part, AMX):
                data += part.assemble()
        return data

    def dump(self) -> bytes:
        data = b''
        for part in self.file_parts:
            if isinstance(part, bytearray):
                data += part
            elif isinstance(part, AMX):
                data += part.dump()
        return data

    def disassemble(self) -> str:
        lines = []
        for part in self.file_parts:
            if isinstance(part, bytearray):
                lines.extend([
                    "",
                    "--- Data Section",
                    "",
                ])
                lines.extend(print_bytes_block(part))
            elif isinstance(part, AMX):
                lines.extend([
                    "",
                    "--- AMX Section",
                    "",
                    part.disassemble(),
                ])
        return "\n".join(lines)


if __name__ == "__main__":

    # These are just examples on how to use this python script

    disassemble = False
    if disassemble:
        with open(f"disassembled/a012_013.xamx", "wt") as f:
            data = bytearray(get_file_as_bytes(f"garcs/a012_/013.bin"))
            disassambled_text = XAMXFile(data).disassemble()
            f.write(disassambled_text)

    assemble = False
    if assemble:
        with open(f"assembled/a012_013.bin", "wb") as f:
            text_lines = get_text_file_lines(f"disassembled/a012_013.xamx")
            binary = XAMXFile(text_lines).dump()
            f.write(binary)

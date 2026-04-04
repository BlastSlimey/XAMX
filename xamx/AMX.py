from typing import Self

from .amx_utils import bytes_to_int, bytes_from_int, decompress_bytes, compress_bytes
from .data import amx_opcodes
from . import assembler, disassembler

amx_magic_32 = b'\xe0\xf1\x0a\x0a'
amx_magic_64 = b'\xe1\xf1\x0a\x0a'
amx_magic_btlai = b'\xef\xf1\x0a\x0a'


class AMX:
    code_section: list[bytes]
    data_section: bytearray
    allocated_memory: int
    main_address: int
    cell_size: int
    def_size: int
    flags: int
    public_functions: list[tuple[int, int]]
    native_functions: dict[int, int]
    libraries: dict[int, int]
    public_variables: list[tuple[int, int]]
    public_tags: list[tuple[int, int]]
    overlays: bytes  # unknown structure
    symbol_names: bytes  # unclear structure

    @classmethod
    def load_compiled(cls, data: bytes | bytearray) -> Self:

        self = AMX()

        length = bytes_to_int(data[:4])
        if data[4:8] == amx_magic_32:
            self.cell_size = 4
        elif data[4:8] == amx_magic_64:
            self.cell_size = 8
        else:
            raise IOError()

        self.def_size = bytes_to_int(data[10:12])
        self.flags = bytes_to_int(data[8:10])
        code_section_start = bytes_to_int(data[12:16])
        data_section_start = bytes_to_int(data[16:20])
        heap_start = bytes_to_int(data[20:24])
        self.allocated_memory = bytes_to_int(data[24:28])
        self.main_address = bytes_to_int(data[28:32], signed=True)

        public_functions_start = bytes_to_int(data[32:36])
        native_functions_start = bytes_to_int(data[36:40])
        libraries_start = bytes_to_int(data[40:44])
        public_variables_start = bytes_to_int(data[44:48])
        public_tags_start = bytes_to_int(data[48:52])
        overlays_start = bytes_to_int(data[52:56])
        symbol_names_start = bytes_to_int(data[56:60])

        header_data = data[:code_section_start]
        dec_data = decompress_bytes(data[code_section_start:length], heap_start - code_section_start)
        self.data_section = dec_data[data_section_start-code_section_start:]
        self._decode_cells(dec_data[:data_section_start-code_section_start])

        self.public_functions = [
            (bytes_to_int(header_data[i:i + self.cell_size]), bytes_to_int(header_data[i+self.cell_size:i+self.def_size]))
            for i in range(public_functions_start, native_functions_start, self.def_size)
        ]
        self.native_functions = {
            (i-native_functions_start) // self.def_size: bytes_to_int(header_data[i+self.cell_size:i+self.def_size])
            for i in range(native_functions_start, libraries_start, self.def_size)
        }
        self.libraries = {
            (i - libraries_start) // self.def_size: bytes_to_int(header_data[i+self.cell_size:i+self.def_size])
            for i in range(libraries_start, public_variables_start, self.def_size)
        }
        self.public_variables = [
            (bytes_to_int(header_data[i:i + self.cell_size]), bytes_to_int(header_data[i + self.cell_size:i + self.def_size]))
            for i in range(public_variables_start, public_tags_start, self.def_size)
        ]
        self.public_tags = [
            (bytes_to_int(header_data[i:i + self.cell_size]), bytes_to_int(header_data[i + self.cell_size:i + self.def_size]))
            for i in range(public_tags_start, overlays_start, self.def_size)
        ]
        self.overlays = header_data[overlays_start:symbol_names_start]
        self.symbol_names = header_data[symbol_names_start:header_data.rfind(b'\x3f\0\0\0')]

        return self

    def _decode_cells(self, code: bytes | bytearray):

        self.code_section = []
        pos = 0
        while pos < len(code):
            opc = bytes_to_int(code[pos:pos+2])
            if opc == 0x82:  # OP_CASETBL
                case_count = bytes_to_int(code[pos+4:pos+8])
                opc_size = (case_count + 1) * 8 + 4
            elif opc == 0x87:  # OP_SYSREQ_N
                opc_size = 12
            elif opc in amx_opcodes:
                opc_size = len(amx_opcodes[opc]) * 4
            else:
                opc_size = 4
            self.code_section.append(code[pos:pos+opc_size])
            pos += opc_size

    def dump(self) -> bytearray:

        data = bytearray()

        self._assemble_header(data)
        data += compress_bytes(b''.join(self.code_section) + self.data_section)
        data[0:4] = bytes_from_int(len(data), 4)

        return data

    def debug_dump(self) -> bytearray:

        data = bytearray()

        self._assemble_header(data)
        for cell in self.code_section:
            data += cell
        data += iter(self.code_section)
        data += self.data_section
        data[0:4] = bytes_from_int(len(data), 4)

        return data

    def _assemble_header(self, data: bytearray):
        data += b'\0\0\0\0'  # Put compressed length later
        data += amx_magic_32
        data += bytes_from_int(self.flags, 2)
        data += b'\x08\0'
        data += b'\0\0\0\0'  # Put header length later
        data += b'\0\0\0\0'  # Put header and code section length later
        data += b'\0\0\0\0'  # Put whole decompressed length later
        data += bytes_from_int(self.allocated_memory, 4)
        data += bytes_from_int(self.main_address, 4)
        self._write_tables(data)
        sum_code = sum(len(cell) for cell in self.code_section)
        data[12:16] = bytes_from_int(len(data), 4)
        data[16:20] = bytes_from_int(len(data) + sum_code, 4)
        data[20:24] = bytes_from_int(len(data) + sum_code + len(self.data_section), 4)

    def _write_tables(self, data: bytearray):
        data += b'\0\0\0\0'
        data += b'\0\0\0\0'
        data += b'\0\0\0\0'
        data += b'\0\0\0\0'
        data += b'\0\0\0\0'
        data += b'\0\0\0\0'
        data += b'\0\0\0\0'
        data[0x20:0x24] = bytes_from_int(len(data), 4)

        for address, name in self.public_functions:
            data += bytes_from_int(address, 4)
            data += bytes_from_int(name, 4)
        data[0x24:0x28] = bytes_from_int(len(data), 4)

        native_functions = [0] * (max(self.native_functions.keys()) + 1 if self.native_functions.keys() else 0)
        for index, name in self.native_functions.items():
            native_functions[index] = name
        for name in native_functions:
            data += b'\0\0\0\0'
            data += bytes_from_int(name, 4)
        data[0x28:0x2c] = bytes_from_int(len(data), 4)

        libraries = [0] * (max(self.libraries.keys()) + 1 if self.libraries.keys() else 0)
        for index, name in self.libraries.items():
            libraries[index] = name
        for name in libraries:
            data += b'\0\0\0\0'
            data += bytes_from_int(name, 4)
        data[0x2c:0x30] = bytes_from_int(len(data), 4)

        for address, name in self.public_variables:
            data += bytes_from_int(address, 4)
            data += bytes_from_int(name, 4)
        data[0x30:0x34] = bytes_from_int(len(data), 4)

        for address, name in self.public_tags:
            data += bytes_from_int(address, 4)
            data += bytes_from_int(name, 4)
        data[0x34:0x38] = bytes_from_int(len(data), 4)

        data += self.overlays
        data[0x38:0x3c] = bytes_from_int(len(data), 4)
        data += self.symbol_names
        data += b'\x3f\0\0\0'

    def disassemble(self) -> str:
        return disassembler.disassemble(self)

    @classmethod
    def assemble_xamx(cls, text_lines: list[str]) -> Self:
        self = AMX()
        assembler.assemble_text(self, text_lines)
        return self

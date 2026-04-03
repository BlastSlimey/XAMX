from typing import TYPE_CHECKING

from .amx_utils import hash_name, read_bytes_block, bytes_from_int
from .data import script_commands, amx_opcode_ids

if TYPE_CHECKING:
    from .AMX import AMX


def assemble_text(self: "AMX", text_lines: list[str]):
    lines_iter = iter(text_lines)
    self.allocated_memory = 0
    self.cell_size = 0
    self.flags = 0
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
    code_sec_buf = bytearray()
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
            if line[0] == "Flags:":
                self.flags = int(line[1])
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
                        label_defs[line[0][1:]] = len(code_sec_buf)
                    elif len(line) == 5 and line[0] == "raw":
                        code_sec_buf += bytes([int(byt, 16) for byt in line[1:]])
                    elif line[0] in amx_opcode_ids and len(line) > 1:
                        opcode_ptr = len(code_sec_buf)
                        code_sec_buf += bytes_from_int(amx_opcode_ids[line[0]], 2)
                        if line[1][:2] == "0x":
                            code_sec_buf += bytes_from_int(int(line[1], 16), 2, signed=False)
                        else:
                            code_sec_buf += bytes_from_int(int(line[1]), 2, signed=True)
                        for param in line[2:]:
                            if param.isnumeric() or (param[:1] == "-" and param[1:].isnumeric()):
                                code_sec_buf += bytes_from_int(int(param), 4, signed=True)
                            elif param[:2] == "0x":
                                code_sec_buf += bytes_from_int(int(param, 16), 4, signed=False)
                            elif param in script_commands.values():
                                # That will be done afterwards in case native functions were defined
                                # after the code section
                                sysreq_calls.append((
                                    len(code_sec_buf),
                                    param
                                ))
                                code_sec_buf += b'\0\0\0\0'
                            else:
                                label_calls.append((
                                    opcode_ptr if line[0] != "OP_CASETBL" else len(code_sec_buf) - 4,
                                    len(code_sec_buf),
                                    param
                                ))
                                code_sec_buf += b'\0\0\0\0'
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
            raise Exception("Calling native function that was not imported: " + name)
        code_sec_buf[address:address + 4] = bytes_from_int(native_function_by_hash[_hash], 4)
    for name, _hash in pub_func_defs:
        if name not in label_defs:
            raise Exception(f"Label {name} not defined")
        self.public_functions.append((label_defs[name], _hash))
    for calling_addr, param_addr, lbl_name in label_calls:
        if lbl_name not in label_defs:
            raise Exception(f"Label {lbl_name} not defined")
        offset = label_defs[lbl_name] - calling_addr
        code_sec_buf[param_addr:param_addr + 4] = bytes_from_int(offset, 4, signed=True)
    if main_func_name not in label_defs:
        raise Exception(f"main function label {main_func_name} not defined")
    self.main_address = label_defs[main_func_name]
    self._decode_cells(code_sec_buf)

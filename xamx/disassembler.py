from enum import Enum
from typing import TYPE_CHECKING

from .amx_utils import print_bytes_block, bytes_to_int, vm_param_str
from .data import script_commands, amx_opcodes

if TYPE_CHECKING:
    from .AMX import AMX


def disassemble(self: "AMX") -> str:
    header, links = _print_header(self)
    return "\n".join([
        *header,
        "",
        "",
        "",
        *_print_disassemble(self, links),
        "",
        "",
        "",
        "Data:",
        *print_bytes_block(self.data_section, 4),
        "",
    ])


def get_sysreq(number: int) -> str:
    if number in script_commands:
        return script_commands[number]
    else:
        return f"  #{number}"


def get_sysreq_param(self: "AMX", number: int) -> str:
    if self.native_functions[number] in script_commands:
        return script_commands[self.native_functions[number]]
    else:
        return str(number)


def _print_header(self: "AMX") -> tuple[list[str], dict[int, str]]:
    lines = [
        f"Allocated memory: {self.allocated_memory} //{hex(self.allocated_memory)}",
        "Main function: funcmain",
        f"Cell size: {self.cell_size}",
        f"Flags: {self.flags}",
        f"Table record size: {self.def_size}",
    ]
    links = {}
    if self.public_functions:
        lines.append("")
        lines.append("Public functions:")
        for address, name in self.public_functions:
            func_name = f"func_{script_commands.get(name, f'pub{name}')}"
            lines.append(f"    #{func_name} {get_sysreq(name)}")
            links[address] = func_name
    if self.native_functions:
        lines.append("")
        lines.append("Native functions:")
        for index, name in self.native_functions.items():
            lines.append(f"    {index} {get_sysreq(name)}")
    if self.libraries:
        lines.append("")
        lines.append("Libraries:")
        for index, name in self.libraries.items():
            lines.append(f"    {index} {get_sysreq(name)}")
    if self.public_variables:
        lines.append("")
        lines.append("Public variables:")
        for address, name in self.public_variables:
            lines.append(f"    {hex(address)} {get_sysreq(name)}")
    if self.public_tags:
        lines.append("")
        lines.append("Public tags:")
        for address, name in self.public_tags:
            lines.append(f"    {hex(address)} {get_sysreq(name)}")
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


def _print_disassemble(self: "AMX", links: dict[int, str]) -> list[str]:
    lines = ["Code:"]
    _analyze_disassemble(self, links)
    printed_link: set[int] = set()

    # Writing lines
    instr_ptr = 0
    code_ptr = 0
    while instr_ptr < len(self.code_section):
        cell = self.code_section[instr_ptr]
        instr = bytes_to_int(cell[0:2])
        opcode_param = bytes_to_int(cell[2:4])
        if code_ptr in links:
            lines.append("")
            lines.append(f"{'  ' if links[code_ptr].startswith('func') else '   '}#{links[code_ptr]} //{hex(code_ptr)}")
            printed_link.add(code_ptr)
        if instr not in amx_opcodes:
            lines.append(f"    {'raw':17} {cell.hex(' ')}")
        else:
            line = f"    {amx_opcodes[instr][0]:17} {vm_param_str(opcode_param, 2)}"
            opcode_ptr = code_ptr
            for param in amx_opcodes[instr][1:]:
                code_ptr += 4
                if param in ("offset", "call_offset"):
                    offset = bytes_to_int(cell[code_ptr-opcode_ptr:code_ptr-opcode_ptr+4],
                                          signed=True)
                    line += " " + links[opcode_ptr + offset]
                else:
                    line += " " + vm_param_str(bytes_to_int(cell[code_ptr-opcode_ptr:code_ptr-opcode_ptr+4]), 4)
            if instr == 0x82:  # OP_CASETBL
                case_count = bytes_to_int(cell[code_ptr-opcode_ptr+4:code_ptr-opcode_ptr+8])
                for _ in range(case_count + 1):
                    code_ptr += 4
                    value = bytes_to_int(cell[code_ptr-opcode_ptr:code_ptr-opcode_ptr+4])
                    offset = bytes_to_int(cell[code_ptr-opcode_ptr+4:code_ptr-opcode_ptr+8],
                                          signed=True)
                    line += f" {vm_param_str(value, 4)} {links[code_ptr + offset]}"
                    code_ptr += 4
            elif instr == 0x87:  # OP_SYSREQ_N
                native = bytes_to_int(cell[code_ptr-opcode_ptr + 4:code_ptr-opcode_ptr + 8])
                pop_count = bytes_to_int(cell[code_ptr-opcode_ptr + 8:code_ptr-opcode_ptr + 12])
                line += f" {get_sysreq_param(self, native)} {pop_count}"
                code_ptr += 8
            lines.append(line)
        instr_ptr += 1
        code_ptr += 4

    return lines


def _analyze_disassemble(self: "AMX", links: dict[int, str]):
    if self.main_address != -1:
        links[self.main_address] = "funcmain"

    instr_ptr = 0
    code_ptr = 0
    while instr_ptr < len(self.code_section):
        instr = bytes_to_int(self.code_section[instr_ptr][0:2])
        if instr in amx_opcodes:
            opcode_ptr = code_ptr
            for param in amx_opcodes[instr][1:]:
                code_ptr += 4
                if param in ("offset", "call_offset"):
                    offset = bytes_to_int(self.code_section[instr_ptr][code_ptr-opcode_ptr:code_ptr-opcode_ptr+4],
                                          signed=True)
                    if (opcode_ptr + offset) not in links:
                        links[opcode_ptr + offset] = f"{'lbl' if param == 'offset' else 'func'}{len(links)}"
            if instr == 0x82:  # OP_CASETBL
                case_count = bytes_to_int(self.code_section[instr_ptr][4:8])
                for _ in range(case_count + 1):
                    code_ptr += 4
                    offset = bytes_to_int(self.code_section[instr_ptr][code_ptr-opcode_ptr+4:code_ptr-opcode_ptr+8],
                                          signed=True)
                    if (code_ptr + offset) not in links:
                        links[code_ptr + offset] = f"lbl{len(links)}"
                    code_ptr += 4
            elif instr == 0x87:  # OP_SYSREQ_N
                code_ptr += 8
        code_ptr += 4
        instr_ptr += 1

from typing import Self

from .AMX import AMX, amx_magic_32
from .amx_utils import bytes_to_int, bytes_from_int, print_bytes_block, read_bytes_block


class AMXFile:

    @classmethod
    def load_compiled(cls, data: bytes | bytearray) -> Self:
        ...

    @classmethod
    def assemble_xamx(cls, text_lines: list[str]) -> Self:
        ...

    def dump(self) -> bytearray:
        ...

    def debug_dump(self) -> bytearray:
        """Important: Debug dumps cannot be re-imported with this tool"""
        ...

    def disassemble(self) -> str:
        ...


class RawScript(AMXFile):
    script: AMX

    @classmethod
    def load_compiled(cls, data: bytes | bytearray) -> Self:
        self = RawScript()
        self.script = AMX.load_compiled(data)
        return self

    @classmethod
    def assemble_xamx(cls, text_lines: list[str]) -> Self:
        self = RawScript()
        self.script = AMX.assemble_xamx(text_lines[1:])
        return self

    def dump(self) -> bytearray:
        return self.script.dump()

    def debug_dump(self) -> bytearray:
        return self.script.debug_dump()

    def disassemble(self) -> str:
        return "\n".join((
            "File type: RawScript",
            self.script.disassemble(),
        ))


class BtlAiScript(AMXFile):
    script: AMX
    other: bytes | bytearray

    @classmethod
    def load_compiled(cls, data: bytes | bytearray) -> Self:
        self = BtlAiScript()
        length = bytes_to_int(data[:4])
        self.script = AMX.load_compiled(data[:length])
        self.other = data[length:]
        return self

    @classmethod
    def assemble_xamx(cls, text_lines: list[str]) -> Self:
        self = BtlAiScript()
        for i in range(len(text_lines)):
            if text_lines[i].strip() == "Other script:":
                self.script = AMX.assemble_xamx(text_lines[1:i])
                self.other = read_bytes_block(text_lines[i+1:])
                break
        return self

    def dump(self) -> bytearray:
        return self.script.dump() + self.other

    def debug_dump(self) -> bytearray:
        return self.script.debug_dump() + self.other

    def disassemble(self) -> str:
        return "\n".join((
            "File type: BtlAiScript",
            self.script.disassemble(),
            "",
            "",
            "Other script:",
            *print_bytes_block(self.other, 4)
        ))


class MixedAMX:
    data: bytes | bytearray
    script: AMX


class MapFile(AMXFile):
    abbreviation: bytes | bytearray
    parts: list[bytes | bytearray | AMX | MixedAMX]
    alignment: int

    @classmethod
    def load_compiled(cls, data: bytes | bytearray) -> Self:
        self = MapFile()
        self.abbreviation = data[:2]
        self.parts = []
        parts_count = bytes_to_int(data[2:4])
        self.alignment = 0x80 if data[4] == 0x80 else 4
        for p_num in range(parts_count):
            start = bytes_to_int(data[p_num*4+4:p_num*4+8])
            if p_num == 1 and self.abbreviation == b'\x5a\x4f':
                mixed = MixedAMX()
                offset = bytes_to_int(data[start:start+4])
                script_len = bytes_to_int(data[start+4+offset:start+8+offset])
                mixed.data = data[start+4:start+4+offset]
                mixed.script = AMX.load_compiled(data[start+4+offset:start+4+offset+script_len])
                self.parts.append(mixed)
            elif data[start+4:start+8] == amx_magic_32:
                script_len = bytes_to_int(data[start:start+4])
                self.parts.append(AMX.load_compiled(data[start:start+script_len]))
            else:
                self.parts.append(data[start:bytes_to_int(data[p_num*4+8:p_num*4+12])])
        return self

    @classmethod
    def assemble_xamx(cls, text_lines: list[str]) -> Self:
        self = MapFile()
        self.parts = []
        sep = []
        abbr, align = False, False
        for i in range(len(text_lines)):
            split = text_lines[i].split()
            if split and split[0] == "---" and len(split) > 1:
                sep.append(i)
        for i in range(sep[0]):
            line_parts = text_lines[i].split()
            if line_parts and line_parts[0] == "Abbreviation:":
                abbr = True
                self.abbreviation = line_parts[1].encode()
            elif line_parts and line_parts[0] == "Alignment:":
                align = True
                self.alignment = int(line_parts[1])
        if not abbr:
            raise Exception("MapFile disassembly requires an abbreviation")
        if not align:
            raise Exception("MapFile disassembly requires an alignment")
        for i in range(len(sep)):
            start, end = sep[i], sep[i+1] if i+1 < len(sep) else len(text_lines)
            split = text_lines[start].split()
            if split[1] == "AMX":
                self.parts.append(AMX.assemble_xamx(text_lines[start+1:end]))
            elif split[1] == "MixedAMX":
                mixed = MixedAMX()
                extra = -1
                for j in range(start+1, end):
                    line = text_lines[j].strip()
                    if line == "Extra:":
                        extra = j
                    elif line == "End extra":
                        if extra == -1:
                            raise Exception("MixedAMX section has an 'End extra' before or without an 'Extra:'")
                        mixed.data = read_bytes_block(text_lines[extra+1:j])
                        mixed.script = AMX.assemble_xamx(text_lines[j+1:end])
                        self.parts.append(mixed)
                        break
                else:
                    raise Exception("MixedAMX section is missing an 'End extra'")
            elif split[1] == "Raw":
                self.parts.append(read_bytes_block(text_lines[start+1:end]))
            else:
                raise Exception(f"MapFile disassembly has unknown section '{split[1]}'")
        return self

    def dump(self) -> bytearray:
        out = []
        for part in self.parts:
            if type(part) is AMX:
                out.append(part.dump())
            elif type(part) is MixedAMX:
                out.append(bytes_from_int(len(part.data), 4)+part.data+part.script.dump())
            else:
                out.append(part)
        head = bytearray(len(out)*4+8)
        if len(head) % self.alignment:
            head += bytes(self.alignment - (len(head) % self.alignment))
        head[0:2] = self.abbreviation
        head[2:4] = bytes_from_int(len(out), 2)
        for out_num in range(len(out)):
            head[out_num*4+4:out_num*4+8] = bytes_from_int(len(head), 4)
            head += out[out_num]
            if len(head) % self.alignment:
                head += bytes(self.alignment - (len(head) % self.alignment))
        head[len(out) * 4 + 4:len(out) * 4 + 8] = bytes_from_int(len(head), 4)
        if len(head) % self.alignment:
            head += bytes(self.alignment - (len(head) % self.alignment))
        return head

    def debug_dump(self) -> bytearray:
        out = []
        for part in self.parts:
            if type(part) is AMX:
                out.append(part.debug_dump())
            elif type(part) is MixedAMX:
                out.append(bytes_from_int(len(part.data)+4, 4)+part.data+part.script.debug_dump())
            else:
                out.append(part)
        head = bytearray(len(out)*4+8)
        if len(head) % self.alignment:
            head += bytes(self.alignment - (len(head) % self.alignment))
        head[0:2] = self.abbreviation
        head[2:4] = bytes_from_int(len(out), 2)
        for out_num in range(len(out)):
            head[out_num*4+4:out_num*4+8] = bytes_from_int(len(head), 4)
            head += out[out_num]
            if len(head) % self.alignment:
                head += bytes(self.alignment - (len(head) % self.alignment))
        head[len(out) * 4 + 4:len(out) * 4 + 8] = bytes_from_int(len(head), 4)
        if len(head) % self.alignment:
            head += bytes(self.alignment - (len(head) % self.alignment))
        return head

    def disassemble(self) -> str:
        out = [
            "File type: MapFile",
            f"Abbreviation: {self.abbreviation.decode()}",
            f"Alignment: {self.alignment}",
        ]
        for part in self.parts:
            if type(part) is AMX:
                out.extend((
                    "",
                    "--- AMX",
                    "",
                    part.disassemble(),
                ))
            elif type(part) is MixedAMX:
                out.extend((
                    "",
                    "--- MixedAMX",
                    "",
                    "Extra:",
                    *print_bytes_block(part.data, 4),
                    "End extra",
                    "",
                    part.script.disassemble(),
                ))
            else:
                out.extend((
                    "",
                    "--- Raw",
                    "",
                    *print_bytes_block(part),
                ))
        return "\n".join(out)

import os.path

from . import amx_utils

amx_opcodes: dict[int, tuple[str, ...]] = {}
amx_opcode_ids: dict[str, int] = {}
script_commands: dict[int, str] = {}

for line in amx_utils.get_text_file_lines(os.path.join(__name__[:__name__.rindex(".")], "opcodes.txt")):
    parts = line.split()
    if len(parts) and parts[0][:2] == "OP":
        amx_opcodes[int(parts[1])] = (parts[0], *parts[3:])
        amx_opcode_ids[parts[0]] = int(parts[1])
for line in amx_utils.get_text_file_lines(os.path.join(__name__[:__name__.rindex(".")], "commands.txt")):
    parts = line.split()
    if len(parts) and parts[0][:2] != "//":
        _hash = amx_utils.hash_name(parts[0])
        if _hash not in script_commands:
            script_commands[_hash] = parts[0]
        else:
            raise Exception(f"Duplicate hash: {parts[0]} {script_commands[_hash]}")

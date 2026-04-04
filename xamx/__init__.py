import os.path
import traceback

from .AMX import amx_magic_32, amx_magic_btlai
from .amx_utils import bytes_to_int
from .FileTypes import RawScript, MapFile, BtlAiScript


def main(decompile: bool | None, *names: str):
    processed_count = 0
    print("Whenever user input is required, typing 'y', 'yes', or 'true' will be interpreted as that. "
          "Everything else will be treated as no/false.")
    print("")
    try:
        for name in names:
            # if folder, then ask whether to process everything inside recursively or only direct files
            # load first few bytes (and file name) and then decide what subclass of AMXFile to call
            # if file with disassembled header, then assemble it
            # if file with decompiled header, then compile it
            # check for various binary hints to what file type it is and then call AMXFile types accordingly and ask whether to disassemble or decompile it
            # if none found (not even pure amx) then warning and return

            # if folder, then...
            #   if folder name doesn't end with "_" or "_{num}", then put everything processed into another folder with f"{folder_name}_"
            #     if that folder already exists, then ask whether to overwrite everything in that folder or to append numbers at the end
            #   else put everything processed into another folder with everything after and including the last "_" being cut from the name
            #     if that folder already exists, then ask whether to overwrite everything in that folder or to continue the numbering like above
            # if disassembling/decompiling a binary file, then add .xamx/.py to the end (do NOT replace existing file name ending)
            #   if that exists, then ask whether to replace the existing file or to add f"_{num}" to original file name
            # if assembling/compiling a text file, then either remove .xamx/.py (if that exists)
            #   if that exists, then ask whether to replace the existing file or to add f"_{num}" at the end
            if os.path.isdir(name):
                inp = input(f"Process all files in the folder \"{name}\" recursively "
                            f"(i.e. go through all subfolders and subfolders within them)? ")
                # should_decompile = input("Should assembled AMX files (if any) be decompiled? "
                #                          "Otherwise, they will be disassembled. ")
                should_decompile = "no"
                if "_" in name and (name[-1] == "_" or name[name.rindex("_") + 1:].isnumeric()):
                    new_folder = name[:name.rindex("_")]
                else:
                    new_folder = name + "_"
                if os.path.exists(new_folder):
                    inp2 = input(f"Destination folder \"{new_folder}\" already exists. Put results into that folder "
                                 f"anyway? Otherwise, a new folder will be created. ")
                    if not inp2.casefold() in ("y", "yes", "true"):
                        new_folder += "1" if new_folder[-1] == "_" else "_1"
                        count = 1
                        while os.path.exists(new_folder):
                            count += 1
                            new_folder = new_folder[:-1] + str(count)
                        os.mkdir(new_folder)
                else:
                    os.mkdir(new_folder)
                if inp.casefold() in ("y", "yes", "true"):
                    for root, dirs, files in os.walk(name):
                        new_root = root.replace(name, new_folder, 1)
                        assert root != new_root, f"{root} == {new_root} but shouldn't be, please report this to the dev"
                        if not os.path.exists(new_root):
                            os.mkdir(new_root)
                        for file in files:
                            with open(os.path.join(root, file), "rb") as infile:
                                data = infile.read()
                                processed = process_file(data, should_decompile.casefold() in ("y", "yes", "true"))
                                if processed is not None:
                                    if type(processed) is str:
                                        new_name = file + ".xamx"
                                    elif type(processed) in (bytes, bytearray) and file.endswith(".xamx"):
                                        new_name = file[:-5]
                                    with open(os.path.join(new_root, new_name),
                                              "wt" if type(processed) is str else "wb") as outfile:
                                        processed_count += 1
                                        outfile.write(processed)
                else:
                    for file in (fn for fn in os.listdir(name) if os.path.isfile(os.path.join(name, fn))):
                        with open(os.path.join(name, file), "rb") as infile:
                            data = infile.read()
                            processed = process_file(data, should_decompile.casefold() in ("y", "yes", "true"))
                            if processed is not None:
                                if type(processed) is str:
                                    new_name = file + ".xamx"
                                elif type(processed) in (bytes, bytearray) and file.endswith(".xamx"):
                                    new_name = file[:-5]
                                with open(os.path.join(new_folder, new_name),
                                          "wt" if type(processed) is str else "wb") as outfile:
                                    processed_count += 1
                                    outfile.write(processed)
            else:
                with open(name, "rb") as infile:
                    processed = process_file(infile.read(), None)
                if processed is None:
                    pass
                elif type(processed) is str:
                    new_name = name + ".xamx"
                    if os.path.exists(new_name):
                        inp = input(f"Destination file \"{new_name}\" already exists. Overwrite that file? Otherwise, "
                                    f"a number will be put at the end of the destination file name. ")
                        if not inp.casefold() in ("y", "yes", "true"):
                            new_name = name + f"_{1}" + ".xamx"
                            count = 1
                            while os.path.exists(new_name):
                                count += 1
                                new_name = name + f"_{count}" + ".xamx"
                    with open(new_name, "wt") as outfile:
                        processed_count += 1
                        outfile.write(processed)
                else:
                    new_name = name[:-5] if name.endswith(".xamx") else name
                    if os.path.exists(new_name):
                        inp = input(f"Destination file \"{new_name}\" already exists. Overwrite that file? Otherwise, "
                                    f"a number will be put at the end of the destination file name. ")
                        if not inp.casefold() in ("y", "yes", "true"):
                            new_name += f"_{1}"
                            count = 1
                            while os.path.exists(new_name):
                                count += 1
                                new_name = new_name[:new_name.rindex("_")+1] + str(count)
                    with open(new_name, "wb") as outfile:
                        processed_count += 1
                        outfile.write(processed)
        input(f"Processed {processed_count} files. Press enter to close.")
    except Exception:
        print(traceback.format_exc())
        input("An error occurred. Press enter to close.")


def process_file(data: bytes | bytearray, should_decompile: bool | None) -> str | bytes | bytearray | None:
    if data[4:8] == amx_magic_32:
        length = bytes_to_int(data[:4])
        if length == len(data):  # pure amx
            # TODO implement choice to decompile
            return RawScript.load_compiled(data).disassemble()
        elif data[length+4:length+8] == amx_magic_btlai and bytes_to_int(data[length:length+4]) + length == len(data):  # XY btl_ai.garc
            # TODO implement choice to decompile
            return BtlAiScript.load_compiled(data).disassemble()
        else:  # unknown
            print("File type unknown: " + str(data[:10]))
            return None
    elif data[:2] in (b'\x5a\x53', b'\x5a\x49', b'\x5a\x4f'):  # Map files
        # TODO implement choice to decompile
        return MapFile.load_compiled(data).disassemble()
    elif data[:10] == b'File type:':  # disassembled
        text = data.decode().splitlines()
        first = text[0].split()
        if len(first) < 3:
            raise Exception("Need to specify file type")
        if first[2] == "BtlAiScript":
            return BtlAiScript.assemble_xamx(text).dump()
        elif first[2] == "RawScript":
            return RawScript.assemble_xamx(text).dump()
        elif first[2] == "MapFile":
            return MapFile.assemble_xamx(text).dump()
        else:
            raise Exception(f"File type unknown: {first[2]}")
    # elif data[:10] == b'...':  # decompiled TODO
    else:  # unknown
        print("File type unknown: " + str(data[:10]))
        return None

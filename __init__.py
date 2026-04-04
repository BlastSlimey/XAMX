from xamx import main
import sys

if __name__ == "__main__":
    # main(None, *sys.argv[1:])
    from xamx import data
    for name, idx in data.amx_opcode_ids.items():
        print("")
        print("")
        print(f"@register_opcode({idx})")
        print(f"def {name.casefold()}(state: State, packed: int, params: tuple[int]):")
        print("    ...")
        print("")

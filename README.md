# XAMX
Pokémon XY/ORAS/SM/USUM script dis- and re-assembler and documentation

This is a tool for dis- and re-assembling the AMX scripts in 
Pokémon X, Y, Omega Ruby, Alpha Sapphire, Sun, Moon, Ultra Sun, and Ultra Moon.
<br>Documentation for how the scripts work (and other things) is found in (almost) all files, so please read them carefully.

## Requirements

Python (preferably 3.11, newer versions should probably also work, but lower versions will very likely break something)

## How to use it

Just drag&drop a single file, multiple files, or even whole folders onto the \_\_init\_\_.py file (NOT the one in the amx subfolder!). 
The script will then automatically detect what kind of file you have and (dis)assemble it.
Disassembling a file will save the output as <original file name>.xamx; assembling a file will instead remove the .xamx extension (if present)
If the destination file/folder already exists, the script will ask you whether you want to overwrite it.

## Why "XAMX"?

***Pokémon X + AMX***
<br>because all of this started with a dumped Pokémon X rom, but also
<br>***Version of compiled AMX files (10) + AMX***
<br>which was just a coincidence.

## TODO

- Decompiler
- (Re-) Compiler
- Add LGPE and SwSh compatibility

